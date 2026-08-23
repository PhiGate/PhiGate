# PhiGate（ファイゲート）

**SLM活用でコストを極小化、社内データ流出を防ぐ企業向けAI安全網。**

[English README](README.md) · [脅威モデル](THREAT-MODEL.md) · [セキュリティ方針](SECURITY.md) · [コントリビュート](CONTRIBUTING.md)

PhiGate は、社内の AIOps ツールとクラウド LLM の間に立つ OpenAI 互換リバース
プロキシです。生のログやコードを外部へそのまま送るのではなく、**圧縮・匿名化・
分類・振り分け・検査**を行い、トークン費用を削減しながら機微データを社内に
とどめます。

クライアントの `base_url` を PhiGate に向けるだけです。他の変更は要りません。

---

## 「保証する」と言える根拠

PhiGate の 2 つの訴求点はいずれも実測できる性質のものです。したがって、成立し
なくなった瞬間に落ちるテストを用意しています。ご自身で実行して確認できます。

| 主張 | 実装 | 検証コマンド |
|---|---|---|
| 認証情報・個人情報がマスクされずに外部へ出ることはない | [`internal/redact`](internal/redact/) | `go test ./internal/redact/ -run Leak` |
| 値が「部分的に」マスクされることはない | 単一パスでの重複解決 | 同上（部分漏洩でも失敗する） |
| 設定した機密度を超えるデータは、障害時であってもクラウドへ出ない | [`internal/policy`](internal/policy/) | `go test ./internal/policy/` |
| 破滅的なコマンドが運用者に届くことはない | [`internal/sandbox`](internal/sandbox/) | `go test ./internal/sandbox/` |
| ガードレールが通常の文章を誤ってブロックしない | 同上 | `-run TestGuardDoesNotBlockProse` |
| キャッシュが他セッションの値を渡すことはない | [`internal/cache`](internal/cache/) | `go test ./internal/gateway/ -run Cache` |
| 監査ログに生の機微データが含まれない | [`internal/audit`](internal/audit/) | `Event` 型に値を保持できる項目が存在しない |

そのうえで、**貴社のデータ**で測定してください。

```bash
./bin/phigate-eval leak  -dir /var/log/yourapp    # 何が分類・検出されたか
./bin/phigate-eval bench -dir /var/log/yourapp    # 各段階のトークン削減率
./bin/phigate-eval eval  -cases eval/cases.json   # 回答品質：素通し vs PhiGate 経由
```

最後の 1 つが最も重要です。各ケースを 2 回 — 一度は生のままクラウドモデルへ、
もう一度は PhiGate 経由で — 送り、審査用モデルに両方を採点させます。品質の数値を
伴わない削減率は、どのお客様も既に信用していない数字です。

---

## リクエストの流れ

```
POST /v1/chat/completions
  → 認証（APIキー、テナント単位）
  → プロンプトインジェクション検査        internal/sandbox  (入口)
  → 圧縮・匿名化                          internal/compressor + internal/redact
  → 検出内容の分類                        secret / pii / network / identifier / …
  → 送信先ポリシーによる判定              internal/policy     ← 拘束力あり
  → テンプレートキャッシュ照会            internal/cache      ← ヒット時トークン 0
  → ローカル / クラウド振り分け           internal/router     ← 助言にすぎない
  → 送信（リトライ・サーキットブレーカ）  internal/llm        OpenAI | Azure OpenAI
  → 実値へ復元                            + 辞書列挙ガード
  → 回答の検査                            internal/sandbox    (出口)
  → 費用計上                              internal/tokens     トークンと金額
  → 監査記録                              internal/audit      構造化 JSON
```

**ポリシーはルーティングに優先します。** ルータは「どこが安いか」を、ポリシーは
「どこへ出してよいか」を判断します。両者が食い違えばポリシーが勝ちます。ローカル
バックエンドが停止していても同じで、ローカル限定と判定されたペイロードは
クラウドへフォールバックしません。失敗します。

---

## 押さえておきたい 3 つの考え方

### 1. テンプレートキャッシュこそが本命のコスト削減策

AIOps のトラフィックは極めて反復的です。同じディスク枯渇アラートが日に何千件も
届き、違うのは IP・タイムスタンプ・リクエスト ID だけ。通常のキャッシュはこれら
の値のせいで毎回別物になり、まずヒットしません。

PhiGate はキャッシュ照会の時点で、まさにその値をプレースホルダに置換済みです。
1 万件の異なるログ行が 1 つのテンプレートに収束するため、2 件目以降は**上流
トークン 0** で応答できます。圧縮があるからキャッシュが効き、キャッシュがある
から圧縮が採算に乗ります。

キャッシュは**復元前**の回答をハッシュキーで保持するため、顧客データを一切
含まず、テナント間で共有しても安全です（各セッションが自分の辞書で復元します）。

### 2. 分類はラベルではなく「制御」

検出された値には分類が付き、ペイロード内で最も高い分類が送信先を決めます。

| 分類 | 例 | 既定の扱い |
|---|---|---|
| `restricted` | API キー、秘密鍵、JWT、パスワード | **ローカル限定** |
| `confidential` | 個人番号、カード番号、電話、メール、住所 | **ローカル限定** |
| `internal` | IP、MAC、社内ホスト名、パス | クラウド可（マスク済み） |
| `low` | UUID、ハッシュ、タイムスタンプ | クラウド可（マスク済み） |

最も厳格にするなら `PHIGATE_CLOUD_MAX_SENSITIVITY=low`、そもそも受け付けない
なら `PHIGATE_DENY_ABOVE_SENSITIVITY=confidential` を設定します。

### 3. ガードレールは「文章」ではなく「コマンド」を読む

出口ガードは実行されうる部分 — コードブロック、インラインコード、明らかに
コマンドである行 — を取り出し、argv に字句解析して、コマンド名とフラグで判定
します。

```
「駄目ならノードを reboot してください」  → 許可（説明文）
「SIGTERM で graceful shutdown します」   → 許可（説明文）
sudo reboot                               → 警告（正当な復旧手順）
rm -rf ./build                            → 警告（対象が限定的）
rm --force --recursive /                  → ブロック（正規表現方式では素通り）
```

重大度の段階を設けているのは、破壊的に見えるものを一律ブロックすると
ガードレールそのものが無効化されてしまうからです。無効化されたガードレールは
何も守りません。

---

## クイックスタート

```bash
docker run -p 8080:8080 \
  -e PHIGATE_API_KEYS="my-client-key:team-sre" \
  -e PHIGATE_CLOUD_API_KEY="sk-..." \
  -e PHIGATE_INTERNAL_DOMAINS="internal,corp" \
  ghcr.io/phigate/phigate:latest
```

ソースからビルドする場合（Go 1.26+ と C コンパイラが必要。tree-sitter が cgo を
使うため）:

```bash
make build && make run
```

あとは OpenAI クライアントの向き先を変えるだけです。

```python
client = OpenAI(base_url="http://localhost:8080/v1", api_key="my-client-key")
```

**Kubernetes:** `helm install phigate deploy/helm/phigate --set secrets.apiKeys="key:team"`

---

## 日本企業向けの設計判断

- **個人番号（マイナンバー）と法人番号**は、総務省令の検査用数字（チェック
  ディジット）で検証します。「12 桁の数字」という広いパターンを使いながら誤検知を
  抑えられるのはこのためです。マイナンバー法上の特定個人情報にあたるため、既定
  ではクラウドへ出ません。
- **Azure OpenAI に対応**しています。多くの日本企業が実際に利用しているのは
  Microsoft 契約とデータ所在地要件を満たす Azure 側です。`api-key` ヘッダ、
  デプロイメント名、`api-version` の差異を吸収します。
- **トークン推定は CJK を 1 文字 ≒ 1 トークンで計算**します。4 文字 ≒ 1 トークン
  と仮定すると日本語のコストを数倍過小評価し、削減率の数字がすべて狂います。
- **価格表は差し替え可能**です。公表価格ではなく貴社の契約単価・通貨（円）で
  計上できます（`PHIGATE_PRICE_BOOK`）。
- **監査ログは構造化 JSON** で、規則名・分類件数・ハッシュのみを記録します。
  ISMS / JIS Q 27001 の監査に耐えるよう、生の値を保持できる項目自体が存在
  しません。
- **ダッシュボードは単一バイナリに同梱**され、外部 CDN を参照しません。閉域
  ネットワークでも表示できます。

---

## 主な設定

必須は `PHIGATE_API_KEYS` と `PHIGATE_CLOUD_API_KEY` のみです。クライアント認証
情報が無い場合、PhiGate は**起動を拒否**します（`PHIGATE_ALLOW_ANONYMOUS=true`
で明示的に許可した場合を除く）。課金される API キーの前に置かれた無認証の
ゲートウェイは、オープンリレーに他ならないためです。

設定項目の一覧は [English README](README.md#configuration) を参照してください。
`phigate -rules` で、実際に有効な検出規則と分類をすべて表示できます。

---

## エンドポイント

| エンドポイント | 認証 | 用途 |
|---|---|---|
| `POST /v1/chat/completions` | ✅ | OpenAI 互換（ストリーミング対応） |
| `GET /v1/models` | ✅ | モデル一覧 |
| `GET /v1/phigate/stats` | ✅ | 削減トークン・金額、キャッシュ状況 |
| `GET /v1/phigate/rules` | ✅ | 有効な統制の一覧（監査用） |
| `GET /metrics` | ✅ | Prometheus 形式 |
| `GET /dashboard` | ✅ | 運用ダッシュボード（同梱・CDN 不要） |
| `GET /healthz` | — | 死活監視 |
| `GET /readyz` | — | 疎通確認（両バックエンドを検査） |
| `POST /debug/compress` | ✅ | **既定で無効** — 平文を返します |

---

## エディション

PhiGate はオープンコア構成です。**この README が説明する機能はすべて
Community Edition であり、Apache-2.0 のもとで本番環境でも無償・無期限に
利用できます。** マスキングルール、My Number をはじめとする日本向け PII
検出、エグレスポリシー、サンドボックス、監査ログ — プライバシー保護に
関わる機能はすべて CE に含まれます。

`ee/` ディレクトリが Enterprise Edition で、ソース公開型のライセンスを
採用しています。EE は**独立した Go モジュール**です。これにより CE の
サードパーティ依存は tree-sitter 1 件のみという状態が構造的に保たれます
— セキュリティ審査で実際に確認されるのはこの点です。`ee/` の内容が CE の
ビルドに影響することはなく、万一そうなれば `make ce-purity` がビルドを
失敗させます。

|  | Community Edition | Enterprise Edition |
|---|---|---|
| ライセンス | Apache-2.0 | [BSL 1.1](ee/LICENSE)（4 年後に Apache-2.0 へ移行） |
| 本番利用 | 無償 | 商用ライセンスが必要 |
| 非本番利用（評価・開発・検証） | 無償 | 無償 |
| 依存関係 | tree-sitter のみ | `ee/go.mod` に隔離 |

EE が担うのは規模と運用です — 再起動後も維持されるクォータ、クラスタ構成、
分散キャッシュ、改ざん不可能な監査ログ保管、コントロールプレーン。
プライバシー保証そのものは EE ではなく CE にあります。

「本番利用（production）」の定義と具体例は
[ee/LICENSING-FAQ.md](ee/LICENSING-FAQ.md) に記載しています。実データを用いた
EE の評価については、期間を区切った評価用ライセンスを無償で発行します
（info@tenkan.co.jp）。日本企業のセキュリティ審査が 60 日を超えることは
珍しくないため、その場合は期間を延長します。

## ライセンス

Copyright 2026 Tenkan Inc. (天干株式会社) — [NOTICE](NOTICE) を参照。

- Community Edition（`ee/` 以外のすべて）: [Apache License 2.0](LICENSE)
- Enterprise Edition（`ee/`）: [Business Source License 1.1](ee/LICENSE)
  — 各バージョンの公開から 4 年後に Apache-2.0 へ移行します。
