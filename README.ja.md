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
| ツール呼び出しの中身も同様（本文を一切持たない形式であっても） | [`internal/gateway`](internal/gateway/) | `go test ./internal/gateway/ -run ToolCall` |
| 値が「部分的に」マスクされることはない | 単一パスでの重複解決 | 同上（部分漏洩でも失敗する） |
| 設定した機密度を超えるデータは、障害時であってもクラウドへ出ない | [`internal/policy`](internal/policy/) | `go test ./internal/policy/` |
| 破滅的なコマンドが運用者に届くことはない | [`internal/sandbox`](internal/sandbox/) | `go test ./internal/sandbox/` |
| ガードレールが通常の文章を誤ってブロックしない | 同上 | `-run TestGuardDoesNotBlockProse` |
| ストリーミング応答も非ストリーミング応答とまったく同じ基準で検査される | [`internal/sandbox`](internal/sandbox/) | `go test ./internal/sandbox/ -run TestStreamingAgrees` |
| キャッシュが他セッションの値を渡すことはない | [`internal/cache`](internal/cache/) | `go test ./internal/gateway/ -run Cache` |
| ある質問に別の質問の回答を返すこともない | 形状による照合は完全一致 | `go test ./internal/gateway/ -run Shape` |
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

**実測値（2026-09-12）。** 両アームを同一モデル `claude-sonnet-5` に固定し、審査も
同モデル、1 ケースあたり 5 回、キャッシュ無効で測定しました。ガードに差し止められた
1 ケースを除く 7 ケースで、素通し **8.94** に対し PhiGate 経由 **8.91** — 0〜10 点中
**−0.03** であり、ケースごとの最大ばらつき ±1.02 を大きく下回ります。**圧縮と匿名化
による回答品質の低下は測定できませんでした。**

除外した `disk-full-remediation` の −7.40 は、圧縮による劣化ではなく**エグレス
ガードが回答全体を差し止めた**結果です（5 回中 4 回）。**この欠陥は修正済みで**、
現在は該当箇所のみを切り取って残りを返します。ただし表は測定時のまま残してあり
ます。これはその日のビルドの挙動の記録であり、あとから黙って良くなる数字こそ読者
が疑うべきものだからです。再測定は行っていません。

同じ実行での削減率は **64.2%** ですが、その大半は圧縮ではなく**ルーティング**に
よるものです。実際にクラウドへ出た 3 ケースの圧縮率は 0.6〜11% でした。上記の
97.4% は大量ログに対する圧縮率であり、短い障害質問とは前提が異なります。自社の
トラフィックに合う方を、**どちらを引用したか明示したうえで**お使いください。

なお、この表は**保証ではなく測定値**です。漏洩コーパスやポリシーの検証は CI で
回り、主張が成り立たなくなればビルドが落ちます。回答品質はそれができません
（実費と認証情報を要するため）。完全な表と 4 つの但し書きは
[English README](README.md#answer-quality) にあります。

---

## リクエストの流れ

```
POST /v1/chat/completions
  → 認証、テナント解決                    ポリシーと検出ルールはテナント単位
  → テナントのトークン予算を確認          internal/gateway    ← 使い切れば 429
  → プロンプトインジェクション検査        internal/sandbox  (入口)
  → 圧縮・匿名化                          internal/compressor + internal/redact
      本文、ツール呼び出しの引数、ツール定義の説明文
  → 検出内容の分類                        secret / pii / network / identifier / …
  → 送信先ポリシーによる判定              internal/policy     ← 拘束力あり
  → テンプレートキャッシュ照会            internal/cache      ← 「形状」で照合
  → ローカル / クラウド振り分け           internal/router     ← 助言にすぎない
  → 送信（リトライ・サーキットブレーカ）  internal/llm
      OpenAI | Azure OpenAI | Anthropic | Amazon Bedrock
  → 実値へ復元                            + 辞書列挙ガード
  → 回答の検査                            internal/sandbox    (出口)
      本文に加えてツール呼び出しの引数も
  → 費用計上                              internal/tokens     トークンと金額
  → 監査記録                              internal/audit      構造化 JSON
```

**ポリシーはルーティングに優先します。** ルータは「どこが安いか」を、ポリシーは
「どこへ出してよいか」を判断します。両者が食い違えばポリシーが勝ちます。ローカル
バックエンドが停止していても同じで、ローカル限定と判定されたペイロードは
クラウドへフォールバックしません。失敗します。

---

## 押さえておきたい 3 つの考え方

### 1. テンプレートキャッシュこそが本命のコスト削減策 — 鍵は「形状」

AIOps のトラフィックは極めて反復的です。同じディスク枯渇アラートが日に何千件も
届き、違うのは IP・タイムスタンプ・リクエスト ID だけ。通常のキャッシュはこれら
の値のせいで毎回別物になり、まずヒットしません。

PhiGate はキャッシュ照会の時点で、まさにその値をプレースホルダに置換済みです。
ただしプレースホルダだけでは足りず、それは**実測して初めて分かりました**。
セッション辞書は値を「初めて見た時点」で採番します（`<V7>` が会話全体で同じ
ホストを指すからこそ復元が成立する、という設計です）。その結果、同じログ行が
1 時間後に届くと `<V7> failed` と `<V931> failed` になり、本文で鍵を作ると
別々の鍵になって、**同一のペイロードでキャッシュが外れて**いました。

上の表と同じ語料でご自身で測れます:

```bash
./bin/phigate-eval cache -dir eval/corpus
```

| 鍵の作り方 | 16,000 行でのヒット率 |
|---|---:|
| 圧縮後の本文 | **4.5%** |
| 圧縮後の**形状**（プレースホルダをペイロード単位で振り直す） | **50.5%** |

そこで鍵は形状で作っています。これは依然として**完全一致**です — 振り直した
うえで同一である場合にのみ鍵を共有するので、ある質問に別の質問の回答を返すこと
は原理的に起こりません。項目は正規形で保存し、ヒット時には要求側の採番へ戻して
から復元します。

残る 44.9% は、形状まで含めて 1 回しか現れないペイロードです。これが意味的
キャッシュ層に残された全余地であり、しかもそれを回収するには**別の**ペイロード
と照合するしかありません — それは誤答の発生源であり、完全一致キャッシュには
起こしようのない種類の失敗です。

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

**クラウド API キーなし、データを外に出さずに、コマンド 1 つで評価できます。**

```bash
docker compose up
```

PhiGate と、ローカルの Phi-4-mini（[Ollama](https://ollama.com) 上に自動で取得）
と Prometheus が起動します。外部送信の上限は `low` に設定してあるため、ホスト名・
IP・パスを含むデータは「そう運用する」のではなく
[`internal/policy`](internal/policy/) によってローカルモデルに固定されます。

```bash
curl localhost:8080/v1/chat/completions \
  -H 'Authorization: Bearer demo-key' -H 'Content-Type: application/json' \
  -d '{"model":"phi4-mini","messages":[
        {"role":"user","content":"nginx upstream timeout to 10.24.8.19, help"}]}'
```

`docker compose logs phigate` で、そのリクエストの監査ログ — どのルールが発火し、
どこへ振り分け、その理由は何か — を確認できます。ダッシュボードは
[localhost:8080/dashboard](http://localhost:8080/dashboard)、メトリクスは
[localhost:9090](http://localhost:9090) です。

公開ベンチマークの再現、および自社ログでの測定:

```bash
scripts/fetch-benchmark-corpus.sh              # eval/corpus は同梱せず取得する方式
docker compose run --rm bench                  # 上記の表の数値
docker compose run --rm -v /var/log:/data:ro bench -dir /data   # 自社データ
```

クラウドモデルと比較したくなった時点で追加してください:
`PHIGATE_CLOUD_API_KEY=sk-... PHIGATE_CLOUD_MAX_SENSITIVITY=internal docker compose up`

### ゲートウェイ単体で動かす場合

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
- **Azure OpenAI、Anthropic、Amazon Bedrock に対応**しています。多くの日本企業が
  実際に利用しているのは、既存の Microsoft 契約や AWS 契約とデータ所在地要件を
  満たす側です。前面に置けないゲートウェイは検討対象にすら入りません。Azure の
  `api-key` ヘッダ・デプロイメント名・`api-version`、Anthropic の Messages API、
  Bedrock の SigV4 署名 — いずれも吸収します。いずれも標準ライブラリのみで実装
  しており、CE のサードパーティ依存 1 件という性質は保たれています。
- **ルーティングが日本語で機能します。** 判定に使う障害パターンは英語の文字列
  しか無く、日本語のチケットはどれにも一致しませんでした。またサイズ閾値が
  rune 単位だったため、CJK は 1 文字 ≒ 1 トークン・英語は 4 文字 ≒ 1 トークン
  という差により、日本語のペイロードは同等の英語の約 4 分の 1 の大きさで
  クラウドへ送られていました — 日本語データをローカルに保つという売り方の
  正反対です。閾値はトークン推定に、パターンには日本語表現を追加しました。
- **自由文中の日本語氏名検出**（EE）。`jp.json` の `jp_name_kanji` は既定で
  無効です — 「自由書式の漢字氏名は正規表現だけでは確実に検出できない」と
  ルール自身が説明しています。EE は姓の辞書で候補を絞り、**ローカルの**モデルに
  文脈判定させます（個人情報を探す検出器が、それを含むか判定するために本文を
  クラウドへ送るわけにはいきません）。CE のエンジンと組み合わせる方式なので、
  EE が CE より少なく検出することは構造上あり得ません。
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

設定は `PHIGATE_CONFIG` で指定する JSON ファイルからも読み込めます。優先順位は
**既定値 → ファイル → 環境変数**です。ファイルはバージョン管理され監査人が読む
「宣言された状態」であり、環境変数はコンテナの機密情報が置かれる場所、そして障害
対応時に管理者が手を伸ばす場所だからです。緊急時の
`PHIGATE_CLOUD_MAX_SENSITIVITY=low` が、リポジトリに入ったファイルによって黙って
無効化されることがあってはなりません。ファイル内の未知のキーは起動エラーです。
綴り間違いが受理されて無視されるということは、監査人に「有効です」と説明した制御
が黙って何もしていないということだからです。

**テナント単位の制御。** `PHIGATE_API_KEYS="key:tenant"` のテナント名に、独自の
外部送信ポリシー・レート制限・検出ルールパックを持たせられます。経理部門と SRE
チームを別々の基準で運用するために、ゲートウェイを 2 つ立てる必要はありません:

```json
{
  "api_keys": { "sre-key": "team-sre", "fin-key": "team-finance" },
  "policy":   { "cloud_max_sensitivity": "internal" },
  "tenants": {
    "team-finance": {
      "policy": { "cloud_max_sensitivity": "low" },
      "rate_limit_per_min": 60
    }
  }
}
```

テナントは全体設定を**狭める**ことしかできません。全体の上限を超えるテナント
ポリシーは起動エラーであり、どの API キーも対応しないテナント名も同様です（typo
の場合、狭めたはずのテナントが全体ポリシーのまま残ってしまうため）。
`GET /v1/phigate/rules` は呼び出し元テナントの設定を返すので、監査人は自分の
トラフィックに実際に適用される規則を確認できます。

**無停止での設定再読み込み。** `kill -HUP` でファイルを読み直します。リスナーは
閉じられず、接続は一本も切れず、処理中のストリーミング応答は開始時の設定のまま
完了します。API キー、ポリシー閾値、レート制限、ルールパック、ガードの重大度、
テナント定義は次のリクエストから有効になります。検出ルールが変わった場合は
テンプレートキャッシュを破棄します（既存のキーはもう適用されない規則の下で
作られたものだからです）。待受アドレス・メトリクスのパス・ダッシュボードと
デバッグ端点の有無は起動時に一度だけ読まれ、変更には再起動が必要です。検証に
失敗した再読み込みは**何も変更せず、その旨をログに出します**。設定全体を構築し
終えてから初めて適用するため、不正な編集をしても稼働中のゲートウェイはそのまま
です。

<details>
<summary><b>バックエンド</b> — OpenAI 互換 / Azure OpenAI</summary>

| 変数 | 既定値 | 用途 |
|---|---|---|
| `PHIGATE_LOCAL_PROVIDER` | `openai` | `openai` \| `azure` \| `anthropic` \| `bedrock` |
| `PHIGATE_LOCAL_BASE_URL` | `http://localhost:11434/v1` | Ollama / vLLM / llama.cpp |
| `PHIGATE_LOCAL_MODEL` | `phi4-mini` | `ollama list` の表示と**完全に一致**させること |
| `PHIGATE_CLOUD_PROVIDER` | `openai` | `azure` / `anthropic` / `bedrock` |
| `PHIGATE_CLOUD_BASE_URL` | `https://api.openai.com/v1` | Azure の場合はリソースのルート |
| `PHIGATE_CLOUD_MODEL` | `gpt-4o` | |
| `PHIGATE_CLOUD_API_KEY` | (`OPENAI_API_KEY`) | |
| `PHIGATE_CLOUD_API_VERSION` | `2024-10-21` | Azure のみ |
| `PHIGATE_CLOUD_DEPLOYMENT` | (モデル名) | Azure のデプロイ名。Bedrock では推論プロファイル ARN |
| `PHIGATE_CLOUD_REGION` | (`AWS_REGION`) | Bedrock のみ |
| `PHIGATE_CLOUD_ACCESS_KEY_ID` | (`AWS_ACCESS_KEY_ID`) | Bedrock のみ |
| `PHIGATE_CLOUD_SECRET_ACCESS_KEY` | (`AWS_SECRET_ACCESS_KEY`) | Bedrock のみ |
| `PHIGATE_CLOUD_SESSION_TOKEN` | (`AWS_SESSION_TOKEN`) | Bedrock のみ。一時認証情報用 |

ローカルモデルの差し替えは**環境変数だけ**で完結します。PhiGate にモデル固有の
コードは一切なく、`phi4-mini` は既定値の文字列にすぎません。

**Claude（第一者 API / Bedrock 経由）。** どちらも OpenAI のワイヤ形式を話さない
ため、ベース URL の差し替えではなく PhiGate が変換する「方言」として実装されて
います。システムプロンプトはトップレベルのフィールドへ移り、`max_tokens` が必須に
なり、コンテンツは型付きブロックの配列になります。ツール呼び出しも双方向で変換
されるため、他のバックエンドと同様にマスキングとガードの対象になります。

```json
{ "cloud": { "provider": "anthropic", "model": "claude-opus-5",
             "base_url": "https://api.anthropic.com", "api_key": "sk-ant-..." } }
```

Bedrock のリクエストは SigV4 で署名されます。認証情報はバックエンド設定または
標準の `AWS_*` 環境変数から取得しますが、**AWS の認証情報チェーン全体（インスタンス
メタデータ、SSO、プロファイル、AssumeRole）は未実装**です。リージョンや認証情報を
欠いた Bedrock バックエンドは、最初のリクエスト時ではなく起動時に失敗します。
Bedrock の**ストリーミングは非対応**です（イベントストリームが SSE ではなくバイナリ
フレーミングのため）。非ストリーミングのリクエストか、第一者 API を使ってください。

</details>

**国産 LLM・デジタル庁「源内」採択モデル。** PLaMo・tsuzumi 2・ELYZA・Sarashina
など、源内で採択された 7 モデルへの接続方法は
[日本の国産モデル接続ガイド](docs/japan-models.md) にまとめています。接続設定の
記載であり、動作検証済みという意味ではない点にご注意ください。

その他の設定項目は [English README](README.md#configuration) を参照してください。
`phigate -rules` で、実際に有効な検出規則と分類をすべて表示できます。

---

## エンドポイント

| エンドポイント | 認証 | 用途 |
|---|---|---|
| `POST /v1/chat/completions` | ✅ | OpenAI 互換（ストリーミング対応） |
| `POST /v1/embeddings` | ✅ | 入力を送信前にマスキング。エグレスポリシーが拘束します |
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

EE は規模と運用のためのものであり、プライバシー保護のためのものではありません。
4 つの接合点のうち 3 つが実装済みです — 改竄検知可能な監査チェーン
（`ee/audit/worm`）、テナント単位で永続化されるトークン台帳
（`ee/tokens/durable`）、そして CE の正規表現エンジンを**置き換えるのではなく
組み合わせる**日本語氏名検出（`ee/redact/slm`）。意味的キャッシュ層は意図的に
実装していません。その判断の根拠となった実測値は [ee/README.md](ee/README.md)
にあります。

プライバシー保護の機能は CE 側にとどまります。EE の氏名検出器が CE のエンジン
より**少なく**検出することは構造上あり得ず、CE 自身の漏洩検査語料を敵対的な
認識器と組み合わせて EE 検出器に通すテストがそれを保証しています。

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
