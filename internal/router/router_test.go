package router

import (
	"context"
	"strings"
	"testing"
)

func TestRouteSimpleErrorLocal(t *testing.T) {
	r := NewHeuristicRouter()
	d, err := r.Route(context.Background(), "ERROR <V1> nginx upstream connection refused on <V2>")
	if err != nil {
		t.Fatal(err)
	}
	if d.Target != TargetLocal {
		t.Fatalf("simple infra error should route local, got %s (%s)", d.Target, d.Reason)
	}
}

func TestRouteCodeCloud(t *testing.T) {
	r := NewHeuristicRouter()
	d, _ := r.Route(context.Background(), "func <id>(<id> <type>) <type> { return <id> }")
	if d.Target != TargetCloud {
		t.Fatalf("code structure should route cloud, got %s (%s)", d.Target, d.Reason)
	}
}

func TestRouteMultiTemplateCloud(t *testing.T) {
	r := NewHeuristicRouter()
	payload := strings.Repeat("service <V1> reported anomaly <V2>\n", 6)
	d, _ := r.Route(context.Background(), payload)
	if d.Target != TargetCloud {
		t.Fatalf("multi-template payload should route cloud, got %s (%s)", d.Target, d.Reason)
	}
}

func TestRouteLargePayloadCloud(t *testing.T) {
	r := NewHeuristicRouter()
	d, _ := r.Route(context.Background(), "x "+strings.Repeat("a", 500))
	if d.Target != TargetCloud {
		t.Fatalf("large payload should route cloud, got %s (%s)", d.Target, d.Reason)
	}
}

// TestJapaneseErrorsRouteLocal is the market-facing half of this router. The
// signal list was entirely English literals, so a Japanese ticket matched none
// of them and reached the default by fallthrough rather than by a decision an
// audit record could explain.
func TestJapaneseErrorsRouteLocal(t *testing.T) {
	r := NewHeuristicRouter()
	for _, text := range []string{
		"web-1 への接続が拒否されました",
		"バックアップがタイムアウトしました",
		"ディスク容量が不足しています",
		"メモリ不足でプロセスが停止しました",
		"ファイルが見つかりません",
		"サーバーが応答しません",
	} {
		d, err := r.Route(context.Background(), text)
		if err != nil {
			t.Fatal(err)
		}
		if d.Target != TargetLocal {
			t.Errorf("%q routed to %s, want local", text, d.Target)
		}
		if d.Reason != "known simple infrastructure error" {
			t.Errorf("%q: reason = %q; it reached local by fallthrough rather "+
				"than by recognising the error", text, d.Reason)
		}
	}
}

// TestSizeThresholdIsFairAcrossScripts. internal/tokens documents that CJK
// tokenizes at roughly one token per character where Latin runs about four, so
// a rune threshold escalated Japanese to the cloud at about a quarter of the
// size of an equivalent English payload — the opposite of what a gateway sold
// on keeping Japanese data local should do.
func TestSizeThresholdIsFairAcrossScripts(t *testing.T) {
	r := NewHeuristicRouter()

	// Two payloads of comparable *information*, not comparable length.
	english := "the backup job failed on the primary node and then retried twice"
	japanese := "バックアップ処理が主ノードで失敗し、その後二回再試行されました"

	de, err := r.Route(context.Background(), english)
	if err != nil {
		t.Fatal(err)
	}
	dj, err := r.Route(context.Background(), japanese)
	if err != nil {
		t.Fatal(err)
	}
	if de.Target != dj.Target {
		t.Errorf("comparable payloads routed differently by script: english=%s (%s), japanese=%s (%s)",
			de.Target, de.Reason, dj.Target, dj.Reason)
	}
}

// TestLargeJapanesePayloadStillEscalates: the threshold must still bite, or
// making it fair would just have removed it.
func TestLargeJapanesePayloadStillEscalates(t *testing.T) {
	r := NewHeuristicRouter()
	long := strings.Repeat("システム障害の詳細な調査報告です。", 40)
	d, err := r.Route(context.Background(), long)
	if err != nil {
		t.Fatal(err)
	}
	if d.Target != TargetCloud {
		t.Errorf("a long Japanese payload routed to %s, want cloud", d.Target)
	}
}
