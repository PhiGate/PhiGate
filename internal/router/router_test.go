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
