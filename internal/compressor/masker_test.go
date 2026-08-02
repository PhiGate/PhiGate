package compressor

import (
	"strings"
	"testing"
)

func TestMaskerCollapsesDuplicates(t *testing.T) {
	m := NewMasker()
	s := NewSession()
	in := "conn from 192.168.1.10 failed; retry from 192.168.1.10 ok"
	out, err := m.Process(in, s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "192.168.1.10") {
		t.Fatalf("raw IP leaked: %q", out)
	}
	if strings.Count(out, "<V1>") != 2 {
		t.Fatalf("duplicate IP should reuse one token, got %q", out)
	}
}

func TestMaskerRoundTrip(t *testing.T) {
	m := NewMasker()
	s := NewSession()
	in := "2026-06-29T15:04:05Z user=admin@corp.local req=550e8400-e29b-41d4-a716-446655440000 ip=10.2.3.4:8443 took 12345ms"
	out, err := m.Process(in, s)
	if err != nil {
		t.Fatal(err)
	}

	// Egress guarantee: none of the sensitive literals survive masking.
	for _, secret := range []string{"admin@corp.local", "550e8400-e29b-41d4-a716-446655440000", "10.2.3.4:8443", "12345"} {
		if strings.Contains(out, secret) {
			t.Fatalf("sensitive value %q leaked in %q", secret, out)
		}
	}

	// Masking is fully reversible for the operator.
	if got := s.Dict.Hydrate(out); got != in {
		t.Fatalf("round trip failed:\n in  = %q\n out = %q", in, got)
	}
}
