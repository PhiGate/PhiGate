package compressor

import (
	"strings"
	"testing"
)

func TestASTPruneGo(t *testing.T) {
	a := NewASTPruner()
	s := NewSession()
	src := `package main

func add(a int, b int) int {
	secret := "p@ssw0rd"
	return a + b + 42
}`
	out, err := a.Process(src, s)
	if err != nil {
		t.Fatal(err)
	}

	for _, leaked := range []string{"p@ssw0rd", "42", "secret", "add", "main"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("value %q survived pruning: %q", leaked, out)
		}
	}
	for _, want := range []string{"func", "return", "<str>", "<int>"} {
		if !strings.Contains(out, want) {
			t.Fatalf("structure %q missing from skeleton: %q", want, out)
		}
	}
}

func TestASTPrunePython(t *testing.T) {
	a := NewASTPruner()
	s := NewSession()
	src := `def greet(name):
    password = "hunter2"
    return name + str(99)`
	out, err := a.Process(src, s)
	if err != nil {
		t.Fatal(err)
	}

	for _, leaked := range []string{"hunter2", "99", "password", "greet"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("value %q survived pruning: %q", leaked, out)
		}
	}
	for _, want := range []string{"def", "return", "<str>", "<int>"} {
		if !strings.Contains(out, want) {
			t.Fatalf("structure %q missing from skeleton: %q", want, out)
		}
	}
}

// Plain logs must not be misclassified as code and should pass through intact.
func TestASTPruneIgnoresLogs(t *testing.T) {
	a := NewASTPruner()
	s := NewSession()
	in := "ERROR 2026-06-29 nginx: upstream timed out (110: Connection timed out)"
	out, err := a.Process(in, s)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("log was altered by pruner:\n in  = %q\n out = %q", in, out)
	}
}
