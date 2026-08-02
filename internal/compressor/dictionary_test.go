package compressor

import "testing"

func TestDictionaryDedupe(t *testing.T) {
	d := NewDictionary()
	a := d.Mask("10.0.0.1", ClassVar)
	b := d.Mask("10.0.0.1", ClassVar) // same value -> same token
	c := d.Mask("10.0.0.2", ClassVar)

	if a != b {
		t.Fatalf("identical values must collapse: %q != %q", a, b)
	}
	if a == c {
		t.Fatalf("distinct values must differ: both %q", a)
	}
	if a != "<V1>" || c != "<V2>" {
		t.Fatalf("unexpected tokens: a=%q c=%q", a, c)
	}
}

func TestDictionaryClasses(t *testing.T) {
	d := NewDictionary()
	v := d.Mask("1.2.3.4", ClassVar)
	r := d.Mask("org.springframework.web.servlet", ClassRef)
	if v != "<V1>" {
		t.Errorf("var token = %q, want <V1>", v)
	}
	if r != "#REF1" {
		t.Errorf("ref token = %q, want #REF1", r)
	}
}

// TestHydrateLongestFirst guards against <V1> clobbering the prefix of <V12>.
func TestHydrateLongestFirst(t *testing.T) {
	d := NewDictionary()
	var last string
	for i := 1; i <= 12; i++ {
		last = d.Mask("value-"+itoa(i), ClassVar)
	}
	if last != "<V12>" {
		t.Fatalf("expected <V12>, got %q", last)
	}

	masked := "first=<V1> twelfth=<V12>"
	got := d.Hydrate(masked)
	want := "first=value-1 twelfth=value-12"
	if got != want {
		t.Fatalf("Hydrate = %q, want %q", got, want)
	}
}
