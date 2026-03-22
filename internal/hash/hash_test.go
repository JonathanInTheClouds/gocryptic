package hash_test

import (
	"testing"

	"github.com/gocryptic/gocryptic/internal/hash"
)

func TestKnownDigests(t *testing.T) {
	cases := []struct {
		algo   string
		input  string
		expect string
	}{
		// echo -n "" | md5sum
		{"md5", "", "d41d8cd98f00b204e9800998ecf8427e"},
		// echo -n "" | sha256sum
		{"sha256", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		// echo -n "hello" | sha256sum
		{"sha256", "hello", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"},
	}
	for _, tc := range cases {
		t.Run(tc.algo+"/"+tc.input, func(t *testing.T) {
			got, err := hash.Sum([]byte(tc.input), tc.algo)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expect {
				t.Fatalf("want %s\n got %s", tc.expect, got)
			}
		})
	}
}

func TestAllAlgorithms(t *testing.T) {
	results := hash.SumAll([]byte("gocryptic"))
	for _, algo := range hash.Algorithms() {
		if _, ok := results[algo]; !ok {
			t.Errorf("missing result for algorithm %q", algo)
		}
	}
}

func TestUnsupportedAlgorithm(t *testing.T) {
	if _, err := hash.Sum([]byte("x"), "blake2b"); err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}
