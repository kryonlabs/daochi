package main

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

func TestZiranStringSets(t *testing.T) {
	cases := []string{
		"", ",,,", " A,a,A , B ", "\t app \r\n,other",
		"\u2003雪\u00a0,Σ,İ,K", "bad\xff, bad\xff, \xfe ",
	}
	rng := rand.New(rand.NewSource(827))
	alphabet := []byte(" AaBb,\t\r\n_-.\x00\xff\xfe")
	for i := 0; i < 1000; i++ {
		data := make([]byte, rng.Intn(100))
		for j := range data {
			data[j] = alphabet[rng.Intn(len(alphabet))]
		}
		cases = append(cases, string(data))
	}
	for _, raw := range cases {
		values := strings.Split(raw, ",")
		wantEnvironment := map[string]bool{}
		wantNormalized := map[string]bool{}
		for _, value := range values {
			trimmed := strings.TrimSpace(value)
			if trimmed != "" {
				wantEnvironment[trimmed] = true
				wantNormalized[strings.ToLower(trimmed)] = true
			}
		}
		if got := Sets_FromEnvironment(raw); !reflect.DeepEqual(got, wantEnvironment) {
			t.Fatalf("environment set %q: got %#v, want %#v", raw, got, wantEnvironment)
		}
		if got := Sets_Normalize(values); !reflect.DeepEqual(got, wantNormalized) {
			t.Fatalf("normalized set %q: got %#v, want %#v", raw, got, wantNormalized)
		}
	}
	if got := Sets_Normalize(nil); got == nil || len(got) != 0 {
		t.Fatalf("nil input must return an allocated empty set: %#v", got)
	}
}
