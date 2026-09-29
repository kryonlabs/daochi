package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// This oracle preserves the removed Go implementation, including its order
// of encodings, Unicode trimming, and intentionally non-strict base64 bits.
func referenceBinaryField(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("empty binary field")
	}
	if len(value)%2 == 0 {
		if decoded, err := hex.DecodeString(value); err == nil {
			return decoded, nil
		}
	}
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding,
	} {
		if decoded, err := encoding.DecodeString(value); err == nil {
			return decoded, nil
		}
	}
	return nil, errors.New("field is neither hex nor base64")
}

func checkBinaryField(t *testing.T, input string) {
	t.Helper()
	value, err := referenceBinaryField(input)
	got := Codec_DecodeBinaryField(input)
	if err != nil {
		if got.Error != err.Error() || got.Value != "" {
			t.Fatalf("decode %q: got %#v, want error %q", input, got, err)
		}
		return
	}
	if got.Error != "" || got.Value != string(value) {
		t.Fatalf("decode %q: got %#v, want %x", input, got, value)
	}
}

func TestZiranBinaryFieldMatchesReleasedCodec(t *testing.T) {
	for _, input := range []string{
		"", " \t\n", "00ff", "ABCDEF", "a", "ab", "abc", "abcd", "abcde",
		"Zg==", "Zg", "Zm8=", "Zm8", "Zm9v", "Zh==", "Zm9=",
		"Z\r\ng==\r\n", "Zg=", "Zg===", "Zg==Zg==", "====", "Z===",
		"-_8=", "-_8", "+/8=", "+/8", "\u2003Zg==\u00a0", "Zm 9v", "\xff",
	} {
		checkBinaryField(t, input)
	}
	random := rand.New(rand.NewSource(20260929))
	for length := 1; length <= mlDSA44PrivateKeySize; length += 17 {
		data := make([]byte, length)
		if _, err := random.Read(data); err != nil {
			t.Fatal(err)
		}
		checkBinaryField(t, hex.EncodeToString(data))
		checkBinaryField(t, strings.ToUpper(hex.EncodeToString(data)))
		for _, encoding := range []*base64.Encoding{
			base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding,
		} {
			encoded := encoding.EncodeToString(data)
			checkBinaryField(t, encoded)
			checkBinaryField(t, "\u2003"+encoded+"\u2003")
			checkBinaryField(t, encoded[:len(encoded)/2]+"\r\n"+encoded[len(encoded)/2:])
		}
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_=\r\n! "
	for sample := 0; sample < 20000; sample++ {
		input := make([]byte, random.Intn(40))
		for index := range input {
			input[index] = alphabet[random.Intn(len(alphabet))]
		}
		checkBinaryField(t, string(input))
	}
}

func FuzzZiranBinaryField(f *testing.F) {
	for _, input := range []string{"00ff", "Zg==", "-_8=", "Zg===", "\u2003Zm9v\u2003"} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		checkBinaryField(t, input)
	})
}

func TestZiranIdentifierGrammarMatchesReleasedPatterns(t *testing.T) {
	cases := []struct {
		pattern string
		valid   func(string) bool
	}{
		{`^[0-9a-f]{64}$`, Identity_ValidUserID},
		{`^[A-Za-z0-9._:-]{8,128}$`, Identity_ValidClientID},
		{`^[A-Za-z0-9._:-]{4,128}$`, Identity_ValidResourceID},
		{`^[a-z0-9_]{4,32}$`, Identity_ValidAccountAlias},
		{`^[A-Za-z0-9._:-]{1,64}$`, Identity_ValidNamespace},
		{`^[A-Za-z0-9_:-]{1,64}$`, Identity_ValidNamespaceSegment},
		{`^v[1-9][0-9]{0,3}$`, Identity_ValidVersionSegment},
		{`^[A-Za-z0-9._:-]{1,160}$`, Identity_ValidEncryptedRecordID},
	}
	inputs := []string{"", "v0", "v1", "v001", "v9999", "v10000", "v123\n", "é", "a.b", "A_Z:-"}
	for _, size := range []int{1, 3, 4, 7, 8, 31, 32, 63, 64, 65, 127, 128, 129, 159, 160, 161} {
		for _, byte := range []string{"a", "A", "0", "f", "_", ".", ":", "-", " ", "\n"} {
			inputs = append(inputs, strings.Repeat(byte, size))
		}
	}
	for _, test := range cases {
		pattern := regexp.MustCompile(test.pattern)
		for _, input := range inputs {
			if got, want := test.valid(input), pattern.MatchString(input); got != want {
				t.Fatalf("%s input %q: got %v, want %v", test.pattern, input, got, want)
			}
		}
	}
}

func TestZiranLogTextPreservesOtherBytes(t *testing.T) {
	for _, value := range []string{"", "ordinary", "\r\nentry\r\n", "日\n本\r語", "\x00\xff\n\t"} {
		want := strings.ReplaceAll(strings.ReplaceAll(value, "\n", ""), "\r", "")
		if got := LogSafety_LogText(value); got != want {
			t.Fatalf("sanitize %q: got %q, want %q", value, got, want)
		}
	}
}

func referenceToken(secret []byte, payload string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func referenceVerifyToken(secret []byte, token string, now int64) AuthTokenResult {
	parts := strings.Split(token, ".")
	if len(parts) != 2 || len(secret) == 0 {
		return AuthTokenResult{Error: "invalid token"}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return AuthTokenResult{Error: "invalid token payload"}
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return AuthTokenResult{Error: "invalid token signature"}
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return AuthTokenResult{Error: "invalid token signature"}
	}
	fields := strings.Split(string(payload), "\n")
	if len(fields) < 4 || fields[0] != "v1" ||
		!regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(fields[1]) {
		return AuthTokenResult{Error: "invalid token payload"}
	}
	expires, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || now > expires {
		return AuthTokenResult{Error: "token expired"}
	}
	return AuthTokenResult{Value: fields[1]}
}

func TestZiranTokensPreserveWireBytesAndAuthentication(t *testing.T) {
	user := strings.Repeat("a", 64)
	for _, size := range []int{1, 16, 32, 63, 64, 65, 128, 256} {
		secret := make([]byte, size)
		for index := range secret {
			secret[index] = byte(index * 29)
		}
		for _, expiry := range []int64{-1 << 63, -1, 0, 1, 1790709000, 1<<63 - 1} {
			payload := "v1\n" + user + "\n" + strconv.FormatInt(expiry, 10) + "\n"
			want := referenceToken(secret, payload)
			got := Token_IssueAuthToken(secret, user, expiry)
			if got.Error != "" || got.Value != want {
				t.Fatalf("issue key=%d expiry=%d: got %#v, want %q", size, expiry, got, want)
			}
			for _, now := range []int64{expiry, 0, 1790709000, 1<<63 - 1} {
				if got, want := Token_VerifyAuthToken(secret, got.Value, now), referenceVerifyToken(secret, want, now); got != want {
					t.Fatalf("verify key=%d expiry=%d now=%d: got %#v, want %#v", size, expiry, now, got, want)
				}
			}
		}
	}
	secret := []byte("stable test secret")
	for _, payload := range []string{
		"", "v1\n", "v1\n" + user + "\n1", "v2\n" + user + "\n1\n",
		"v1\n" + strings.Repeat("A", 64) + "\n1\n", "v1\nshort\n1\n",
		"v1\n" + user + "\n+1\n", "v1\n" + user + "\n01\n",
		"v1\n" + user + "\n 1\n", "v1\n" + user + "\n1_0\n",
		"v1\n" + user + "\n9223372036854775808\n",
		"v1\n" + user + "\n-9223372036854775809\n",
		"v1\n" + user + "\n1\nextra\nfields",
	} {
		token := referenceToken(secret, payload)
		for _, now := range []int64{0, 1, 2} {
			if got, want := Token_VerifyAuthToken(secret, token, now), referenceVerifyToken(secret, token, now); got != want {
				t.Fatalf("authenticated payload %q at %d: got %#v, want %#v", payload, now, got, want)
			}
		}
	}
	valid := referenceToken(secret, "v1\n"+user+"\n1\n")
	for _, token := range []string{"", ".", "...", "!.!", valid + ".", valid[:len(valid)-1], valid + "="} {
		if got, want := Token_VerifyAuthToken(secret, token, 0), referenceVerifyToken(secret, token, 0); got != want {
			t.Fatalf("malformed token %q: got %#v, want %#v", token, got, want)
		}
	}
	if got := Token_VerifyAuthToken([]byte("wrong secret"), valid, 0); got.Error != "invalid token signature" {
		t.Fatalf("wrong key accepted: %#v", got)
	}
	if got := Token_IssueAuthToken(nil, user, 1); got.Error != "invalid token input" {
		t.Fatalf("empty key accepted: %#v", got)
	}
	if got := Token_IssueAuthToken(secret, "invalid", 1); got.Error != "invalid token input" {
		t.Fatalf("invalid user accepted: %#v", got)
	}
}

func FuzzZiranTokenVerification(f *testing.F) {
	secret := []byte("test token key")
	f.Add(referenceToken(secret, "v1\n"+strings.Repeat("a", 64)+"\n1\n"))
	f.Add("invalid")
	f.Fuzz(func(t *testing.T, token string) {
		if got, want := Token_VerifyAuthToken(secret, token, 0), referenceVerifyToken(secret, token, 0); got != want {
			t.Fatalf("verify %q: got %#v, want %#v", token, got, want)
		}
	})
}
