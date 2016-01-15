package xjwt

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/context"

	"github.com/dgrijalva/jwt-go"
	"github.com/rs/xhandler"
)

func generateToken() (string, error) {
	tok := jwt.New(jwt.SigningMethodHS256)
	tok.Claims[ClaimIssuer] = "dmiss"
	tok.Claims[ClaimAudiences] = "dm"

	tokenString, err := tok.SignedString([]byte("5d63GMY5fRsBRdB7cDsMoLlNX9vWxNSq"))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func TestNewHandlerWrongKey(t *testing.T) {
	c := Config{
		Secret:    "secret",
		Issuer:    "dmiss",
		Audiences: []string{"dm"},
	}
	h := NewHandler(c)
	xh := h(xhandler.HandlerFuncC(func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tok, err := generateToken()
	if err != nil {
		t.Fatalf("generateToken() - error encoding claim: %s", err)
	}
	fullPath := "/?access_token=" + tok

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", fullPath, nil)

	xh.ServeHTTPC(context.Background(), w, r)

	if want, got := http.StatusForbidden, w.Code; want != got {
		t.Errorf("TestNewHandlerWrongKey http code: want %d got %d", want, got)
	}
}

func TestNewHandlerWrongIssuer(t *testing.T) {
	c := Config{
		Secret:    "5d63GMY5fRsBRdB7cDsMoLlNX9vWxNSq",
		Issuer:    "issuer",
		Audiences: []string{"dm"},
	}
	h := NewHandler(c)
	xh := h(xhandler.HandlerFuncC(func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tok, err := generateToken()
	if err != nil {
		t.Fatalf("generateToken() - error encoding claim: %s", err)
	}
	fullPath := "/?access_token=" + tok

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", fullPath, nil)

	xh.ServeHTTPC(context.Background(), w, r)

	if want, got := http.StatusForbidden, w.Code; want != got {
		t.Errorf("TestNewHandlerWrongIssuer http code: want %d got %d", want, got)
	}
}

func TestNewHandlerWrongAudience(t *testing.T) {
	c := Config{
		Secret:    "5d63GMY5fRsBRdB7cDsMoLlNX9vWxNSq",
		Issuer:    "dmiss",
		Audiences: []string{"aud1", "aud2"},
	}
	h := NewHandler(c)
	xh := h(xhandler.HandlerFuncC(func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tok, err := generateToken()
	if err != nil {
		t.Fatalf("generateToken() - error encoding claim: %s", err)
	}
	fullPath := "/?access_token=" + tok

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", fullPath, nil)

	xh.ServeHTTPC(context.Background(), w, r)

	if want, got := http.StatusForbidden, w.Code; want != got {
		t.Errorf("TestNewHandlerWrongAudience http code: want %d got %d", want, got)
	}
}

func TestNewHandlerWithJWT(t *testing.T) {
	c := Config{
		Secret:    "5d63GMY5fRsBRdB7cDsMoLlNX9vWxNSq",
		Issuer:    "dmiss",
		Audiences: []string{"dm"},
	}
	h := NewHandler(c)
	xh := h(xhandler.HandlerFuncC(func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tok, err := generateToken()
	if err != nil {
		t.Fatalf("generateToken() - error encoding claim: %s", err)
	}
	fullPath := "/?access_token=" + tok

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", fullPath, nil)

	xh.ServeHTTPC(context.Background(), w, r)

	if got := w.Code; got < 200 || got > 299 {
		t.Errorf("TestNewHandlerWithJWT http code: want 200 got %d", got)
	}
}

func TestNewHandlerWithBasicAuth(t *testing.T) {
	c := Config{
		BasicUser: "user",
		BasicPass: "pass",
	}
	h := NewHandler(c)
	xh := h(xhandler.HandlerFuncC(func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	r.SetBasicAuth("user", "pass")

	xh.ServeHTTPC(context.Background(), w, r)

	if got := w.Code; got < 200 || got > 299 {
		t.Errorf("TestNewHandlerWithJWT http code: want 200 got %d", got)
	}
}

func TestNewHandlerSkip(t *testing.T) {
	c := Config{
		Secret:    "secret",
		Issuer:    "issuer",
		Audiences: []string{"aud"},
		BasicUser: "user",
		BasicPass: "pass",
		Skip:      []string{"/healthz"},
	}
	h := NewHandler(c)
	xh := h(xhandler.HandlerFuncC(func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/healthz", nil)

	xh.ServeHTTPC(context.Background(), w, r)

	if got := w.Code; got < 200 || got > 299 {
		t.Errorf("TestNewHandlerSkip http code: want 200 got %d", got)
	}
}
