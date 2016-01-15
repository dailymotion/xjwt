package xjwt

import (
	"net/http"

	"golang.org/x/net/context"

	"github.com/dgrijalva/jwt-go"
	"github.com/rs/xhandler"
)

type Config struct {
	Secret    string
	Issuer    string
	Audiences []string
	BasicUser string
	BasicPass string
	Skip      []string
}

const (
	ClaimIssuer    = "iss"
	ClaimAudiences = "aud"
)

func NewHandler(c Config) func(xhandler.HandlerC) xhandler.HandlerC {
	return func(next xhandler.HandlerC) xhandler.HandlerC {
		return xhandler.HandlerFuncC(func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
			var auth bool

			// Skip verification of path is in skip list.
			for _, skipPath := range c.Skip {
				if r.URL.Path == skipPath {
					auth = true
					break
				}
			}

			if !auth && c.Secret != "" {
				// Check token credentials.
				auth = checkToken(c, r)
			}

			// Check basic auth if no authorization based on token.
			if !auth && c.BasicUser != "" && c.BasicPass != "" {
				auth = checkBasicAuth(c, w, r)
			}

			if auth {
				next.ServeHTTPC(ctx, w, r)
			} else {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			}
		})
	}
}

func checkBasicAuth(c Config, w http.ResponseWriter, r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}

	return user == c.BasicUser && pass == c.BasicPass
}

func checkToken(c Config, r *http.Request) bool {
	token, err := jwt.ParseFromRequest(r, func(token *jwt.Token) (interface{}, error) {
		return []byte(c.Secret), nil
	})

	if err == nil && token.Valid {
		if c.Issuer != "" && token.Claims[ClaimIssuer].(string) != c.Issuer {
			return false
		}

		if len(c.Audiences) > 0 {
			switch token.Claims[ClaimAudiences].(type) {
			case string:
				for _, aud := range c.Audiences {
					if token.Claims[ClaimAudiences].(string) == aud {
						return true
					}
				}
			case []string:
				for _, aud := range c.Audiences {
					for _, claimAud := range token.Claims[ClaimAudiences].([]string) {
						if claimAud == aud {
							return true
						}
					}
				}
			}
		} else {
			return true
		}
	}

	return false
}
