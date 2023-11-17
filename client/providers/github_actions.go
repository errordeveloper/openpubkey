package providers

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/awnumar/memguard"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/client"
	oidcclient "github.com/zitadel/oidc/v2/pkg/client"
)

const (
	Issuer = "https://token.actions.githubusercontent.com"

	EnvTokenURL = "ACTIONS_ID_TOKEN_REQUEST_URL"
	EnvToken    = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
)

type GitHubActions struct {
	rawTokenRequestURL    string
	tokenRequestAuthToken string
}

var _ client.OpenIdProvider = (*GitHubActions)(nil)

func NewGitHubActionsFromEnvironment() (*GitHubActions, error) {
	tokenURL, hasTokenURL := os.LookupEnv(EnvTokenURL)
	token, hasToken := os.LookupEnv(EnvToken)

	if !hasTokenURL || !hasToken {
		return nil, fmt.Errorf("missing environment variables %q and/or %q", EnvTokenURL, EnvToken)
	}

	return NewGitHubActions(tokenURL, token), nil
}

func NewGitHubActions(tokenURL string, token string) *GitHubActions {
	return &GitHubActions{
		rawTokenRequestURL:    tokenURL,
		tokenRequestAuthToken: token,
	}
}

func buildTokenURL(rawTokenURL, audience string) (string, error) {
	parsedURL, err := url.Parse(rawTokenURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL: %w", err)
	}

	if audience == "" {
		return "", fmt.Errorf("audience is required")
	}

	query := parsedURL.Query()
	query.Set("audience", audience)
	parsedURL.RawQuery = query.Encode()
	return parsedURL.String(), nil
}

func (g *GitHubActions) VerifyCICHash(ctx context.Context, idt []byte, expectedCICHash string) error {
	cicHash, err := client.ExtractClaim(idt, "aud")
	if err != nil {
		return err
	}

	if cicHash != expectedCICHash {
		return fmt.Errorf("aud claim doesn't match, got %q, expected %q", cicHash, expectedCICHash)
	}

	return nil
}

func (g *GitHubActions) PublicKey(ctx context.Context, idt []byte) (crypto.PublicKey, error) {
	j, err := jws.Parse(idt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWS: %w", err)
	}
	headers := j.Signatures()[0].ProtectedHeaders()
	alg, kid := headers.Algorithm(), headers.KeyID()
	if alg != jwa.RS256 {
		return nil, fmt.Errorf("expected RS256 alg claim, got %s", alg)
	}

	discovery, err := oidcclient.Discover(Issuer, http.DefaultClient)
	if err != nil {
		return nil, fmt.Errorf("failed to call OIDC discovery endpoint: %w", err)
	}

	jwks, err := jwk.Fetch(ctx, discovery.JwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch to JWKS: %w", err)
	}

	key, ok := jwks.LookupKeyID(kid)
	if !ok {
		return nil, fmt.Errorf("key %q isn't in JWKS", kid)
	}
	keyAlg := key.Algorithm()
	if keyAlg != jwa.RS256 {
		return nil, fmt.Errorf("expected RS256 key, got %s", keyAlg)
	}

	pubKey := new(rsa.PublicKey)
	err = key.Raw(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	return pubKey, err
}

func (g *GitHubActions) RequestTokens(ctx context.Context, cicHash string) (*memguard.LockedBuffer, error) {
	tokenURL, err := buildTokenURL(g.rawTokenRequestURL, cicHash)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, "GET", tokenURL, nil)
	if err != nil {
		return nil, err
	}

	request.Header.Set("Authorization", "Bearer "+g.tokenRequestAuthToken)

	var httpClient http.Client
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-200 from jwt api: %s", http.StatusText(response.StatusCode))
	}

	rawBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var jwt struct {
		Value *memguard.LockedBuffer
	}
	err = json.Unmarshal(rawBody, &jwt)
	memguard.WipeBytes(rawBody)

	return jwt.Value, err
}

func (*GitHubActions) VerifyNonGQSig(context.Context, []byte, string) error {
	return client.ErrNonGQUnsupported
}
