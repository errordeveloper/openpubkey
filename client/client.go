package client

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"

	"github.com/awnumar/memguard"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
)

type Client struct {
	Provider OpenIdProvider
}

func (c *Client) OidcAuth(
	ctx context.Context,
	signer crypto.Signer,
	alg jwa.KeyAlgorithm,
	extraClaims map[string]any,
	signGQ bool,
) (*pktoken.PKToken, error) {
	// Use our signing key to generate a JWK key with the alg header set
	jwkKey, err := jwk.PublicKeyOf(signer)
	if err != nil {
		return nil, err
	}
	jwkKey.Set(jwk.AlgorithmKey, alg)

	// Use provided public key to generate client instance claims
	cic, err := clientinstance.NewClaims(jwkKey, extraClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate client instance claims: %w", err)
	}

	// Define our OIDC nonce as a commitment to the client instance claims
	nonce, err := cic.Hash()
	if err != nil {
		return nil, fmt.Errorf("error getting nonce: %w", err)
	}

	// Use the commitment nonce to complete the OIDC flow and get an ID token from the provider
	idToken, err := c.Provider.RequestTokens(ctx, string(nonce))
	if err != nil {
		return nil, fmt.Errorf("error requesting ID Token: %w", err)
	}
	defer idToken.Destroy()

	// Sign over the payload from the ID token and client instance claims
	cicToken, err := cic.Sign(signer, alg, idToken.Bytes())
	if err != nil {
		return nil, fmt.Errorf("error creating cic token: %w", err)
	}

	if signGQ {
		opKey, err := c.Provider.PublicKey(ctx, idToken.Bytes())
		if err != nil {
			return nil, fmt.Errorf("error getting OP public key: %w", err)
		}
		rsaPubKey := opKey.(*rsa.PublicKey)

		sv := gq.NewSignerVerifier(rsaPubKey, GQSecurityParameter)
		gqToken, err := sv.SignJWT(idToken.Bytes())
		if err != nil {
			return nil, fmt.Errorf("error creating GQ signature: %w", err)
		}
		idToken = memguard.NewBufferFromBytes(gqToken)
	}

	// Combine our ID token and signature over the cic to create our PK Token
	pkt, err := pktoken.New(idToken.Bytes(), cicToken, signGQ)
	if err != nil {
		return nil, fmt.Errorf("error creating PK Token: %w", err)
	}

	err = VerifyPKToken(ctx, pkt, c.Provider)
	if err != nil {
		return nil, fmt.Errorf("error verifying PK Token: %w", err)
	}

	return pkt, nil
}
