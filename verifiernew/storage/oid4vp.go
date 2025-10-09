package storage

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type OID4VPAuthRequest struct {
	jwt.RegisteredClaims
	Scope          string `json:"scope,omitempty"`
	ResponseType   string `json:"response_type,omitempty"`
	ResponseMode   string `json:"response_mode,omitempty"`
	ClientId       string `json:"client_id,omitempty"`
	ClientIdScheme string `json:"client_id_scheme,omitempty"`
	ResponseUri    string `json:"response_uri,omitempty"`
	State          string `json:"state,omitempty"`
	Nonce          string `json:"nonce,omitempty"`
}

func (o *OID4VPAuthRequest) String() string {
	out, _ := json.MarshalIndent(o, "", "  ")
	return string(out)
}

// createJWTSecuredAuthenticationRequest creates an Authorization Request Object according to:
// "IETF RFC 9101: The OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request (JAR)""
func createJWTSecuredAuthenticationRequest(response_uri string, state string) (string, error) {

	// This specifies the type of credential that the Verifier will accept
	// TODO: In this use case it is hardcoded, which is enough if the Verifier is simple and uses
	// only one type of credential for authenticating its users.

	verifierDID := "did:elsi:VATES:55555555"

	// Prepare some fields of the LEARCredential
	now := time.Now()

	// Create claims with multiple fields populated
	claims := OID4VPAuthRequest{
		Scope:          "LEARCredentialEmployee",
		ResponseType:   "vp_token",
		ResponseMode:   "direct_post",
		ClientId:       verifierDID,
		ClientIdScheme: "did",
		ResponseUri:    response_uri,
		State:          state,
		Nonce:          GenerateNonce(),
	}

	claims.ExpiresAt = jwt.NewNumericDate(now.Add(24 * 365 * time.Hour))
	claims.IssuedAt = jwt.NewNumericDate(now)
	claims.NotBefore = jwt.NewNumericDate(now)
	claims.Issuer = verifierDID
	claims.Audience = jwt.ClaimStrings{"self-issued"}
	claims.ID = GenerateNonce()

	// TODO: use the did:elsi method and sign with the private key associated to the certificate
	// Generate a raw EC key with the P-256 curve
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	return token.SignedString(privateKey)

}

func GenerateNonce() string {
	b := make([]byte, 16)
	io.ReadFull(rand.Reader, b)
	nonce := base64.RawURLEncoding.EncodeToString(b)
	return nonce
}
