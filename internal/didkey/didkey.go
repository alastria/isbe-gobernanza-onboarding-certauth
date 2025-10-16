package didkey

import (
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/json"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
)

// GenDIDKey generates a new elliptic curve'did:key' DID by creating an EC key pair
func GenDIDKey(rawPrivKey *ecdsa.PrivateKey) (did string, privateKeyJWK jwk.Key, err error) {

	// Create the JWK for the private and public pair
	privateKeyJWK, err = jwk.FromRaw(rawPrivKey)
	if err != nil {
		return "", nil, err
	}

	pubKeyJWK, err := privateKeyJWK.PublicKey()
	if err != nil {
		return "", nil, err
	}

	// Create the 'did:key' associated to the public key
	did, err = PubKeyToDIDKey(pubKeyJWK)
	if err != nil {
		return "", nil, err
	}

	return did, privateKeyJWK, nil

}

func PubKeyToDIDKey(pubKeyJWK jwk.Key) (did string, err error) {

	var buf [10]byte
	n := binary.PutUvarint(buf[0:], uint64(multicodec.Jwk_jcsPub))
	Jwk_jcsPub_Buf := buf[0:n]

	serialized, err := json.Marshal(pubKeyJWK)
	if err != nil {
		return "", err
	}

	keyEncoded := append(Jwk_jcsPub_Buf, serialized...)

	mb, err := multibase.Encode(multibase.Base58BTC, keyEncoded)
	if err != nil {
		return "", err
	}

	return "did:key:" + mb, nil

}
