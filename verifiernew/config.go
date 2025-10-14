package verifiernew

import (
	"encoding/json"
	"errors"

	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/hesusruiz/vcutils/yaml"
	val "github.com/invopop/validation"
)

type Config struct {
	ListenAddress          string   `json:"listenAddress,omitempty"`
	VerifierURL            string   `json:"verifierURL,omitempty"`
	AuthnPolicies          string   `json:"authnPolicies,omitempty"`
	SamedeviceWallet       string   `json:"samedeviceWallet,omitempty"`
	CredentialTemplatesDir string   `json:"credentialTemplatesDir,omitempty"`
	RegisteredClients      []Client `json:"registeredClients,omitempty"`
}

type Client struct {
	Id           string   `json:"id,omitempty"`
	Type         string   `json:"type,omitempty"`
	Secret       string   `json:"secret,omitempty"`
	RedirectURIs []string `json:"redirectURIs,omitempty"`
}

var defaultConfig = Config{
	ListenAddress:          ":9998",
	VerifierURL:            "https://verifier.mycredential.eu",
	AuthnPolicies:          "authn_policies.star",
	SamedeviceWallet:       "https://wallet.mycredential.eu",
	CredentialTemplatesDir: "data/credential_templates",
}

func ConfigFromMap(cfg *yaml.YAML) (*Config, error) {
	d, err := json.Marshal(cfg.Data())
	if err != nil {
		return nil, err
	}

	config := &Config{}
	err = json.Unmarshal(d, config)
	if err != nil {
		return nil, err
	}

	err = config.Validate()

	return config, err

}

func (s *Config) SetDefaults() {

}

func (s *Config) Validate() (err error) {

	// SamedeviceWallet and VerifierURL are required
	if len(s.SamedeviceWallet) == 0 {
		return errors.New("samedeviceWallet is required")
	}
	if len(s.VerifierURL) == 0 {
		return errors.New("verifierURL is required")
	}

	// Other values are optional and will be set to default values if not provided
	if len(s.ListenAddress) == 0 {
		s.ListenAddress = defaultConfig.ListenAddress
	}
	if len(s.AuthnPolicies) == 0 {
		s.AuthnPolicies = defaultConfig.AuthnPolicies
	}
	if len(s.CredentialTemplatesDir) == 0 {
		s.CredentialTemplatesDir = defaultConfig.CredentialTemplatesDir
	}

	err = val.ValidateStruct(s,
		val.Field(&s.ListenAddress, val.Required),
		val.Field(&s.VerifierURL, val.Required, is.URL),
		val.Field(&s.AuthnPolicies, val.Required),
		val.Field(&s.SamedeviceWallet, val.Required, is.URL),
		val.Field(&s.CredentialTemplatesDir, val.Required),
	)

	if err != nil {
		return err
	}

	if len(s.RegisteredClients) > 0 {
		err = val.Validate(&s.RegisteredClients, val.Required)
	}

	return err
}

func (s *Config) Copy() Config {
	return Config{}
}

func (s *Config) OverrideWith(other Config) {

}

func (s *Config) String() string {
	out, _ := json.MarshalIndent(s, "", "  ")
	return string(out)
}
