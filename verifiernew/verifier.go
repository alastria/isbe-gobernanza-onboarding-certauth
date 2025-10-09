package verifiernew

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/hesusruiz/vcutils/yaml"

	"crypto/sha256"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/evidenceledger/certauth/verifiernew/storage"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/zitadel/logging"
	"golang.org/x/text/language"

	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	pathLoggedOut = "/logged-out"
)

type VerifierServer struct {
	Config     *Config
	HTTPServer *http.Server
}

func Start(cfg *yaml.YAML) error {

	ver := NewVerifier(cfg)

	// Register the configured clients
	for _, cfgClient := range ver.Config.RegisteredClients {
		switch cfgClient.Type {
		case "web":
			cl, err := storage.WebClient(cfgClient.Id, cfgClient.Secret, cfgClient.RedirectURIs...)
			if err != nil {
				return err
			}
			storage.RegisterClients(cl)
		case "native":
			cl, err := storage.WebClient(cfgClient.Id, cfgClient.Secret, cfgClient.RedirectURIs...)
			if err != nil {
				return err
			}
			storage.RegisterClients(cl)
		default:
			return fmt.Errorf("invalid Client specified: %s", cfgClient.Id)
		}
	}

	// The OpenIDProvider interface needs a Storage interface handling various checks and state manipulations.
	// This is normally used as the layer for accessing a database, but we do not need permanent verifierStorage for users
	// and it will be handled in-memory because the user data is coming from the Verifiable Credential presented.
	verifierStorage := storage.NewStorage(ver.Config.VerifierURL, storage.NewUserStore(ver.Config.VerifierURL))

	logger := slog.New(
		slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			AddSource: true,
			Level:     slog.LevelDebug,
		}),
	)

	router, err := ver.SetupServer(verifierStorage, logger)
	if err != nil {
		return err
	}

	router.Post("/reqonbehalf", RequestOnBehalf)

	go func() {

		ver.HTTPServer = &http.Server{
			Addr:    ver.Config.ListenAddress,
			Handler: router,
		}
		logger.Info("Verifier listening, press ctrl+c to stop", "addr", ver.Config.ListenAddress)

		err := ver.HTTPServer.ListenAndServe()
		if err != http.ErrServerClosed {
			logger.Error("server terminated", "error", err)
			os.Exit(1)
		}
	}()

	return nil
}

func RequestOnBehalf(w http.ResponseWriter, r *http.Request) {

	fmt.Println("RequestOnBehalf")

	type requestData struct {
		Method string `json:"method,omitempty"`
		Url    string `json:"url,omitempty"`
	}
	reqData := requestData{}

	err := json.NewDecoder(r.Body).Decode(&reqData)
	if err != nil {
		msg := fmt.Sprintf("error decoding Body: %s", err.Error())
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	requestMethod := reqData.Method
	requestURL := reqData.Url

	fmt.Println("RequestOnBehalf, method:", requestMethod, "URL", requestURL)

	if requestMethod == "GET" {
		resp, err := http.Get(requestURL)
		if err != nil {
			http.Error(w, fmt.Sprintf("error %s making request: %s", err, requestURL), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("error %s reading reply", err), http.StatusInternalServerError)
			return
		}

		fmt.Println(string(body))

		w.Write(body)
		return
	} else {
		http.Error(w, fmt.Sprintf("method not supported %s", requestMethod), http.StatusBadRequest)
		return
	}

}

func NewVerifier(cfg *yaml.YAML) *VerifierServer {
	ver := &VerifierServer{}

	c, err := ConfigFromMap(cfg)
	if err != nil {
		panic(err)
	}
	ver.Config = c

	return ver

}
func InspectRuntime() (baseDir string, withGoRun bool) {
	if strings.HasPrefix(os.Args[0], os.TempDir()) {
		// probably ran with go run
		withGoRun = true
		baseDir, _ = os.Getwd()
	} else {
		// probably ran with go build
		withGoRun = false
		baseDir = filepath.Dir(os.Args[0])
	}
	return
}

type Storage interface {
	op.Storage
	authenticate
}

// simple counter for request IDs
var counter atomic.Int64

// var pdp *PDP

// SetupServer creates an OIDC server with the configured verifier URL
func (ver *VerifierServer) SetupServer(storage Storage, logger *slog.Logger, extraOptions ...op.Option) (chi.Router, error) {
	var err error

	// // Start the Policy Decision Point engine for this Verifier
	// pdp, err = NewPDP(ver.Config.AuthnPolicies)
	// if err != nil {
	// 	return nil, fmt.Errorf("starting authn policies runtime: %w", err)
	// }

	// the OpenID Provider requires a 32-byte verifierKey for (token) encryption
	// be sure to create a proper crypto random verifierKey and manage it securely!
	// TODO: use Pocketbase secret management for the Verifier verifierKey
	verifierKey := sha256.Sum256([]byte("test"))

	router := chi.NewRouter()
	// Basic CORS
	router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	router.Use(logging.Middleware(
		logging.WithLogger(logger),
		logging.WithIDFunc(func() slog.Attr {
			return slog.Int64("id", counter.Add(1))
		}),
	))

	fs := http.FileServer(http.Dir("verifiernew/static"))
	router.Handle("/static/*", http.StripPrefix("/static/", fs))

	// for simplicity, we provide a very small default page for users who have signed out
	// TODO: replace with a proper page.
	router.HandleFunc(pathLoggedOut, func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("signed out successfully"))
		// no need to check/log error, this will be handled by the middleware.
	})

	// creation of the OpenIDProvider with the just created in-memory Storage
	verifierProvider, err := newOP(storage, ver.Config.VerifierURL, verifierKey, logger, extraOptions...)
	if err != nil {
		return nil, fmt.Errorf("creating new OP: %w", err)
	}

	//the verifierProvider will only take care of the OpenID Protocol, so there must be some sort of UI for the login process
	//for the simplicity of the example this means a simple page with username and password field
	//be sure to provide an IssuerInterceptor with the IssuerFromRequest from the OP so the login can select / and pass it to the storage
	// TODO: we will put the Verifiable Credential authentication process replacing the user/password screen.
	loginProcess := NewLogin(
		ver.Config,
		storage,
		op.AuthCallbackURL(verifierProvider),
		op.NewIssuerInterceptor(verifierProvider.IssuerFromRequest),
	)

	// regardless of how many pages / steps there are in the process, the UI must be registered in the router,
	// so we will direct all calls to /login to the login UI
	router.Mount("/login/", http.StripPrefix("/login", loginProcess.router))

	handler := http.Handler(verifierProvider)

	// We register the http handler of the OP on the root, so that the discovery endpoint (/.well-known/openid-configuration)
	// is served on the correct path.
	router.Mount("/", handler)

	return router, nil
}

// newOP will create an OpenID Provider for the verifierUrl with a given encryption key
// and a predefined default logout uri
// it will enable all options (see descriptions)
func newOP(storage op.Storage, verifierUrl string, verifierKey [32]byte, logger *slog.Logger, extraOptions ...op.Option) (op.OpenIDProvider, error) {
	config := &op.Config{
		CryptoKey: verifierKey,

		// will be used if the end_session endpoint is called without a post_logout_redirect_uri
		DefaultLogoutRedirectURI: pathLoggedOut,

		// enables code_challenge_method S256 for PKCE (and therefore PKCE in general)
		CodeMethodS256: true,

		// enables additional client_id/client_secret authentication by form post (not only HTTP Basic Auth)
		AuthMethodPost: true,

		// enables additional authentication by using private_key_jwt
		AuthMethodPrivateKeyJWT: true,

		// enables refresh_token grant use
		GrantTypeRefreshToken: true,

		// enables use of the `request` Object parameter
		RequestObjectSupported: true,

		// we only support English for the moment
		SupportedUILocales: []language.Tag{language.English},

		DeviceAuthorization: op.DeviceAuthorizationConfig{
			Lifetime:     5 * time.Minute,
			PollInterval: 5 * time.Second,
			UserFormPath: "/device",
			UserCode:     op.UserCodeBase20,
		},
	}
	handler, err := op.NewProvider(config, storage, op.StaticIssuer(verifierUrl),
		append([]op.Option{

			// as an example on how to customize an endpoint this will change the authorization_endpoint from /authorize to /auth
			// op.WithCustomAuthEndpoint(op.NewEndpoint("auth")),

			// Pass our logger to the OP
			op.WithLogger(logger.WithGroup("op")),
		}, extraOptions...)...,
	)
	if err != nil {
		return nil, err
	}
	return handler, nil
}
