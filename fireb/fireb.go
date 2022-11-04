package fireb

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/mousybusiness/firebase_token/creds"
	"github.com/mousybusiness/firebase_token/rand"
	"github.com/mousybusiness/firebase_token/static"
	"github.com/mousybusiness/firebase_token/web"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type (
	Exchange struct {
		Code         string `json:"code"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		RedirectURI  string `json:"redirect_uri"`
		GrantType    string `json:"grant_type"`
	}

	Token struct {
		IDToken      string `json:"id_token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
		ExpiresIn    int    `json:"expires_in"`
	}

	LoginRequest struct {
		RequestUri          string `json:"requestUri"`
		PostBody            string `json:"postBody"`
		ReturnSecureToken   bool   `json:"returnSecureToken"`
		ReturnIdpCredential bool   `json:"returnIdpCredential"`
	}

	FirebaseFlow struct {
		port        string
		credentials *creds.Credentials
	}

	RefreshResponse struct {
		ExpiresIn    string `json:"expires_in"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		UserID       string `json:"user_id"`
		ProjectID    string `json:"project_id"`
	}

	APIKey string
)

const (
	//port       = "5000"
	refreshURL = "https://securetoken.googleapis.com/v1/token"
	idpURL     = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithIdp"
)

var (
	scopes = []string{
		"email",
		"profile",
		"openid",
		"https://www.googleapis.com/auth/userinfo.email",
		"https://www.googleapis.com/auth/userinfo.profile",
	}

	nonce  = rand.Generate(12)
	server *http.Server
	authWG *sync.WaitGroup
	cfg    Config
)

var callback func(w http.ResponseWriter, r *http.Request)

func init() {
	http.HandleFunc("/__/auth/handler", handlerWrapper)
}

func handlerWrapper(w http.ResponseWriter, r *http.Request) {
	if callback != nil {
		callback(w, r)
	}
}

func New(port string, config Config) *FirebaseFlow {
	flow := new(FirebaseFlow)
	flow.port = port
	callback = flow.redirectHandler
	cfg = config
	return flow
}

// open attempts an os specific opening of transferred files or urls
func open(uri string) error {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", uri).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll.FileProtocolHandler", uri).Start()
	case "darwin":
		err = exec.Command("open", uri).Start()
	default:
		err = errors.New("unsupported platform, cannot open browser")
	}

	return err
}

// Auth generates a URL which the user can click to navigate to the
// Google login page to authenticate their CLI API calls using a Firebase user
func (f *FirebaseFlow) Auth() *creds.Credentials {
	f.credentials = nil

	authWG = new(sync.WaitGroup)
	authWG.Add(1)

	f.serve()

	s := strings.Join(scopes, " ")

	redirectURI := fmt.Sprintf("http://localhost:%v/__/auth/handler", f.port)

	params := url.Values{}
	params.Add("client_id", cfg.ClientID)
	params.Add("scope", s)
	params.Add("response_type", "code")
	params.Add("state", nonce)
	params.Add("redirect_uri", redirectURI)
	params.Add("access_type", "offline")

	uri := cfg.AuthURI + "?" + params.Encode()

	if err := open(uri); err != nil {
		fmt.Println("couldnt open browser, please visit manually")
	}
	fmt.Printf("Visit the URL for the auth dialog: %v\n", uri)

	authWG.Wait()
	time.Sleep(time.Second)
	if err := server.Shutdown(context.TODO()); err != nil {
		log.Error(errors.Wrap(err, "error while shutting down server"))
	}

	return f.credentials
}

func (f *FirebaseFlow) Authenticated() bool {
	return f.credentials.Verify()
}

// serve will start a simple http server awaiting
// a callback from the IDP component
func (f *FirebaseFlow) serve() {
	if server != nil {
		_ = server.Close()
	}

	// use server so we can shutdown loter
	srv := &http.Server{
		Addr: ":" + f.port,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			if !strings.HasSuffix(err.Error(), "Server closed") {
				log.Error(errors.Wrap(err, "failed to listen and serve login callback"))
				return
			}
		}
	}()

	server = srv
}

// redirectHandler is invoke after the user logs in using their OAuth2
// identity provider (Google), and contain auth information
// in the query string parameters of the request
func (f *FirebaseFlow) redirectHandler(w http.ResponseWriter, req *http.Request) {
	// inform Auth function that we can return
	defer authWG.Done() // TODO if the callback is never hit this will lock here

	log.Debugf("redirect invoked")
	m := req.URL.Query()
	state := m.Get("state")
	code := m.Get("code")

	if state != nonce {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	redirectURI := fmt.Sprintf("http://localhost:%v/__/auth/handler", f.port)

	ex := Exchange{
		Code:         code,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURI:  redirectURI,
		GrantType:    "authorization_code",
	}

	b, err := json.Marshal(ex)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, static.FailedHTML)
		log.Errorf("failed to marshal exchange payload: %v", err)
	}

	// exchange auth code for token
	statusCode, body, err := web.Post(cfg.TokenURI, time.Second*10, b)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, static.FailedHTML)
		log.Errorf("failed to exchange auth code for token: %v", err)
		return
	}

	if statusCode != http.StatusOK {
		w.WriteHeader(statusCode)
		_, _ = fmt.Fprintln(w, "failed to exchange code for token")
		log.Errorf("failed to exchange auth code for token, code: %v, err: %v", statusCode, err)
		return
	}

	var token Token
	if err := json.Unmarshal(body, &token); err != nil {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, static.FailedHTML)
		log.Errorf("failed to unmarshal token: %v", err)
		return
	}

	// after the Google OAuth2 token has been received, we need to log into Firebase
	r := LoginRequest{
		RequestUri:          "http://localhost",
		PostBody:            fmt.Sprintf("id_token=%v&providerId=google.com", token.IDToken),
		ReturnSecureToken:   true,
		ReturnIdpCredential: true,
	}

	log.Debugf("login request: %v", r)
	b, err = json.Marshal(r)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, static.FailedHTML)
		log.Errorf("failed to marshal login response: %v", err)
	}

	uri := idpURL + "?key=" + cfg.APIKey
	log.Debugf("login uri: %v", uri)
	statusCode, body, err = web.Post(uri, time.Second*10, b)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, static.FailedHTML)
		log.Errorf("failed to login to firebase: %v", err)
		return
	}
	if statusCode != 200 {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, static.FailedHTML)
		log.Errorf("failed to login to firebase, code: %v, err: %v", statusCode, err)
		return
	}

	var resp GoogleAuthResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, static.FailedHTML)
		log.Errorf("failed to unmarshal google auth response: %v", err)
		return
	}

	f.credentials = &creds.Credentials{
		UID:          resp.LocalId,
		IDToken:      creds.IDToken(resp.IDToken),
		RefreshToken: creds.RefreshToken(resp.RefreshToken),
		Expiry:       time.Now(),
	}
	// assign the idToken globally so it can be returned by Auth
	if sec, err := strconv.Atoi(resp.ExpiresIn); err == nil {
		log.Debugf("expires in seconds: %v", sec)
		f.credentials.Expiry = time.Now().Add(time.Duration(sec-60) * time.Second) // allow 1 minute of buffer
	}

	// display success HTML
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintln(w, static.SuccessHTML)

}

func (f *FirebaseFlow) Refresh(refreshToken creds.RefreshToken) (*creds.Credentials, error) {
	f.credentials = &creds.Credentials{}

	token, err := doRefresh(refreshToken, APIKey(cfg.APIKey))
	if err != nil {
		return nil, errors.Wrap(err, "require auth token")
	}

	if token.IDToken == "" {
		return nil, errors.New("require auth token: refresh token response invalid")
	}

	// assign the idToken globally so it can be returned by Auth
	if sec, err := strconv.Atoi(token.ExpiresIn); err == nil {
		f.credentials.Expiry = time.Now().Add(time.Duration(sec-60) * time.Second) // allow 1 minute of buffer
	}

	f.credentials.UID = token.UserID
	f.credentials.RefreshToken = refreshToken
	f.credentials.IDToken = creds.IDToken(token.IDToken)

	return f.credentials, nil
}

func doRefresh(token creds.RefreshToken, secret APIKey) (RefreshResponse, error) {
	b, err := json.Marshal(struct {
		RefreshToken string `json:"refresh_token"`
		GrantType    string `json:"grant_type"`
	}{
		RefreshToken: string(token),
		GrantType:    "refresh_token",
	})
	if err != nil {
		return RefreshResponse{}, err
	}

	resp, err := http.Post(fmt.Sprintf("%s?key=%s", refreshURL, secret), http.DetectContentType(b), bytes.NewReader(b))
	if err != nil {
		return RefreshResponse{}, err
	}

	code := resp.StatusCode
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return RefreshResponse{}, err
	}

	if code != 200 {
		return RefreshResponse{}, errors.New(fmt.Sprintf("status code not 200, code: %d, error: %v", code, string(body)))
	}

	var r RefreshResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return RefreshResponse{}, err
	}

	return r, nil
}
