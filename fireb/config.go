package fireb

type Root struct {
	Config `json:"web"`
}

type Config struct {
	ProjectID    string `json:"project_id"`
	AuthURI      string `json:"auth_uri"`
	TokenURI     string `json:"token_uri"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	APIKey       string
}
