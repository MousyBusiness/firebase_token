package fireb

type GoogleAuthResponse struct {
	FederatedId   string `json:"federatedId"`
	ProviderId    string `json:"providerId"`
	LocalId       string `json:"localId"`
	EmailVerified bool   `json:"emailVerified"`
	Email         string `json:"email"`
	OAuthIDToken  string `json:"oauthIdToken"`
	FirstName     string `json:"firstName"`
	LastName      string `json:"lastName"`
	FullName      string `json:"fullName"`
	DisplayName   string `json:"displayName"`
	IDToken       string `json:"idToken"`
	PhotoUrl      string `json:"photoUrl"`
	RefreshToken  string `json:"refreshToken"`
	ExpiresIn     string `json:"expiresIn"`
	RawUserInfo   string `json:"rawUserInfo"`
}
