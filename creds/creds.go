package creds

import (
	"time"
)

type AccessToken string
type IDToken string
type RefreshToken string

type Credentials struct {
	UID string
	AccessToken
	IDToken
	RefreshToken
	Expiry time.Time
}

func (c *Credentials) Verify() bool {
	return c.UID != "" && c.RefreshToken != "" && c.IDToken != ""
}
