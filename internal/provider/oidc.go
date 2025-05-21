package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// OIDC provider
type OIDC struct {
	IssuerURL    string `long:"issuer-url" env:"ISSUER_URL" description:"Issuer URL"`
	ClientID     string `long:"client-id" env:"CLIENT_ID" description:"Client ID"`
	ClientSecret string `long:"client-secret" env:"CLIENT_SECRET" description:"Client Secret" json:"-"`

	OAuthProvider

	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
}

// Name returns the name of the provider
func (o *OIDC) Name() string {
	return "oidc"
}

type transportWithAudience struct {
	Base     http.RoundTripper
	Audience string
}

func (t *transportWithAudience) RoundTrip(req *http.Request) (*http.Response, error) {
	// TODO Used for debugging but can be removed for final release. Also really the whole replacement of the http method can be removed.
	fmt.Println("WWWWWWWW")
	fmt.Println(req.URL.Path)
	if req.URL.Path == "/oauth/token" {
		//bodyBytes, _ := io.ReadAll(req.Body)
		//fmt.Println("BBBBBBB")
		//fmt.Println(string(bodyBytes))
		//fmt.Println(req.Method)
		//fmt.Println(req.URL)
	}
	return t.Base.RoundTrip(req)
}

// Setup performs validation and setup
func (o *OIDC) Setup() error {
	// Check parms
	if o.IssuerURL == "" || o.ClientID == "" || o.ClientSecret == "" {
		return errors.New("providers.oidc.issuer-url, providers.oidc.client-id, providers.oidc.client-secret must be set")
	}

	httpClient := &http.Client{
		Transport: &transportWithAudience{
			Base:     http.DefaultTransport,
			Audience: "astronomer-ee",
		},
	}

	var err error
	ctx := context.Background()
	o.ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	// Try to initiate provider
	o.provider, err = oidc.NewProvider(o.ctx, o.IssuerURL)
	if err != nil {
		return err
	}

	// Create oauth2 config
	o.Config = &oauth2.Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		Endpoint:     o.provider.Endpoint(),
		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email", oidc.ScopeOfflineAccess},
	}

	// Create OIDC verifier
	o.verifier = o.provider.Verifier(&oidc.Config{
		ClientID: o.ClientID,
	})

	return nil
}

// GetLoginURL provides the login url for the given redirect uri and state
func (o *OIDC) GetLoginURL(redirectURI, state string) string {
	return o.OAuthGetLoginURL(redirectURI, state)
}

// ExchangeCode exchanges the given redirect uri and code for a token
func (o *OIDC) ExchangeCode(redirectURI, code string) (string, error) {
	token, err := o.OAuthExchangeCode(redirectURI, code)
	if err != nil {
		return "", err
	}

	// Extract ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return "", errors.New("Missing id_token")
	}

	return rawIDToken, nil
}

// GetUser uses the given token and returns a complete provider.User object
func (o *OIDC) GetUser(token string) (User, error) {
	var user User

	// Parse & Verify ID Token
	idToken, err := o.verifier.Verify(o.ctx, token)
	if err != nil {
		return user, err
	}

	// Extract custom claims
	if err := idToken.Claims(&user); err != nil {
		return user, err
	}

	return user, nil
}
