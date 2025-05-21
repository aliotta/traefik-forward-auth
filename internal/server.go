package tfa

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/aliotta/traefik-forward-auth/internal/provider"
	"github.com/sirupsen/logrus"
	muxhttp "github.com/traefik/traefik/v2/pkg/muxer/http"
)

// Server contains muxer and handler methods
type Server struct {
	muxer *muxhttp.Muxer
}

// NewServer creates a new server object and builds muxer
func NewServer() *Server {
	s := &Server{}
	s.buildRoutes()
	return s
}

func (s *Server) buildRoutes() {
	var err error
	s.muxer, err = muxhttp.NewMuxer()
	if err != nil {
		log.Fatal(err)
	}

	// Let's build a muxer
	for name, rule := range config.Rules {
		matchRule := rule.formattedRule()
		if rule.Action == "allow" {
			_ = s.muxer.AddRoute(matchRule, 1, s.AllowHandler(name))
		} else {
			_ = s.muxer.AddRoute(matchRule, 1, s.AuthHandler(rule.Provider, name))
		}
	}

	// Add callback handler
	s.muxer.Handle(config.Path, s.AuthCallbackHandler())

	// Add logout handler
	s.muxer.Handle(config.Path+"/logout", s.LogoutHandler())

	// Add a default handler
	if config.DefaultAction == "allow" {
		s.muxer.NewRoute().Handler(s.AllowHandler("default"))
	} else {
		s.muxer.NewRoute().Handler(s.AuthHandler(config.DefaultProvider, "default"))
	}
}

// RootHandler Overwrites the request method, host and URL with those from the
// forwarded request so it's correctly routed by mux
func (s *Server) RootHandler(w http.ResponseWriter, r *http.Request) {
	// Modify request
	r.Method = r.Header.Get("X-Forwarded-Method")
	r.Host = r.Header.Get("X-Forwarded-Host")

	// Read URI from header if we're acting as forward auth middleware
	if _, ok := r.Header["X-Forwarded-Uri"]; ok {
		r.URL, _ = url.Parse(r.Header.Get("X-Forwarded-Uri"))
	}

	// Pass to mux
	s.muxer.ServeHTTP(w, r)
}

// AllowHandler Allows requests
func (s *Server) AllowHandler(rule string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.logger(r, "Allow", rule, "Allowing request")
		w.WriteHeader(200)
	}
}

type AuthConn struct {
	Id       string `json:"id"`
	Name     string `json:"name"`
	Strategy string `json:"strategy"`
}

type CustomClaims struct {
	OrgAuthServiceId      string   `json:"org_id"`
	Scope                 string   `json:"scope"`
	Permissions           []string `json:"permissions"`
	AuthConnection        AuthConn `json:"https://astronomer.io/jwt/auth_connection"`
	Version               string   `json:"version"`
	IsAstronomerGenerated bool     `json:"isAstronomerGenerated"`
	RsaKeyId              string   `json:"kid"`
	ApiTokenId            string   `json:"apiTokenId"`
	IsInternal            bool     `json:"isInternal"`
	jwt.RegisteredClaims
}

// AuthHandler Authenticates requests
func (s *Server) AuthHandler(providerName, rule string) http.HandlerFunc {
	p, _ := config.GetConfiguredProvider(providerName)

	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "Auth", rule, "Authenticating request")

		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			authHeaderParts := strings.Fields(authHeader)
			if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" || authHeaderParts[1] == "" {
				logger.Warn("Invalid auth token")
				http.Error(w, "Not authorized", 401)
				return
			}

			token := authHeaderParts[1]
			// Parse the token to peek at the custom claims
			jwtParser := jwt.NewParser()
			parsedToken, _, err := jwtParser.ParseUnverified(token, &CustomClaims{})
			if err != nil {
				logger.Warn("Invalid auth token claims")
				http.Error(w, "Not authorized", 401)
				return
			}
			claims, ok := parsedToken.Claims.(*CustomClaims)
			if !ok {
				logger.Warn("Invalid auth token claims")
				http.Error(w, "Not authorized", 401)
				return
			}
			if claims.IsAstronomerGenerated == true && claims.Permissions != nil && len(claims.Permissions) > 0 {
				logger.Debug("Allowing valid api token request")
				w.WriteHeader(200)
			}
		} else {
			// Get auth cookie
			c, err := r.Cookie(config.CookieName)
			if err != nil {
				s.authRedirect(logger, w, r, p)
				return
			}

			// Validate cookie
			token, err := ValidateCookie(r, c)
			if err != nil {
				if err.Error() == "Cookie has expired" {
					logger.Info("Cookie has expired")
					s.authRedirect(logger, w, r, p)
				} else {
					logger.WithField("error", err).Warn("Invalid cookie")
					http.Error(w, "Not authorized", 401)
				}
				return
			}

			// Valid request
			logger.Debug("Allowing valid request", r.Body)
			logger.Debug("Allowing valid request header", r.Header)
			w.Header().Set("Authorization", fmt.Sprintf("Bearer %s", token))
			w.Header().Set("X-Forwarded-User", "pasta")
			w.WriteHeader(200)
		}
	}
}

// AuthCallbackHandler Handles auth callback request
func (s *Server) AuthCallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "AuthCallback", "default", "Handling callback")

		// Check state
		state := r.URL.Query().Get("state")
		if err := ValidateState(state); err != nil {
			logger.WithFields(logrus.Fields{
				"error": err,
			}).Warn("Error validating state")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Check for CSRF cookie
		c, err := FindCSRFCookie(r, state)
		if err != nil {
			logger.Info("Missing csrf cookie")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Validate CSRF cookie against state
		valid, providerName, redirect, err := ValidateCSRFCookie(c, state)
		if !valid {
			logger.WithFields(logrus.Fields{
				"error":       err,
				"csrf_cookie": c,
			}).Warn("Error validating csrf cookie")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Get provider
		p, err := config.GetConfiguredProvider(providerName)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"error":       err,
				"csrf_cookie": c,
				"provider":    providerName,
			}).Warn("Invalid provider in csrf cookie")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Clear CSRF cookie
		http.SetCookie(w, ClearCSRFCookie(r, c))

		// Exchange code for token
		auth0Token, err := p.ExchangeCode(redirectUri(r), r.URL.Query().Get("code"))
		if err != nil {
			logger.WithField("error", err).Error("Code exchange failed with provider")
			http.Error(w, "Service unavailable", 503)
			return
		}
		token, err := s.ExchangeAuth0TokenWithCoreSignedJwt("cmawzxvvs0000kfpjgibdhh96", "cmax00u1m000z01kl591lm26x", auth0Token)
		if err != nil {
			logger.WithField("error", err).Error("Code exchange failed with core")
			http.Error(w, "Service unavailable", 503)
			return
		}
		fmt.Println("TOOOOOOOOOKEN")
		fmt.Println(token)
		// Generate cookie
		http.SetCookie(w, MakeCookie(r, token))
		logger.WithFields(logrus.Fields{
			"provider": providerName,
			"redirect": redirect,
		}).Info("Successfully generated auth cookie, redirecting user.")

		// Redirect
		http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
	}
}

type CoreJwtResponse struct {
	Jwt string `json:"jwt"`
}

func (s *Server) ExchangeAuth0TokenWithCoreSignedJwt(organizationId, deploymentId, token string) (string, error) {
	fmt.Println("TTTTTTTT")
	fmt.Println(token)
	url := fmt.Sprintf("http://host.docker.internal:8888/private/v1alpha1/authz/organizations/%s/deployments/%s/airflow-jwt", organizationId, deploymentId)

	// Create a new HTTP request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		log.Fatal("AAAAA1")
	}

	// Add headers to the request
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("X-Astro-Client-Identifier", "auth-proxy")

	// Create an HTTP client and send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		log.Fatal("AAAAA2")

	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		log.Fatal("AAAAA3")
	}

	// Print the response status and body
	fmt.Println("Response Status:", resp.Status)
	fmt.Println("Response Body:", string(body))
	var coreJwtReponse CoreJwtResponse
	err = json.Unmarshal(body, &coreJwtReponse)
	if err != nil {
		fmt.Println("Error parsing core jwt response:", err)
		log.Fatal("AAAAA5")
	}
	return coreJwtReponse.Jwt, nil
}

// LogoutHandler logs a user out
func (s *Server) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Clear cookie
		http.SetCookie(w, ClearCookie(r))

		logger := s.logger(r, "Logout", "default", "Handling logout")
		logger.Info("Logged out user")

		if config.LogoutRedirect != "" {
			http.Redirect(w, r, config.LogoutRedirect, http.StatusTemporaryRedirect)
		} else {
			http.Error(w, "You have been logged out", 401)
		}
	}
}

func (s *Server) authRedirect(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, p provider.Provider) {
	// Error indicates no cookie, generate nonce
	err, nonce := Nonce()
	if err != nil {
		logger.WithField("error", err).Error("Error generating nonce")
		http.Error(w, "Service unavailable", 503)
		return
	}

	// Set the CSRF cookie
	csrf := MakeCSRFCookie(r, nonce)
	http.SetCookie(w, csrf)

	if !config.InsecureCookie && r.Header.Get("X-Forwarded-Proto") != "https" {
		logger.Warn("You are using \"secure\" cookies for a request that was not " +
			"received via https. You should either redirect to https or pass the " +
			"\"insecure-cookie\" config option to permit cookies via http.")
	}

	// Forward them on
	loginURL := p.GetLoginURL(redirectUri(r), MakeState(r, p, nonce))
	http.Redirect(w, r, loginURL, http.StatusTemporaryRedirect)

	logger.WithFields(logrus.Fields{
		"csrf_cookie": csrf,
		"login_url":   loginURL,
	}).Debug("Set CSRF cookie and redirected to provider login url")
}

func (s *Server) logger(r *http.Request, handler, rule, msg string) *logrus.Entry {
	// Create logger
	logger := log.WithFields(logrus.Fields{
		"handler":   handler,
		"rule":      rule,
		"method":    r.Header.Get("X-Forwarded-Method"),
		"proto":     r.Header.Get("X-Forwarded-Proto"),
		"host":      r.Header.Get("X-Forwarded-Host"),
		"uri":       r.Header.Get("X-Forwarded-Uri"),
		"source_ip": r.Header.Get("X-Forwarded-For"),
	})

	// Log request
	logger.WithFields(logrus.Fields{
		"cookies": r.Cookies(),
	}).Debug(msg)

	return logger
}
