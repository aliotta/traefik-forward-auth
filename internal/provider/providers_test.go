package provider

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// Utilities

type OAuthServer struct {
	t    *testing.T
	url  *url.URL
	body map[string]string // method -> body
}

func NewOAuthServer(t *testing.T, body map[string]string) (*httptest.Server, *url.URL) {
	handler := &OAuthServer{t: t, body: body}
	server := httptest.NewServer(handler)
	handler.url, _ = url.Parse(server.URL)
	return server, handler.url
}

func (s *OAuthServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)

	if r.Method == "POST" && r.URL.Path == "/token" {
		if s.body["token"] != string(body) {
			s.t.Fatal("Unexpected request body, expected", s.body["token"], "got", string(body))
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"123456789"}`)
	} else if r.Method == "GET" && r.URL.Path == "/userinfo" {
		fmt.Fprint(w, `{
			"id":"1",
			"email":"example@example.com",
			"verified_email":true,
			"hd":"example.com"
		}`)
	} else {
		s.t.Fatal("Unrecognised request: ", r.Method, r.URL, string(body))
	}
}
