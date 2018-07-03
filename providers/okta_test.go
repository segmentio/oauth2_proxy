package providers

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func newOktaProvider() *OktaProvider {
	return NewOktaProvider(
		&ProviderData{
			ProviderName: "",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""})
}

func TestOktaProviderDefaults(t *testing.T) {
	p := newOktaProvider()
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Okta", p.Data().ProviderName)
	assert.Equal(t, "", p.Data().ProfileURL.String())
	assert.Equal(t, "openid profile email offline_access", p.Data().Scope)
}

func TestOktaProviderOverrides(t *testing.T) {
	p := newOktaProvider()

	p.SetOktaDomain("example.okta.com")

	assert.NotEqual(t, nil, p)
	assert.Equal(t, "https://example.okta.com/oauth2/v1/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.okta.com/oauth2/v1/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://example.okta.com/oauth2/v1/userinfo",
		p.Data().ValidateURL.String())
}

func TestOktaProviderGetEmailAddress(t *testing.T) {
	p := newOktaProvider()
	body, err := json.Marshal(redeemResponse{
		AccessToken:  "a1234",
		ExpiresIn:    10,
		RefreshToken: "refresh12345",
		IdToken:      "ignored prefix." + base64.URLEncoding.EncodeToString([]byte(`{"email": "michael.bland@gsa.gov", "email_verified":true}`)),
	})
	assert.Equal(t, nil, err)
	var server *httptest.Server
	p.RedeemURL, server = newRedeemServer(body)
	defer server.Close()

	session, err := p.Redeem("http://redirect/", "code1234")
	assert.Equal(t, nil, err)
	assert.NotEqual(t, session, nil)
	assert.Equal(t, "michael.bland@gsa.gov", session.Email)
	assert.Equal(t, "a1234", session.AccessToken)
	assert.Equal(t, "refresh12345", session.RefreshToken)
}

func TestOktaProviderGetEmailAddressInvalidEncoding(t *testing.T) {
	p := newOktaProvider()
	body, err := json.Marshal(redeemResponse{
		AccessToken: "a1234",
		IdToken:     "ignored prefix." + `{"email": "michael.bland@gsa.gov"}`,
	})
	assert.Equal(t, nil, err)
	var server *httptest.Server
	p.RedeemURL, server = newRedeemServer(body)
	defer server.Close()

	session, err := p.Redeem("http://redirect/", "code1234")
	assert.NotEqual(t, nil, err)
	if session != nil {
		t.Errorf("expect nill session %#v", session)
	}
}

func TestOktaProviderGetEmailAddressInvalidJson(t *testing.T) {
	p := newOktaProvider()

	body, err := json.Marshal(redeemResponse{
		AccessToken: "a1234",
		IdToken:     "ignored prefix." + base64.URLEncoding.EncodeToString([]byte(`{"email": michael.bland@gsa.gov}`)),
	})
	assert.Equal(t, nil, err)
	var server *httptest.Server
	p.RedeemURL, server = newRedeemServer(body)
	defer server.Close()

	session, err := p.Redeem("http://redirect/", "code1234")
	assert.NotEqual(t, nil, err)
	if session != nil {
		t.Errorf("expect nill session %#v", session)
	}
}

func TestOktaProviderGetEmailAddressEmailMissing(t *testing.T) {
	p := newOktaProvider()
	body, err := json.Marshal(redeemResponse{
		AccessToken: "a1234",
		IdToken:     "ignored prefix." + base64.URLEncoding.EncodeToString([]byte(`{"not_email": "missing"}`)),
	})
	assert.Equal(t, nil, err)
	var server *httptest.Server
	p.RedeemURL, server = newRedeemServer(body)
	defer server.Close()

	session, err := p.Redeem("http://redirect/", "code1234")
	assert.NotEqual(t, nil, err)
	if session != nil {
		t.Errorf("expect nill session %#v", session)
	}

}
