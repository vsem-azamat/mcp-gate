package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"github.com/vsem-azamat/mcp-gate/internal/config"
)

// RevokeOptions configure Revoke.
type RevokeOptions struct {
	Grant *Grant
	// Config is the server's oauth block: its authServerMetadataURL, if set, is where the
	// metadata is read, and its client secret authenticates a configured client.
	Config config.OAuth
	// HTTPClient makes the requests; see NewHTTPClient.
	HTTPClient *http.Client
}

// Revoke asks the grant's authorization server to revoke its refresh token and its access
// token (RFC 7009), when the server's metadata names a revocation endpoint. It reports whether
// the server has one; an error means the metadata could not be read or a token could not be
// revoked. Errors never carry a token.
func Revoke(ctx context.Context, o RevokeOptions) (bool, error) {
	g := o.Grant
	dc := discoveryClient(o.HTTPClient)
	var asm *oauthex.AuthServerMeta
	var err error
	if mu := o.Config.AuthServerMetadataURL; mu != "" {
		issuer, ierr := issuerOf(mu)
		switch {
		case ierr != nil:
			return false, ierr
		case !sameIssuer(issuer, g.Issuer):
			return false, errors.New("authServerMetadataURL names another issuer than the grant's")
		}
		asm, err = oauthex.GetAuthServerMeta(ctx, mu, issuer, dc)
	} else {
		asm, err = auth.GetAuthServerMetadata(ctx, g.Issuer, dc)
	}
	switch {
	case err != nil:
		return false, fmt.Errorf("authorization server metadata: %w", err)
	case asm == nil:
		return false, errors.New("no authorization server metadata found for the grant's issuer")
	case asm.RevocationEndpoint == "":
		return false, nil
	case !config.SecureURL(asm.RevocationEndpoint):
		return true, errors.New("the revocation endpoint is neither https nor loopback")
	}
	cl := client{id: g.ClientID, secret: g.ClientSecret, style: g.AuthStyle}
	if !g.Registered {
		cl.secret = o.Config.ClientSecret
	}
	// The refresh token first: revoking it ends the grant, and RFC 7009 lets the server revoke
	// the access tokens issued with it too.
	var errs []error
	for _, t := range []struct{ token, hint string }{{g.RefreshToken, "refresh_token"}, {g.AccessToken, "access_token"}} {
		if t.token == "" {
			continue
		}
		err := revokeToken(ctx, o.HTTPClient, asm.RevocationEndpoint, cl, t.token, t.hint)
		var unsupported errUnsupportedTokenType
		if t.hint == "access_token" && g.RefreshToken != "" && errors.As(err, &unsupported) {
			// Revoking access tokens is optional (RFC 7009, section 2.2.1); the grant ended with
			// its refresh token.
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("revoking the %s: %w", t.hint, err))
		}
	}
	return true, errors.Join(errs...)
}

// revokeToken posts one revocation request. The server answers 200 also for a token it does
// not know (RFC 7009, section 2.2).
func revokeToken(ctx context.Context, hc *http.Client, endpoint string, cl client, token, hint string) error {
	ctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	req, err := clientRequest(ctx, endpoint, cl, url.Values{"token": {token}, "token_type_hint": {hint}})
	if err != nil {
		return errors.New("the revocation endpoint is not a valid URL")
	}
	resp, err := hc.Do(req)
	if err != nil {
		return sanitizeTransport(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	msg := "the revocation endpoint answered " + strconv.Itoa(resp.StatusCode)
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		msg += " " + errorCode(e.Error)
	}
	// The description is the server's text, which could echo the token.
	if resp.StatusCode == http.StatusBadRequest && e.Error == "unsupported_token_type" {
		return errUnsupportedTokenType{msg}
	}
	return errors.New(msg)
}

// errUnsupportedTokenType is the answer of a server that does not revoke tokens of that type.
type errUnsupportedTokenType struct{ msg string }

func (e errUnsupportedTokenType) Error() string { return e.msg }
