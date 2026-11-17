package samlsp

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

// statusLogoutForm returns the form of a LogoutResponse from the IdP, signed
// by it, with the given status. It answers id-sp-logout-request, the ID
// trackLogoutRequest tracks.
func statusLogoutForm(t *testing.T, lt *logoutTest, status saml.Status) url.Values {
	t.Helper()
	lr := lt.logoutResponse(saml.StatusSuccess)
	lr.Status = status
	return url.Values{"SAMLResponse": {lt.signedIDPMessage(t, lr.Element())}}
}

// assertLogoutEnded checks that resp finishes the logout: it redirects to
// "/", expires the session cookie, and clears the logout tracking cookie.
func assertLogoutEnded(t *testing.T, lt *logoutTest, resp *httptest.ResponseRecorder, tracking *http.Cookie) {
	t.Helper()
	assert.Check(t, is.Equal(http.StatusFound, resp.Code))
	assert.Check(t, is.Equal("/", resp.Header().Get("Location")))
	assertSessionDeleted(t, lt, resp)
	cleared := logoutTrackingCookie(t, resp)
	assert.Check(t, is.Equal(tracking.Name, cleared.Name))
	assert.Check(t, is.Equal("", cleared.Value))
}

// TestServeSLOResponseResponder: the IdP ended its session but reports
// Responder, so the logout still ends here instead of leaving the user on a
// 403 page with the tracking cookie set.
func TestServeSLOResponseResponder(t *testing.T) {
	lt := newLogoutTest(t, saml.HTTPRedirectBinding)
	var gotErr error
	lt.m.OnError = func(w http.ResponseWriter, _ *http.Request, err error) {
		gotErr = err
		http.Error(w, "forbidden", http.StatusForbidden)
	}

	tracking := lt.trackLogoutRequest(t, "id-sp-logout-request")
	resp := lt.postToSLO(statusLogoutForm(t, lt, saml.Status{
		StatusCode: saml.StatusCode{Value: saml.StatusResponder},
	}), lt.sessionCookie(t, "x"), tracking)

	assertLogoutEnded(t, lt, resp, tracking)
	// The failure is reported for logging, and names the status.
	assert.Check(t, is.ErrorIs(gotErr, errLogoutNotSuccess))
	assert.Check(t, is.ErrorIs(gotErr, saml.ErrBadStatus{Status: saml.StatusResponder}))

	// The request is no longer tracked: the same response cannot be delivered
	// again, and the user is not stuck retrying.
	replay := lt.postToSLO(statusLogoutForm(t, lt, saml.Status{
		StatusCode: saml.StatusCode{Value: saml.StatusResponder},
	}))
	assert.Check(t, is.Equal(http.StatusForbidden, replay.Code))
}

// TestServeSLOResponsePartialLogout: the IdP logged the user out of this SP
// and says so with Success, but reports that other SPs may keep their
// sessions (saml-core-2.0-os §3.7.3.2). That is not a failure here: the
// logout ends, and nothing is passed to OnError.
func TestServeSLOResponsePartialLogout(t *testing.T) {
	lt := newLogoutTest(t, saml.HTTPRedirectBinding)
	var errs []error
	lt.m.OnError = func(_ http.ResponseWriter, _ *http.Request, err error) { errs = append(errs, err) }

	tracking := lt.trackLogoutRequest(t, "id-sp-logout-request")
	resp := lt.postToSLO(statusLogoutForm(t, lt, saml.Status{
		StatusCode: saml.StatusCode{
			Value:      saml.StatusSuccess,
			StatusCode: &saml.StatusCode{Value: saml.StatusPartialLogout},
		},
	}), lt.sessionCookie(t, "x"), tracking)

	assertLogoutEnded(t, lt, resp, tracking)
	assert.Check(t, is.Len(errs, 0))
}

// TestServeSLOResponseSuccess is the positive control for the two tests
// above: a Success response takes the same path, ending the logout with
// nothing passed to OnError.
func TestServeSLOResponseSuccess(t *testing.T) {
	lt := newLogoutTest(t, saml.HTTPRedirectBinding)
	var errs []error
	lt.m.OnError = func(_ http.ResponseWriter, _ *http.Request, err error) { errs = append(errs, err) }

	tracking := lt.trackLogoutRequest(t, "id-sp-logout-request")
	resp := lt.postToSLO(statusLogoutForm(t, lt, saml.Status{
		StatusCode: saml.StatusCode{Value: saml.StatusSuccess},
	}), lt.sessionCookie(t, "x"), tracking)

	assertLogoutEnded(t, lt, resp, tracking)
	assert.Check(t, is.Len(errs, 0))
}

// TestServeSLOResponseRefusedKeepsTracking is the counterpart of the tests
// above: a response that does not verify, or that answers no pending
// request, is not an answer to this logout at all, so it is refused and the
// request stays tracked for the real one. Clearing the tracking on a
// response anyone can post would leave the user unable to finish the logout.
func TestServeSLOResponseRefusedKeepsTracking(t *testing.T) {
	for _, tc := range []struct {
		name string
		form func(t *testing.T, lt *logoutTest) url.Values
	}{
		{
			name: "unsigned",
			form: func(t *testing.T, lt *logoutTest) url.Values {
				doc := etree.NewDocument()
				doc.SetRoot(lt.logoutResponse(saml.StatusSuccess).Element())
				buf, err := doc.WriteToBytes()
				assert.NilError(t, err)
				return url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(buf)}}
			},
		},
		{
			name: "answers another request",
			form: func(t *testing.T, lt *logoutTest) url.Values {
				lr := lt.logoutResponse(saml.StatusSuccess)
				lr.InResponseTo = "id-other-request"
				return url.Values{"SAMLResponse": {lt.signedIDPMessage(t, lr.Element())}}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lt := newLogoutTest(t, saml.HTTPRedirectBinding)
			lt.m.OnError = func(w http.ResponseWriter, _ *http.Request, _ error) {
				http.Error(w, "forbidden", http.StatusForbidden)
			}
			tracking := lt.trackLogoutRequest(t, "id-sp-logout-request")

			resp := lt.postToSLO(tc.form(t, lt), lt.sessionCookie(t, "x"), tracking)
			assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
			// No cookie is cleared, and the session is kept: the logout is
			// still in progress.
			assert.Check(t, is.Len(resp.Result().Cookies(), 0))

			// The real answer still ends it.
			lt.m.OnError = func(_ http.ResponseWriter, _ *http.Request, _ error) {}
			good := lt.postToSLO(statusLogoutForm(t, lt, saml.Status{
				StatusCode: saml.StatusCode{Value: saml.StatusSuccess},
			}), lt.sessionCookie(t, "x"), tracking)
			assertLogoutEnded(t, lt, good, tracking)
		})
	}
}
