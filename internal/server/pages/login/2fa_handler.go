package login

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/homelab-tool/auth/internal/auth"
	"github.com/homelab-tool/auth/internal/server/api/cacheutil"
	"github.com/homelab-tool/auth/internal/server/api/secondfactor"
	"github.com/labstack/echo/v5"
	"github.com/rs/zerolog/log"
)

const maxTOTPAttempts = 5
const totpAttemptWindow = 5 * time.Minute

type TwoFAHandler struct {
	secondFactor *secondfactor.Handler
	jwt          *auth.JWTService
	failures     *ristretto.Cache[string, int]
}

func NewTwoFAHandler(sf *secondfactor.Handler, jwt *auth.JWTService) (*TwoFAHandler, error) {
	failures, err := cacheutil.NewCache[int]()
	if err != nil {
		return nil, fmt.Errorf("failed to create totp failure cache: %w", err)
	}

	return &TwoFAHandler{
		secondFactor: sf,
		jwt:          jwt,
		failures:     failures,
	}, nil
}

func (h *TwoFAHandler) Init2FA(c *echo.Context) error {
	sessionID := c.QueryParam("session_id")
	if sessionID == "" {
		return c.String(400, "missing session_id")
	}

	methods, err := h.secondFactor.GetPendingMethods(sessionID)
	if err != nil {
		return c.String(400, "invalid session")
	}

	return Login2FAChallenge(sessionID, methods).Render(c.Request().Context(), c.Response())
}

func (h *TwoFAHandler) VerifyTOTP(c *echo.Context) error {
	sessionID := c.Request().FormValue("sessionId")
	code := c.Request().FormValue("code")
	if sessionID == "" || code == "" {
		return LoginTOTPError(sessionID, "Code is required.").Render(c.Request().Context(), c.Response())
	}

	if count, found := h.failures.Get(sessionID); found && count >= maxTOTPAttempts {
		return LoginTOTPError(sessionID, "Too many attempts. Please start over.").Render(c.Request().Context(), c.Response())
	}

	token, err := h.secondFactor.ValidatePendingTOTP(c.Request().Context(), sessionID, code)
	if err != nil {
		count, _ := h.failures.Get(sessionID)
		h.failures.SetWithTTL(sessionID, count+1, 1, totpAttemptWindow)
		h.failures.Wait()
		return LoginTOTPError(sessionID, "Invalid code. Please try again.").Render(c.Request().Context(), c.Response())
	}

	h.failures.Del(sessionID)

	claims, err := h.jwt.ValidateToken(token)
	if err != nil {
		log.Err(err).Msg("failed to validate token in totp verification")
		return c.String(500, "server error")
	}

	c.SetCookie(&http.Cookie{
		Name:     "token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Expires:  claims.ExpiresAt.Time,
	})

	c.Response().Header().Set("HX-Redirect", "/profile")
	return c.NoContent(200)
}

func hasMethod(methods []string, method string) bool {
	for _, m := range methods {
		if m == method {
			return true
		}
	}
	return false
}
