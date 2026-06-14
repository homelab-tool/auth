package login

import (
	"net/http"
	"strings"

	"github.com/homelab-tool/auth/internal/auth"
	"github.com/homelab-tool/auth/internal/server/api/secondfactor"
	"github.com/labstack/echo/v5"
	"github.com/rs/zerolog/log"
)

type TwoFAHandler struct {
	secondFactor *secondfactor.Handler
	jwt          *auth.JWTService
}

func NewTwoFAHandler(sf *secondfactor.Handler, jwt *auth.JWTService) *TwoFAHandler {
	return &TwoFAHandler{secondFactor: sf, jwt: jwt}
}

func (h *TwoFAHandler) Init2FA(c *echo.Context) error {
	sessionID := c.QueryParam("session_id")
	methodsParam := c.QueryParam("methods")
	if sessionID == "" {
		return c.String(400, "missing session_id")
	}

	var methods []string
	if methodsParam != "" {
		methods = strings.Split(methodsParam, ",")
	}

	return Login2FAChallenge(sessionID, methods).Render(c.Request().Context(), c.Response())
}

func (h *TwoFAHandler) VerifyTOTP(c *echo.Context) error {
	sessionID := c.Request().FormValue("sessionId")
	code := c.Request().FormValue("code")
	if sessionID == "" || code == "" {
		return LoginTOTPError(sessionID, "Code is required.").Render(c.Request().Context(), c.Response())
	}

	token, err := h.secondFactor.ValidatePendingTOTP(c.Request().Context(), sessionID, code)
	if err != nil {
		return LoginTOTPError(sessionID, "Invalid code. Please try again.").Render(c.Request().Context(), c.Response())
	}

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
