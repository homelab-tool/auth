package register

import (
	"github.com/homelab-tool/auth/internal/auth"
	"github.com/homelab-tool/auth/internal/server/pages/layout"
	"github.com/homelab-tool/auth/internal/service"
	"github.com/labstack/echo/v5"
	"github.com/rs/zerolog/log"
)

func PageHandler(c *echo.Context) error {
	return Page().Render(c.Request().Context(), c.Response())
}

type EnrollmentHandler struct {
	jwt          *auth.JWTService
	users        *service.UserService
	totp         *service.TOTPService
	secondFactor service.SecondFactorService
	credentials  *service.CredentialService
}

func NewEnrollmentHandler(jwt *auth.JWTService, users *service.UserService, totp *service.TOTPService, secondFactor service.SecondFactorService, credentials *service.CredentialService) *EnrollmentHandler {
	return &EnrollmentHandler{jwt: jwt, users: users, totp: totp, secondFactor: secondFactor, credentials: credentials}
}

func (h *EnrollmentHandler) PageHandler(c *echo.Context) error {
	_, err := layout.UserIDFromCookie(c, h.jwt)
	if err != nil {
		return c.Redirect(302, "/login")
	}
	return EnrollmentPage().Render(c.Request().Context(), c.Response())
}

func (h *EnrollmentHandler) HandleTOTPGenerate(c *echo.Context) error {
	userID, err := layout.UserIDFromCookie(c, h.jwt)
	if err != nil {
		return c.Redirect(302, "/login")
	}

	displayName, err := h.users.GetDisplayName(c.Request().Context(), userID)
	if err != nil {
		log.Err(err).Int64("userID", userID).Msg("failed to query display name for totp")
		return c.String(500, "server error")
	}

	result, err := h.totp.GenerateSecret(c.Request().Context(), userID, displayName, "auth")
	if err != nil {
		log.Err(err).Int64("userID", userID).Msg("failed to generate totp secret")
		return c.String(500, "server error")
	}

	return TOTPSetupForm(result.Secret, result.URI, "/register/2fa/totp/verify", "").Render(c.Request().Context(), c.Response())
}

func (h *EnrollmentHandler) HandleTOTPVerify(c *echo.Context) error {
	userID, err := layout.UserIDFromCookie(c, h.jwt)
	if err != nil {
		return c.Redirect(302, "/login")
	}

	code := c.Request().FormValue("code")
	if code == "" {
		return TOTPError("Code is required.").Render(c.Request().Context(), c.Response())
	}

	ok, err := h.totp.VerifyAndEnable(c.Request().Context(), userID, code)
	if err != nil {
		log.Err(err).Int64("userID", userID).Msg("failed to verify totp")
		return c.String(500, "server error")
	}
	if !ok {
		return TOTPError("Invalid code. Please try again.").Render(c.Request().Context(), c.Response())
	}

	redirect := c.Request().FormValue("_redirect")
	if redirect != "" {
		c.Response().Header().Set("HX-Redirect", redirect)
		return c.NoContent(200)
	}

	return TOTPSuccess().Render(c.Request().Context(), c.Response())
}

func (h *EnrollmentHandler) HandleTOTPSetupPage(c *echo.Context) error {
	userID, err := layout.UserIDFromCookie(c, h.jwt)
	if err != nil {
		return c.Redirect(302, "/login")
	}

	methods, err := h.secondFactor.Methods(userID)
	if err != nil {
		return c.String(500, "server error")
	}
	for _, m := range methods {
		if m == "totp" {
			return c.Redirect(302, "/profile")
		}
	}

	displayName, err := h.users.GetDisplayName(c.Request().Context(), userID)
	if err != nil {
		log.Err(err).Int64("userID", userID).Msg("failed to query display name for totp")
		return c.String(500, "server error")
	}

	result, err := h.totp.GenerateSecret(c.Request().Context(), userID, displayName, "auth")
	if err != nil {
		log.Err(err).Int64("userID", userID).Msg("failed to generate totp secret")
		return c.String(500, "server error")
	}

	return TOTPSetupPage(result.Secret, result.URI).Render(c.Request().Context(), c.Response())
}

func (h *EnrollmentHandler) HandleWebAuthnSetupPage(c *echo.Context) error {
	userID, err := layout.UserIDFromCookie(c, h.jwt)
	if err != nil {
		return c.Redirect(302, "/login")
	}

	creds, err := h.credentials.ListBy2FAPurpose(c.Request().Context(), userID)
	if err != nil {
		return c.String(500, "server error")
	}
	if len(creds) > 0 {
		return c.Redirect(302, "/profile")
	}

	return WebAuthnSetupPage().Render(c.Request().Context(), c.Response())
}
