package profile

import (
	"strconv"

	"github.com/homelab-tool/auth/internal/auth"
	"github.com/homelab-tool/auth/internal/server/pages/layout"
	"github.com/homelab-tool/auth/internal/service"
	"github.com/labstack/echo/v5"
	"github.com/rs/zerolog/log"
)

type ProfileData struct {
	User        *service.User
	HasPassword bool
	HasTOTP     bool
	Has2FA      []string
	Passkeys    []service.CredentialInfo
}

func PageHandler(jwt *auth.JWTService, users *service.UserService, svc service.SecondFactorService, credentials *service.CredentialService) echo.HandlerFunc {
	return func(c *echo.Context) error {
		userID, err := layout.UserIDFromCookie(c, jwt)
		if err != nil {
			return c.Redirect(302, "/login")
		}

		user, err := users.GetUser(c.Request().Context(), userID)
		if err != nil {
			log.Err(err).Int64("userID", userID).Msg("failed to load user")
			return c.String(500, "server error")
		}

		hasPassword, err := users.HasPassword(c.Request().Context(), userID)
		if err != nil {
			log.Err(err).Int64("userID", userID).Msg("failed to check password")
			return c.String(500, "server error")
		}

		methods, err := svc.Methods(userID)
		if err != nil {
			log.Err(err).Int64("userID", userID).Msg("failed to query 2fa methods")
			return c.String(500, "server error")
		}

		var hasTOTP bool
		for _, m := range methods {
			if m == "totp" {
				hasTOTP = true
			}
		}

		passkeys, err := credentials.List(c.Request().Context(), userID)
		if err != nil {
			log.Err(err).Int64("userID", userID).Msg("failed to list credentials")
			return c.String(500, "server error")
		}

		return Page(&ProfileData{
			User:        user,
			HasPassword: hasPassword,
			HasTOTP:     hasTOTP,
			Has2FA:      methods,
			Passkeys:    passkeys,
		}).Render(c.Request().Context(), c.Response())
	}
}

func Disable2FAHandler(jwt *auth.JWTService, svc service.SecondFactorService) echo.HandlerFunc {
	return func(c *echo.Context) error {
		userID, err := layout.UserIDFromCookie(c, jwt)
		if err != nil {
			return c.Redirect(302, "/login")
		}

		method := c.Param("method")
		if method != "totp" && method != "webauthn" {
			return c.String(400, "invalid method")
		}

		if err := svc.Disable(userID, method); err != nil {
			log.Err(err).Int64("userID", userID).Str("method", method).Msg("failed to disable second factor")
			return c.String(500, "server error")
		}

		methods, err := svc.Methods(userID)
		if err != nil {
			log.Err(err).Int64("userID", userID).Msg("failed to query 2fa methods")
			return c.String(500, "server error")
		}

		var hasTOTP bool
		for _, m := range methods {
			if m == "totp" {
				hasTOTP = true
			}
		}

		return TwoFASection(&ProfileData{
			HasTOTP: hasTOTP,
			Has2FA:  methods,
		}).Render(c.Request().Context(), c.Response())
	}
}

func PasswordPageHandler(jwt *auth.JWTService, users *service.UserService, opaqueSvc *service.OpaqueService) echo.HandlerFunc {
	return func(c *echo.Context) error {
		userID, err := layout.UserIDFromCookie(c, jwt)
		if err != nil {
			return c.Redirect(302, "/login")
		}

		hasPW, err := opaqueSvc.HasPassword(c.Request().Context(), userID)
		if err != nil {
			log.Err(err).Int64("userID", userID).Msg("failed to check password")
			return c.String(500, "server error")
		}
		if hasPW {
			return c.Redirect(302, "/profile")
		}

		displayName, err := users.GetDisplayName(c.Request().Context(), userID)
		if err != nil {
			displayName = ""
		}

		return PasswordSetupPage(displayName).Render(c.Request().Context(), c.Response())
	}
}

func AddPasskeyPageHandler(jwt *auth.JWTService, credentials *service.CredentialService) echo.HandlerFunc {
	return func(c *echo.Context) error {
		userID, err := layout.UserIDFromCookie(c, jwt)
		if err != nil {
			return c.Redirect(302, "/login")
		}

		count, err := credentials.Count(c.Request().Context(), userID)
		if err != nil {
			log.Err(err).Int64("userID", userID).Msg("failed to count credentials")
			return c.String(500, "server error")
		}
		if count >= 5 {
			return c.Redirect(302, "/profile")
		}

		return AddPasskeyPage().Render(c.Request().Context(), c.Response())
	}
}

func DeletePasskeyHandler(jwt *auth.JWTService, credentials *service.CredentialService) echo.HandlerFunc {
	return func(c *echo.Context) error {
		userID, err := layout.UserIDFromCookie(c, jwt)
		if err != nil {
			return c.Redirect(302, "/login")
		}

		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			return c.String(400, "invalid id")
		}

		if err := credentials.Delete(c.Request().Context(), id); err != nil {
			log.Err(err).Int64("id", id).Int64("userID", userID).Msg("failed to delete credential")
			return c.String(500, "server error")
		}

		c.Response().Header().Set("HX-Redirect", "/profile")
		return c.NoContent(200)
	}
}
