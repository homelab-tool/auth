package profile

import (
	"github.com/homelab-tool/auth/internal/auth"
	"github.com/homelab-tool/auth/internal/server/pages/layout"
	"github.com/homelab-tool/auth/internal/service"
	"github.com/labstack/echo/v5"
	"github.com/rs/zerolog/log"
)

type ProfileData struct {
	User      *service.User
	HasTOTP   bool
	HasWebAuthn bool
}

func PageHandler(jwt *auth.JWTService, users *service.UserService, svc service.SecondFactorService) echo.HandlerFunc {
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

		methods, err := svc.Methods(userID)
		if err != nil {
			log.Err(err).Int64("userID", userID).Msg("failed to query 2fa methods")
			return c.String(500, "server error")
		}

		var hasTOTP, hasWebAuthn bool
		for _, m := range methods {
			switch m {
			case "totp":
				hasTOTP = true
			case "webauthn":
				hasWebAuthn = true
			}
		}

		return Page(&ProfileData{
			User:        user,
			HasTOTP:     hasTOTP,
			HasWebAuthn: hasWebAuthn,
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

		var hasTOTP, hasWebAuthn bool
		for _, m := range methods {
			switch m {
			case "totp":
				hasTOTP = true
			case "webauthn":
				hasWebAuthn = true
			}
		}

		return TwoFASection(&ProfileData{
			HasTOTP:     hasTOTP,
			HasWebAuthn: hasWebAuthn,
		}).Render(c.Request().Context(), c.Response())
	}
}
