package internal

import (
	"database/sql"
	"io/fs"
	"log/slog"

	bytemareopaque "github.com/bytemare/opaque"
	"github.com/homelab-tool/auth/internal/auth"
	"github.com/homelab-tool/auth/internal/server/api"
	"github.com/homelab-tool/auth/internal/server/api/caddy"
	"github.com/homelab-tool/auth/internal/server/api/secondfactor"
	authmw "github.com/homelab-tool/auth/internal/server/middleware"
	"github.com/homelab-tool/auth/internal/server/pages/admin/groups"
	"github.com/homelab-tool/auth/internal/server/pages/admin/siteconfig"
	"github.com/homelab-tool/auth/internal/server/pages/layout"
	"github.com/homelab-tool/auth/internal/server/pages/login"
	"github.com/homelab-tool/auth/internal/server/pages/profile"
	"github.com/homelab-tool/auth/internal/server/pages/register"
	"github.com/homelab-tool/auth/internal/server/pages/static"
	"github.com/homelab-tool/auth/internal/service"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type App struct {
	Router *echo.Echo
	DB     *sql.DB
}

type Services struct {
	JWT           *auth.JWTService
	WebAuthn      *auth.WebAuthnService
	Users         *service.UserService
	Opaque        *service.OpaqueService
	Credentials   *service.CredentialService
	SecondFactor  service.SecondFactorService
	TOTP          *service.TOTPService
	SiteConfigs   *service.SiteConfigService
	Groups        *service.GroupService
	OpaqueServer  *bytemareopaque.Server
}

func InitServices(db *sql.DB, secondFactorSvc service.SecondFactorService) (*Services, error) {
	jwtService, err := auth.NewJWTService(db)
	if err != nil {
		return nil, err
	}

	webAuthnSvc, err := auth.NewWebAuthnService()
	if err != nil {
		return nil, err
	}

	if secondFactorSvc == nil {
		secondFactorSvc = service.NewDefaultSecondFactorService(db)
	}

	opaqueServer, err := auth.CreateOpaqueServer(db)
	if err != nil {
		return nil, err
	}

	return &Services{
		JWT:          jwtService,
		WebAuthn:     webAuthnSvc,
		Users:        service.NewUserService(db),
		Opaque:       service.NewOpaqueService(db),
		Credentials:  service.NewCredentialService(db),
		SecondFactor: secondFactorSvc,
		TOTP:         service.NewTOTPService(db),
		SiteConfigs:  service.NewSiteConfigService(db),
		Groups:       service.NewGroupService(db),
		OpaqueServer: opaqueServer,
	}, nil
}

func CreateApp() (*App, error) {
	var e = echo.New()
	var handler = zerolog.NewSlogHandler(log.Logger)
	e.Logger = slog.New(handler)

	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogURI:       true,
		LogStatus:    true,
		LogMethod:    true,
		LogLatency:   true,
		LogRequestID: true,
		LogValuesFunc: func(c *echo.Context, v middleware.RequestLoggerValues) error {
			log.Info().
				Str("method", v.Method).
				Str("uri", v.URI).
				Int("status", v.Status).
				Dur("latency", v.Latency).
				Str("request_id", v.RequestID).
				Msg("request")
			return nil
		},
	}))

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept},
	}))

	e.GET("/health", func(c *echo.Context) error {
		return c.String(200, "ok")
	})

	var db, err = InitializeDb()
	if err != nil {
		return nil, err
	}

	svcs, err := InitServices(db, nil)
	if err != nil {
		return nil, err
	}

	if err := BootstrapAdminUser(db, svcs.Opaque, svcs.OpaqueServer, svcs.Groups); err != nil {
		return nil, err
	}

	sfHandler, err := secondfactor.NewHandler(
		svcs.Users, svcs.Credentials, svcs.JWT, svcs.WebAuthn,
		svcs.SecondFactor, svcs.TOTP,
	)
	if err != nil {
		return nil, err
	}

	api := api.Api{
		DB:              db,
		JWT:             svcs.JWT,
		WebAuthn:        svcs.WebAuthn,
		Users:           svcs.Users,
		Opaque:          svcs.Opaque,
		Credentials:     svcs.Credentials,
		SecondFactorSvc: svcs.SecondFactor,
		TOTP:            svcs.TOTP,
	}

	if err = api.SetupRoutes(e.Group("/api"), svcs.OpaqueServer, sfHandler); err != nil {
		return nil, err
	}

	caddyHandler := caddy.NewHandler(svcs.JWT, svcs.SiteConfigs, svcs.Groups)
	caddyHandler.SetupRoutes(e.Group("/caddy"))

	subFS, err := fs.Sub(static.Files, "dist")
	if err != nil {
		return nil, err
	}
	e.StaticFS("/static", subFS)

	e.GET("/login", login.PageHandler)
	e.GET("/register", register.PageHandler)
	e.GET("/profile", profile.PageHandler(svcs.JWT, svcs.Users, svcs.SecondFactor, svcs.Credentials))
	e.DELETE("/profile/2fa/:method", profile.Disable2FAHandler(svcs.JWT, svcs.SecondFactor))

	enrollHandler := register.NewEnrollmentHandler(svcs.JWT, svcs.Users, svcs.TOTP, svcs.SecondFactor, svcs.Credentials)
	e.GET("/register/2fa", enrollHandler.PageHandler)
	e.GET("/register/2fa/totp", enrollHandler.HandleTOTPSetupPage)
	e.GET("/register/2fa/webauthn", enrollHandler.HandleWebAuthnSetupPage)
	e.POST("/register/2fa/totp/generate", enrollHandler.HandleTOTPGenerate)
	e.POST("/register/2fa/totp/verify", enrollHandler.HandleTOTPVerify)
	e.POST("/auth/set-cookie", layout.SetCookieHandler(svcs.JWT))
	e.POST("/auth/logout", layout.LogoutHandler)

	twoFAHandler, err := login.NewTwoFAHandler(sfHandler, svcs.JWT)
	if err != nil {
		return nil, err
	}
	e.GET("/login/2fa/init", twoFAHandler.Init2FA)
	e.POST("/login/2fa/totp", twoFAHandler.VerifyTOTP)

	profileGroup := e.Group("/profile")
	profileGroup.GET("/password", profile.PasswordPageHandler(svcs.JWT, svcs.Users, svcs.Opaque))
	profileGroup.GET("/passkey/add", profile.AddPasskeyPageHandler(svcs.JWT, svcs.Credentials))
	profileGroup.DELETE("/passkey/:id", profile.DeletePasskeyHandler(svcs.JWT, svcs.Credentials))

	adminGroup := e.Group("/admin", authmw.AdminMiddleware(svcs.JWT, svcs.Groups))

	scHandler := siteconfig.NewHandler(svcs.SiteConfigs, svcs.Groups, svcs.Users)
	adminGroup.GET("/site-configs", scHandler.PageHandler)
	adminGroup.POST("/site-configs", scHandler.CreateHandler)
	adminGroup.DELETE("/site-configs/:id", scHandler.DeleteHandler)
	adminGroup.GET("/site-configs/:id", scHandler.ManageHandler)
	adminGroup.POST("/site-configs/:id/groups", scHandler.GrantGroupHandler)
	adminGroup.DELETE("/site-configs/:id/groups/:groupID", scHandler.RevokeGroupHandler)
	adminGroup.POST("/site-configs/:id/users", scHandler.GrantUserHandler)
	adminGroup.DELETE("/site-configs/:id/users/:userID", scHandler.RevokeUserHandler)

	grpHandler := groups.NewHandler(svcs.Groups, svcs.Users)
	adminGroup.GET("/groups", grpHandler.PageHandler)
	adminGroup.GET("/groups/new", grpHandler.GroupFormHandler)
	adminGroup.POST("/groups", grpHandler.CreateHandler)
	adminGroup.DELETE("/groups/:id", grpHandler.DeleteHandler)
	adminGroup.GET("/groups/:id", grpHandler.ManageHandler)
	adminGroup.POST("/groups/:id/members", grpHandler.AddMemberHandler)
	adminGroup.DELETE("/groups/:id/members/:userID", grpHandler.RemoveMemberHandler)

	app := &App{
		Router: e,
		DB:     db,
	}

	return app, nil
}
