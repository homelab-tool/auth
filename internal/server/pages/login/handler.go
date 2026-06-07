package login

import "github.com/labstack/echo/v5"

func PageHandler(c *echo.Context) error {
	return Page().Render(c.Request().Context(), c.Response())
}
