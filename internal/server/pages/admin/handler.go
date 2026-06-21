package admin

import "github.com/labstack/echo/v5"

func PageHandler(c *echo.Context) error {
	return DashboardPage().Render(c.Request().Context(), c.Response())
}
