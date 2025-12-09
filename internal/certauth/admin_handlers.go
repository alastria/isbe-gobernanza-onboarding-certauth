package certauth

import (
	"github.com/evidenceledger/certauth/internal/errl"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/basicauth"
)

func (s *Server) registerAdminHandlers(adminPassword string) {

	admin := s.httpServer.Group("/admin")

	// Protect the admin area with basic auth
	adminAuth := basicauth.New(basicauth.Config{
		Users: map[string]string{
			"admin": adminPassword,
		},
		Realm: "Admin Area",
	})

	admin.Use(adminAuth)

	admin.Get("/admin", s.AdminDashboard)

	admin.Get("/rp", s.ListRP)
	admin.Post("/rp", s.CreateRP)
	admin.Put("/rp/:id", s.UpdateRP)
	admin.Delete("/rp/:id", s.DeleteRP)

}

// AdminDashboard handles admin dashboard
func (s *Server) AdminDashboard(c *fiber.Ctx) error {
	// TODO: Implement admin dashboard
	return c.SendStatus(fiber.StatusNotImplemented)
}

// ListRP lists all relying parties
func (s *Server) ListRP(c *fiber.Ctx) error {
	rps, err := s.db.ListRelyingParties()
	if err != nil {
		return errl.Errorf("failed to list relying parties: %w", err)
	}

	return c.JSON(rps)
}

// CreateRP creates a new relying party
func (s *Server) CreateRP(c *fiber.Ctx) error {
	// TODO: Implement RP creation
	return c.SendStatus(fiber.StatusNotImplemented)
}

// UpdateRP updates an existing relying party
func (s *Server) UpdateRP(c *fiber.Ctx) error {
	// TODO: Implement RP update
	return c.SendStatus(fiber.StatusNotImplemented)
}

// DeleteRP deletes a relying party
func (s *Server) DeleteRP(c *fiber.Ctx) error {
	// TODO: Implement RP deletion
	return c.SendStatus(fiber.StatusNotImplemented)
}
