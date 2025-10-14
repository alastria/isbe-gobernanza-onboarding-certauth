package main

import (
	"embed"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/evidenceledger/certauth/internal/html"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

var viewsfs embed.FS

func main() {

	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	fmt.Println(wd)

	// The engine to display the screens (HTML) to the users
	htmlrender, err := html.NewRendererFiber(true, viewsfs, "internal/onboard/views")
	if err != nil {
		slog.Error("Failed to initialize template engine", "error", err)
		panic(err)
	}

	app := fiber.New(fiber.Config{
		AppName:                 "Go template development",
		ServerHeader:            "CertAuth",
		EnableTrustedProxyCheck: false,
		ReadTimeout:             30 * time.Second,
		WriteTimeout:            30 * time.Second,
	})

	// Recovers from panics anywhere in the stack chain and handles the control to the centralized ErrorHandler
	app.Use(recover.New())

	app.Get("/page/:name", func(c *fiber.Ctx) error {
		name := c.Params("name")

		subject := fiber.Map{
			"OrganizationIdentifier": "VATES-12345678K",
			"Email":                  "jesus@alastria.io",
		}

		data := fiber.Map{
			"subject": subject,
		}

		err := htmlrender.Render(c, name, data)
		return err
	})

	app.Static("/static", "./internal/certauth/views/assets")

	if err := app.Listen(":8080"); err != nil {
		fmt.Println(err)
	}

}
