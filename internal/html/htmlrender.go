package html

import (
	"bytes"
	"embed"
	"io/fs"
	"log/slog"
	"net/http"
	"os"

	"github.com/evidenceledger/certauth/internal/errl"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
)

type RendererFiber struct {
	engine *html.Engine
}

type RendererStd struct {
	engine *html.Engine
}

// NewRendererFiber creates a new HTML renderer.
// It supports both embedded templates (in viewsfs) and external templates (in extDir).
// If templateDebug is true, the templates are loaded from the directory specified in extDir.
// If templateDebug is false, the templates are loaded from the embedded directory.
// Templates are reloaded in runtime, to allow dynamic changes.
// viewsfs is the filesystem containing the views.
// extDir is the directory containing the external templates.
func NewRendererFiber(templateDebug bool, viewsfs embed.FS, extDir string) (*RendererFiber, error) {

	engine, err := newEngine(templateDebug, viewsfs, extDir)
	if err != nil {
		return nil, errl.Error(err)
	}

	renderer := &RendererFiber{
		engine: engine,
	}

	return renderer, nil
}

func NewRendererStd(templateDebug bool, viewsfs embed.FS, extDir string) (*RendererStd, error) {

	engine, err := newEngine(templateDebug, viewsfs, extDir)
	if err != nil {
		return nil, errl.Error(err)
	}

	renderer := &RendererStd{
		engine: engine,
	}

	return renderer, nil
}

func newEngine(templateDebug bool, viewsfs embed.FS, extDir string) (*html.Engine, error) {
	// Try to load first the embedded templates, and later the user-provided ones
	var engine *html.Engine

	// Use the embedded directory
	viewsDir, err := fs.Sub(viewsfs, "views")
	if err != nil {
		return nil, errl.Error(err)
	}

	exists := false

	// Check if extDir exists in the os file system
	fi, err := os.Stat(extDir)
	if err == nil {
		if fi.IsDir() {
			exists = true
		}
	}

	// Use external templates if templateDebug is true, otherwise use embedded templates
	if exists {
		slog.Info("Using external HTML templates")
		engine = html.NewFileSystem(http.Dir(extDir), ".hbs")
		engine.Reload(true)
	} else {
		slog.Info("Using embedded HTML templates")
		engine = html.NewFileSystem(http.FS(viewsDir), ".hbs")
		engine.Reload(true)
	}

	err = engine.Load()
	if err != nil {
		return nil, errl.Error(err)
	}

	return engine, nil
}

// ResponseSecurityHeadersFiber sets the security headers for the response according to best practices
func ResponseSecurityHeadersFiber(c *fiber.Ctx) {

	c.Set("Content-Security-Policy", "frame-ancestors 'none';")
	c.Set("X-Frame-Options", "DENY")
	c.Set("X-Content-Type-Options", "nosniff")
	c.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	c.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
	c.Set("Cross-Origin-Opener-Policy", "same-origin")
	c.Set("Cross-Origin-Embedder-Policy", "require-corp")
	c.Set("Cross-Origin-Resource-Policy", "same-site")
	c.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), interest-cohort=()")
	c.Set("X-Powered-By", "webserver")

}

func ResponseSecurityHeadersStd(w http.ResponseWriter) {

	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none';")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-site")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), interest-cohort=()")
	w.Header().Set("X-Powered-By", "webserver")

}

func (h *RendererFiber) Render(c *fiber.Ctx, templateName string, data map[string]any, layout ...string) error {

	c.Set("Content-Type", "text/html; charset=utf-8")
	ResponseSecurityHeadersFiber(c)

	out := &bytes.Buffer{}

	if err := h.engine.Render(out, templateName, data, layout...); err != nil {
		slog.Error("Error rendering template",
			slog.String("error", err.Error()),
		)
		return fiber.NewError(fiber.StatusInternalServerError, "rendering response")
	}

	c.Send(out.Bytes())
	return nil

}

func (h *RendererStd) Render(w http.ResponseWriter, templateName string, data map[string]any, layout ...string) error {

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	ResponseSecurityHeadersStd(w)

	out := &bytes.Buffer{}

	if err := h.engine.Render(out, templateName, data, layout...); err != nil {
		slog.Error("Error rendering template",
			slog.String("error", err.Error()),
		)
		return fiber.NewError(fiber.StatusInternalServerError, "rendering response")
	}

	w.Write(out.Bytes())
	return nil

}
