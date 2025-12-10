package certauth

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"math/big"
	"regexp"
	"time"

	"github.com/evidenceledger/certauth/internal/errl"
	"github.com/evidenceledger/certauth/internal/models"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
)

const (
	certLoginEndpoint                    = "/cert/login"
	certificateBackEndpoint              = "/certificate-back"
	sendEmailVerificationEndpoint        = "/request-email-verification"
	verifyEmailCodeEndpoint              = "/verify-email-code"
	presentContractForAcceptanceEndpoint = "/present-contract-for-acceptance"
	contractAcceptedEndpoint             = "/contract-accepted"
)

func (s *Server) registerCertificateHandlers() {

	// Presents a screen informing the user that a certificate will be requested.
	s.httpServer.Get(certLoginEndpoint, s.pageCertLogin)

	// Redirected from CertSec after the user has provided a certificate.
	// Presents a screen with the certificate data and requests the email from the user.
	s.httpServer.Get(certificateBackEndpoint, s.pageRequestEmail)

	// Receives the email address and sends an email to the user to verify if the email is correct.
	// Presents a screen to allow the user to enter the verification code sent to its email.
	s.httpServer.Post(sendEmailVerificationEndpoint, s.sendEmailVerification)

	// Receives the email verification code and verifies it.
	// Presents the contract text with an embedded form so the user can fill missing data.
	s.httpServer.Post(verifyEmailCodeEndpoint, s.verifyEmailCodeAndPresentContractForm)
	s.httpServer.Post(presentContractForAcceptanceEndpoint, s.pagePresentContractForAcceptance)

	// Handle consent received, generation of SSO cookie and redirection to Relying Party
	s.httpServer.Post(contractAcceptedEndpoint, s.handleContractAccepted)

}

// pageCertLogin shows the certificate selection screen
func (s *Server) pageCertLogin(c *fiber.Ctx) error {
	slog.Info("CertLoginPage", "from", c.Hostname(), "to", c.IP())

	// Retrieve the AuthorizationRequest from the application authentication session
	authProcess, err := s.getAuthProcess(c.Query("code"))
	if err != nil {
		err := errl.Errorf("getAuthProcess: %w", err)
		slog.Error(err.Error())
		return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
	}

	// Present the screen informing the user about the next step
	return s.htmlRender.Render(c, "cert_1_select", fiber.Map{
		"authCode":   authProcess.Code,
		"certsecURL": s.cfg.CertSecURL,
	})

}

// pageRequestEmail is invoked from CertSec when the user has selected a certificate in the browser popup
func (s *Server) pageRequestEmail(c *fiber.Ctx) error {
	// Get auth code from query parameter
	authCode := c.Query("code")

	// Retrieve the Authentication Process object from the cache
	authProcess, err := s.getAuthProcess(authCode)
	if err != nil {
		err := errl.Errorf("getAuthProcess: %w", err)
		slog.Error(err.Error())
		return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
	}
	slog.Info("Certificate received entry", "auth_code", authCode)

	// Check if CertSec returned some error
	certError := c.Query("error")
	if certError != "" || authProcess.ErrorInProcess != nil {
		err := authProcess.ErrorInProcess
		slog.Error("Error:", "error", err)
		return s.htmlRender.Render(c, "error", fiber.Map{
			"message": err,
		})
	}

	// Get the certificate data that was set by the certificate authentication process
	certData := authProcess.CertificateData

	// Check if the organization is already registered
	email, _, _, err := s.db.GetRegistration(certData.OrganizationID)
	if err != nil {
		return errl.Errorf("error retrieving registration email: %w", err)
	}

	if email != "" {

		// The organization is already registered, bypass certificate and email validation

		// Bypass certificate selection and return directly to caller
		slog.Debug("bypass certificate selection", "code", authProcess.Code, "redirect_uri", authProcess.RedirectURI)

		// Store email of the user in the authProcess struct
		authProcess.Email = email

		redirectURL := fmt.Sprintf("%s?code=%s", authProcess.RedirectURI, authProcess.Code)
		if authProcess.State != "" {
			redirectURL += fmt.Sprintf("&state=%s", authProcess.State)
		}

		return c.Redirect(redirectURL, fiber.StatusFound)

	}

	// Otherwise, we present the certificate data to the user and must request and validate its email
	slog.Info("Certificate received exit", "auth_code", authCode, "cert_length", len(certData.Certificate.Raw))

	// Present the screen
	return s.htmlRender.Render(c, "cert_2_received", fiber.Map{
		"authCode":    authCode,
		"authCodeObj": authProcess,
		"certType":    certData.CertificateType,
		"subject":     certData.Subject,
		"postAction":  sendEmailVerificationEndpoint,
	})

}

// sendEmailVerification handles the email verification form submission
func (s *Server) sendEmailVerification(c *fiber.Ctx) error {
	// Get form data
	email := utils.CopyString(c.FormValue("email"))
	authCode := c.FormValue("auth_code")

	// Retrieve the Authentication Process object from the cache
	authProcess, err := s.getAuthProcess(authCode)
	if err != nil {
		err := errl.Errorf("getAuthProcess: %w", err)
		slog.Error(err.Error())
		return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
	}

	if email == "" || authCode == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing email or authorization code",
		})
	}

	// Basic email format validation
	if !isValidEmail(email) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid email format",
		})
	}

	slog.Info("Email verification requested", "email", email, "auth_code", authCode)

	certData := authProcess.CertificateData
	if certData == nil {
		err := errl.Errorf("certificate data not found in authorization request")
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Generate a random 6-digit verification code
	emailVerificationCode := generateRandomCode()

	// Waiting for verification of the email address
	authProcess.Email = email
	authProcess.EmailVerificationCode = emailVerificationCode

	slog.Info("Verification code generated", "code", emailVerificationCode, "auth_code", authCode)

	// Render the confirm_email template
	return s.htmlRender.Render(c, "cert_3_confirm_email", fiber.Map{
		"email":            email,
		"authCode":         authCode,
		"verificationCode": emailVerificationCode, // For testing - remove in production
		"subject":          certData.Subject,
		"postAction":       verifyEmailCodeEndpoint,
	})
}

// isValidEmail performs basic email format validation
func isValidEmail(email string) bool {
	// Simple regex for basic email validation
	emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	matched, _ := regexp.MatchString(emailRegex, email)
	return matched
}

// generateRandomCode generates a random 6-digit verification code
func generateRandomCode() string {
	// Generate a random 6-digit number
	a, _ := rand.Int(rand.Reader, big.NewInt(999999))

	return fmt.Sprintf("%06d", a.Uint64())

}

// verifyEmailCodeAndPresentContractForm handles the email verification code verification,
// and presents the contract form to the user.
func (s *Server) verifyEmailCodeAndPresentContractForm(c *fiber.Ctx) error {
	// Get form data
	emailVerificationCode := utils.CopyString(c.FormValue("verification_code"))
	authCode := utils.CopyString(c.FormValue("auth_code"))
	email := utils.CopyString(c.FormValue("email"))

	if emailVerificationCode == "" || authCode == "" || email == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing verification code, authorization code, or email",
		})
	}

	slog.Info("Email verification code verification requested", "email", email, "auth_code", authCode)

	// Retrieve the Authentication Process object from the cache
	authProcess, err := s.getAuthProcess(authCode)
	if err != nil {
		err := errl.Errorf("getAuthProcess: %w", err)
		slog.Error(err.Error())
		return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
	}

	storedEmailVerificationCode := authProcess.EmailVerificationCode
	if storedEmailVerificationCode == "" {
		err := errl.Errorf("email verification code not found in authorization request")
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Verify the code
	if emailVerificationCode != storedEmailVerificationCode {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid verification code",
		})
	}

	slog.Info("Email verification code verified successfully", "email", email, "auth_code", authCode)

	storedEmail := authProcess.Email
	if storedEmail != email {
		err := errl.Errorf("email mismatch in authorization request")
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	slog.Debug("Stored email", "email", storedEmail)

	certData := authProcess.CertificateData

	// Update the email field in the certificate data
	certData.Subject.EmailAddress = storedEmail

	// Get the current date
	currentDate := time.Now()
	year := currentDate.Year()
	month := currentDate.Month()
	day := currentDate.Day()

	formData := models.ContractForm{
		TodayDay:            day,
		TodayMonth:          int(month),
		TodayYear:           year,
		OrganizationName:    certData.Subject.Organization,
		OrganizationCountry: certData.Subject.Country,
		OrganizationAddress: certData.Subject.StreetAddress,
		OrganizationNif:     certData.Subject.OrganizationIdentifier,
		RepresentativeName:  certData.Subject.CommonName,
		RepresentativeEmail: storedEmail,
	}

	// Render the certificate consent template
	return s.htmlRender.Render(c, "contract", fiber.Map{
		"authCode":    authCode,
		"authCodeObj": authProcess,
		"certType":    certData.CertificateType,
		"subject":     certData.Subject,
		"formData":    formData,
		"postAction":  presentContractForAcceptanceEndpoint,
	})
}

func (s *Server) pagePresentContractForAcceptance(c *fiber.Ctx) error {

	// Data for checking the form is valid, before we do anything else
	authCode := utils.CopyString(c.FormValue("auth_code"))
	if authCode == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing authorization code",
		})
	}

	// Retrieve the Authentication Process object from the cache
	authProcess, err := s.getAuthProcess(authCode)
	if err != nil {
		err := errl.Errorf("getAuthProcess: %w", err)
		slog.Error(err.Error())
		return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
	}

	// Parse the formData
	formData := models.ContractForm{}
	if err := c.BodyParser(&formData); err != nil {
		slog.Error("Failed to parse form", "error", err)
		return errl.Errorf("failed to parse form: %w", err)
	}

	// Check that we have the email of the representative
	if formData.RepresentativeEmail == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing representative email",
		})
	}

	slog.Info("Email verification code verification requested", "email", formData.RepresentativeEmail, "auth_code", authCode)

	// Sanity check, we already have an email and they have to be the same
	storedEmail := authProcess.Email
	if storedEmail != formData.RepresentativeEmail {
		err := errl.Errorf("email mismatch in authorization request")
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	certData := authProcess.CertificateData

	// Update the email field in the certificate data
	certData.Subject.EmailAddress = storedEmail

	// Render the certificate consent template
	return s.htmlRender.Render(c, "contractprint", fiber.Map{
		"authCode":    authCode,
		"authCodeObj": authProcess,
		"formData":    formData,
		"postAction":  contractAcceptedEndpoint,
	})

}

// handleContractAccepted is the last step, after the user has given consent to proceed.
// We then generate the SSO cookie and redirect to the RP with the auth code.
// The RP will eventually exchange the auth code for ID and access tokens, which will contain user and certificate data.
func (s *Server) handleContractAccepted(c *fiber.Ctx) error {

	// Data for checking the form is valid, before we do anything else
	authCode := utils.CopyString(c.FormValue("auth_code"))
	if authCode == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing authorization code",
		})
	}

	// Retrieve the Authentication Process object from the cache
	authProcess, err := s.getAuthProcess(authCode)
	if err != nil {
		err := errl.Errorf("getAuthProcess: %w", err)
		slog.Error(err.Error())
		return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
	}

	// Parse the formData
	formData := models.ContractForm{}
	if err := c.BodyParser(&formData); err != nil {
		slog.Error("Failed to parse form", "error", err)
		return errl.Errorf("failed to parse form: %w", err)
	}

	// Check that we have the email of the representative
	if formData.RepresentativeEmail == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing representative email",
		})
	}

	slog.Info("Email verification code verification requested", "email", formData.RepresentativeEmail, "auth_code", authCode)

	// Sanity check, we already have an email and they have to be the same
	storedEmail := authProcess.Email
	if storedEmail != formData.RepresentativeEmail {
		err := errl.Errorf("email mismatch in authorization request")
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	slog.Debug("Stored email", "email", storedEmail)

	// Store the company data in the registrations table
	if err := s.db.CreateRegistration(s.tsaService, authProcess.CertificateData, storedEmail, &formData); err != nil {
		err = errl.Errorf("creating registration: %w", err)
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})

	}

	// Notify the main portal that the registration is complete
	if err := s.notifyMainPortal(authProcess.CertificateData, storedEmail, &formData); err != nil {
		err = errl.Errorf("notifying main portal: %w", err)
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Generate a random unique identifier for the SSO session
	ssoSessionID := generateRandomString()

	// Create the SSO session data to be held in the server-side cache
	ssoSession := &models.SSOSession{
		SessionID:       ssoSessionID,
		Email:           storedEmail,
		CertificateData: authProcess.CertificateData,
	}

	// Store the SSO session in the cache (valid for 24 hours)
	s.cache.Set(ssoSessionID, ssoSession, 24*time.Hour)

	// Generate SSO cookie
	ssoCookie, err := s.generateSSOCookie(ssoSessionID, ssoSession.CertificateData)
	if err != nil {
		slog.Error("failed to generate sso cookie", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}

	// Set SSO cookie
	c.Cookie(ssoCookie)

	// Redirect (302) to RP with auth code
	slog.Info("User consent processed successfully", "email", storedEmail, "auth_code", authCode)
	// href="{{ .authCodeObj.RedirectURI }}?code={{ .authCode }}&state={{ .authCodeObj.State }}"
	redirectURL := fmt.Sprintf("%s?code=%s", authProcess.RedirectURI, authCode)
	if authProcess.State != "" {
		redirectURL += fmt.Sprintf("&state=%s", authProcess.State)
	}

	return c.Redirect(redirectURL, fiber.StatusFound)

}

func (s *Server) notifyMainPortal(certData *models.CertificateData, email string, contractForm *models.ContractForm) error {
	return nil
}
