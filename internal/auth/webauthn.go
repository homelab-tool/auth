package auth

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	"github.com/go-webauthn/webauthn/webauthn"
)

type WebAuthnService struct {
	WebAuthn *webauthn.WebAuthn
}

func NewWebAuthnService() (*WebAuthnService, error) {
	rpid := os.Getenv("WEBAUTHN_RPID")
	if rpid == "" {
		return nil, fmt.Errorf("WEBAUTHN_RPID environment variable is required")
	}

	originsStr := os.Getenv("WEBAUTHN_RP_ORIGINS")
	if originsStr == "" {
		return nil, fmt.Errorf("WEBAUTHN_RP_ORIGINS environment variable is required")
	}
	origins := strings.Split(originsStr, ",")

	displayName := os.Getenv("WEBAUTHN_RP_DISPLAY_NAME")
	if displayName == "" {
		displayName = "Homelab Auth"
	}

	config := &webauthn.Config{
		RPID:          rpid,
		RPDisplayName: displayName,
		RPOrigins:     origins,
	}

	w, err := webauthn.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create webauthn: %w", err)
	}

	return &WebAuthnService{WebAuthn: w}, nil
}

type WebAuthnUser struct {
	ID          int64
	DisplayName string
	Credentials []webauthn.Credential
}

func (u *WebAuthnUser) WebAuthnID() []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(u.ID))
	return buf[:]
}

func (u *WebAuthnUser) WebAuthnName() string {
	return fmt.Sprintf("%d", u.ID)
}

func (u *WebAuthnUser) WebAuthnDisplayName() string {
	return u.DisplayName
}

func (u *WebAuthnUser) WebAuthnIcon() string {
	return ""
}

func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

func UserIDFromWebAuthnID(id []byte) (int64, error) {
	if len(id) != 8 {
		return 0, fmt.Errorf("invalid webauthn user id length: %d", len(id))
	}
	return int64(binary.BigEndian.Uint64(id)), nil
}


