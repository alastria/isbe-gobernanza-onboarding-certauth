package storage

import (
	"crypto/rsa"
	"fmt"
	"strings"

	"github.com/evidenceledger/certauth/internal/jpath"
	"golang.org/x/text/language"
)

type User struct {
	ID                string
	Username          string
	Password          string
	FirstName         string
	LastName          string
	Email             string
	EmailVerified     bool
	Phone             string
	PhoneVerified     bool
	PreferredLanguage language.Tag
	IsAdmin           bool
	Credential        map[string]any
}

type Service struct {
	keys map[string]*rsa.PublicKey
}

type UserStore interface {
	GetUserByID(string) *User
	GetUserByUsername(string) *User
	ExampleClientID() string
	AddUserFromLEARCredential(cred map[string]any)
}

type userStore struct {
	users map[string]*User
}

func NewUserStore(issuer string) UserStore {
	hostname := strings.Split(strings.Split(issuer, "://")[1], ":")[0]
	fmt.Println("Hostname for user", hostname)
	return userStore{
		users: map[string]*User{
			"id1": {
				ID:                "id1",
				Username:          "hesusruiz",
				Password:          "verysecure",
				FirstName:         "Test",
				LastName:          "User",
				Email:             "test-user@zitadel.ch",
				EmailVerified:     true,
				Phone:             "",
				PhoneVerified:     false,
				PreferredLanguage: language.German,
				IsAdmin:           true,
			},
			"id2": {
				ID:                "id2",
				Username:          "test-user2",
				Password:          "verysecure",
				FirstName:         "Test",
				LastName:          "User2",
				Email:             "test-user2@zitadel.ch",
				EmailVerified:     true,
				Phone:             "",
				PhoneVerified:     false,
				PreferredLanguage: language.German,
				IsAdmin:           false,
			},
		},
	}
}

// ExampleClientID is only used in the example server
func (u userStore) ExampleClientID() string {
	return "service"
}

func (u userStore) GetUserByID(id string) *User {
	return u.users[id]
}

func (u userStore) GetUserByUsername(username string) *User {
	for _, user := range u.users {
		if user.Username == username {
			return user
		}
	}
	return nil
}

func (u userStore) AddUserFromLEARCredential(cred map[string]any) {
	email := jpath.GetString(cred, "credentialSubject.mandate.mandatee.email")

	user := &User{}
	user.ID = email
	user.Email = email
	user.EmailVerified = true
	user.FirstName = jpath.GetString(cred, "credentialSubject.mandate.mandatee.first_name")
	user.LastName = jpath.GetString(cred, "credentialSubject.mandate.mandatee.last_name")
	user.Phone = jpath.GetString(cred, "credentialSubject.mandate.mandatee.mobile_phone")
	user.PhoneVerified = true

	user.Credential = cred

	u.users[user.ID] = user
}
