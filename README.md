# socialengineering
package auth
import (
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"net/http"
	"crypto/rand"
	"github.com/gophish/gophish/models"
	ctx "github.com/gorilla/context"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)
func init() {
	gob.Register(&models.User{})
	gob.Register(&models.Flash{})
	Store.Options.HttpOnly = true
}
var Store = sessions.NewCookieStore(
	[]byte(securecookie.GenerateRandomKey(64)), //Signing key
	[]byte(securecookie.GenerateRandomKey(32)))
the register
var ErrEmptyPassword = errors.New("Password cannot be blank")
var ErrPasswordMismatch = errors.New("Passwords must match")
func Login(r *http.Request) (bool, error) {
	username, password := r.FormValue("username"), r.FormValue("password")
	session, _ := Store.Get(r, "gophish")
	u, err := models.GetUserByUsername(username)
	if err != nil && err != models.ErrUsernameTaken {
		return false, err
	}
	err = bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(password))
	if err != nil {
		ctx.Set(r, "user", nil)
		return false, ErrInvalidPassword
	}
	ctx.Set(r, "user", u)
	session.Values["id"] = u.Id
	return true, nil
}
func Register(r *http.Request) (bool, error) {
	username := r.FormValue("username")
	newPassword := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")
	u, err := models.GetUserByUsername(username)
	if err != nil {
		fmt.Println(err)
		return false, err
	}
	u = models.User{}
	if newPassword == "" {
		return false, ErrEmptyPassword
	}
	if newPassword != confirmPassword {
		return false, ErrPasswordMismatch
	}
	h, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return false, err
	}
	u.Username = username
	u.Hash = string(h)
	u.ApiKey = GenerateSecureKey()
	err = models.PutUser(&u)
	return true, nil
}
func GenerateSecureKey() string {
	
	k := make([]byte, 32)
	io.ReadFull(rand.Reader, k)
	return fmt.Sprintf("%x", k)
}
func ChangePassword(r *http.Request) error {
	u := ctx.Get(r, "user").(models.User)
	currentPw := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_new_password")
	err := bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(currentPw))
	if err != nil {
		return ErrInvalidPassword
	}
	if newPassword == "" {
		return ErrEmptyPassword
	}
	if newPassword != confirmPassword {
		return ErrPasswordMismatch
	}
	h, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.Hash = string(h)
	if err = models.PutUser(&u); err != nil {
		return err
	}
	return nil
}
