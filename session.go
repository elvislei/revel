package revel

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

var (
	GlobalSession        *Manager
	SessionOn            bool
	SessionProvider      string
	SessionName          string
	SessionGCMaxLifetime int64
	SessionSavePath      string
)

func init() {
	OnAppStart(func() {
		var found bool
		if SessionOn, found = Config.Bool("session.on"); !found {
			ERROR.Fatal("not found session.on section in conf file.")
		} else if SessionOn {
			if SessionProvider, found = Config.String("session.provider"); !found {
				ERROR.Fatal("not found session.provider section in conf file.")
			}
			if SessionName, found = Config.String("session.name"); !found {
				ERROR.Fatal("not found session.name section in conf file.")
			}
			if SessionGCMaxLifetime, found = Config.Int64("session.lifetime"); !found {
				ERROR.Fatal("not found session.lifetime section in conf file.")
			}
			if SessionSavePath, found = Config.String("session.savePath"); !found {
				ERROR.Fatal("not found session.savePath section in conf file.")
			}

			GlobalSession, _ = NewManager(SessionProvider, SessionName, SessionGCMaxLifetime, SessionSavePath)
			go GlobalSession.GC() //新建一个线程无限循环,检查过期session

		}

	})
}

type SessionStore interface {
	Set(key, value interface{}) error //set session value
	Get(key interface{}) interface{}  //get session value
	Delete(key interface{}) error     //delete session value
	SessionID() string                //back current sessionID
	SessionRelease()                  // release the resource
}

type Provider interface {
	SessionInit(maxlifetime int64, savePath string) error
	SessionRead(sid string) (SessionStore, error)
	SessionDestroy(sid string) error
	SessionGC()
}

var provides = make(map[string]Provider)

// Register makes a session provide available by the provided name.
// If Register is called twice with the same name or if driver is nil,
// it panics.
func Register(name string, provide Provider) {
	if provide == nil {
		panic("session: Register provide is nil")
	}
	if _, dup := provides[name]; dup {
		panic("session: Register called twice for provider " + name)
	}
	provides[name] = provide
}

type Manager struct {
	cookieName  string //private cookiename
	provider    Provider
	maxlifetime int64
}

func NewManager(provideName, cookieName string, maxlifetime int64, savePath string) (*Manager, error) {
	provider, ok := provides[provideName]
	if !ok {
		return nil, fmt.Errorf("session: unknown provide %q (forgotten import?)", provideName)
	}
	provider.SessionInit(maxlifetime, savePath)
	return &Manager{provider: provider, cookieName: cookieName, maxlifetime: maxlifetime}, nil
}

//get Session
func (manager *Manager) SessionStart(w http.ResponseWriter, r *http.Request) (session SessionStore) {
	cookie, err := r.Cookie(manager.cookieName)
	if err != nil || cookie.Value == "" {
		sid := manager.sessionId()
		session, _ = manager.provider.SessionRead(sid)
		cookie := http.Cookie{Name: manager.cookieName,
			Value:    url.QueryEscape(sid),
			Path:     "/",
			HttpOnly: true,
			Secure:   false}
		//cookie.Expires = time.Now().Add(time.Duration(manager.maxlifetime) * time.Second)
		http.SetCookie(w, &cookie)
		r.AddCookie(&cookie)
	} else {
		//cookie.Expires = time.Now().Add(time.Duration(manager.maxlifetime) * time.Second)
		cookie.HttpOnly = true
		cookie.Path = "/"
		http.SetCookie(w, cookie)
		sid, _ := url.QueryUnescape(cookie.Value)
		session, _ = manager.provider.SessionRead(sid)
	}
	return
}

//Destroy sessionid
func (manager *Manager) SessionDestroy(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(manager.cookieName)
	if err != nil || cookie.Value == "" {
		return
	} else {
		manager.provider.SessionDestroy(cookie.Value)
		expiration := time.Now()
		cookie := http.Cookie{Name: manager.cookieName, Path: "/", HttpOnly: true, Expires: expiration, MaxAge: -1}
		http.SetCookie(w, &cookie)
	}
}

func (manager *Manager) GC() {
	manager.provider.SessionGC()
	time.AfterFunc(time.Duration(manager.maxlifetime)*time.Second, func() { manager.GC() })
}

func (manager *Manager) sessionId() string {
	b := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return ""
	}
	return base64.URLEncoding.EncodeToString(b)
}

func SessionFilter(c *Controller, fc []Filter) {

	fc[0](c, fc[1:])
}
