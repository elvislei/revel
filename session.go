package revel

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"github.com/streadway/simpleuuid"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type SessionStore interface {
	Set(key, value interface{}) error //set session value
	Get(key interface{}) interface{}  //get session value
	Delete(key interface{}) error     //delete session value
	SessionID() string                //back current sessionID
	SessionRelease()                  // release the resource & save data to provider
	Flush() error                     //delete all data
}

type Provider interface {
	SessionInit(maxlifetime int64, savePath string) error
	SessionRead(sid string) (SessionStore, error)
	SessionExist(sid string) bool
	SessionRegenerate(oldsid, sid string) (SessionStore, error)
	SessionDestroy(sid string) error
	SessionAll() int //get all active session
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
	hashfunc    string //support md5 & sha1
	hashkey     string
	maxage      int //cookielifetime
	secure      bool
	options     []interface{}
}

//options
//1. is https  default false
//2. hashfunc  default sha1
//3. hashkey default beegosessionkey
//4. maxage default is none
func NewManager(provideName, cookieName string, maxlifetime int64, savePath string, options ...interface{}) (*Manager, error) {
	provider, ok := provides[provideName]
	if !ok {
		return nil, fmt.Errorf("session: unknown provide %q (forgotten import?)", provideName)
	}
	provider.SessionInit(maxlifetime, savePath)
	secure := false
	if len(options) > 0 {
		secure = options[0].(bool)
	}
	hashfunc := "sha1"
	if len(options) > 1 {
		hashfunc = options[1].(string)
	}
	hashkey := "beegosessionkey"
	if len(options) > 2 {
		hashkey = options[2].(string)
	}
	maxage := -1
	if len(options) > 3 {
		switch options[3].(type) {
		case int:
			if options[3].(int) > 0 {
				maxage = options[3].(int)
			} else if options[3].(int) < 0 {
				maxage = 0
			}
		case int64:
			if options[3].(int64) > 0 {
				maxage = int(options[3].(int64))
			} else if options[3].(int64) < 0 {
				maxage = 0
			}
		case int32:
			if options[3].(int32) > 0 {
				maxage = int(options[3].(int32))
			} else if options[3].(int32) < 0 {
				maxage = 0
			}
		}
	}
	return &Manager{
		provider:    provider,
		cookieName:  cookieName,
		maxlifetime: maxlifetime,
		hashfunc:    hashfunc,
		hashkey:     hashkey,
		maxage:      maxage,
		secure:      secure,
		options:     options,
	}, nil
}

//get Session
func (manager *Manager) SessionStart(w http.ResponseWriter, r *http.Request) (session SessionStore) {
	cookie, err := r.Cookie(manager.cookieName)
	if err != nil || cookie.Value == "" {
		sid := manager.sessionId(r)
		session, _ = manager.provider.SessionRead(sid)
		cookie = &http.Cookie{Name: manager.cookieName,
			Value:    url.QueryEscape(sid),
			Path:     "/",
			HttpOnly: true,
			Secure:   manager.secure}
		if manager.maxage >= 0 {
			cookie.MaxAge = manager.maxage
		}
		http.SetCookie(w, cookie)
		r.AddCookie(cookie)
	} else {
		sid, _ := url.QueryUnescape(cookie.Value)
		if manager.provider.SessionExist(sid) {
			session, _ = manager.provider.SessionRead(sid)
		} else {
			sid = manager.sessionId(r)
			session, _ = manager.provider.SessionRead(sid)
			cookie = &http.Cookie{Name: manager.cookieName,
				Value:    url.QueryEscape(sid),
				Path:     "/",
				HttpOnly: true,
				Secure:   manager.secure}
			if manager.maxage >= 0 {
				cookie.MaxAge = manager.maxage
			}
			http.SetCookie(w, cookie)
			r.AddCookie(cookie)
		}
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

func (manager *Manager) GetProvider(sid string) (sessions SessionStore, err error) {
	sessions, err = manager.provider.SessionRead(sid)
	return
}

func (manager *Manager) GC() {
	manager.provider.SessionGC()
	time.AfterFunc(time.Duration(manager.maxlifetime)*time.Second, func() { manager.GC() })
}

func (manager *Manager) SessionRegenerateId(w http.ResponseWriter, r *http.Request) (session SessionStore) {
	sid := manager.sessionId(r)
	cookie, err := r.Cookie(manager.cookieName)
	if err != nil && cookie.Value == "" {
		//delete old cookie
		session, _ = manager.provider.SessionRead(sid)
		cookie = &http.Cookie{Name: manager.cookieName,
			Value:    url.QueryEscape(sid),
			Path:     "/",
			HttpOnly: true,
			Secure:   manager.secure,
		}
	} else {
		oldsid, _ := url.QueryUnescape(cookie.Value)
		session, _ = manager.provider.SessionRegenerate(oldsid, sid)
		cookie.Value = url.QueryEscape(sid)
		cookie.HttpOnly = true
		cookie.Path = "/"
	}
	if manager.maxage >= 0 {
		cookie.MaxAge = manager.maxage
	}
	http.SetCookie(w, cookie)
	r.AddCookie(cookie)
	return
}

func (manager *Manager) GetActiveSession() int {
	return manager.provider.SessionAll()
}

func (manager *Manager) SetHashFunc(hasfunc, hashkey string) {
	manager.hashfunc = hasfunc
	manager.hashkey = hashkey
}

func (manager *Manager) SetSecure(secure bool) {
	manager.secure = secure
}

//remote_addr cruunixnano randdata
func (manager *Manager) sessionId(r *http.Request) (sid string) {
	bs := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, bs); err != nil {
		return ""
	}
	sig := fmt.Sprintf("%s%d%s", r.RemoteAddr, time.Now().UnixNano(), bs)
	if manager.hashfunc == "md5" {
		h := md5.New()
		h.Write([]byte(sig))
		sid = hex.EncodeToString(h.Sum(nil))
	} else if manager.hashfunc == "sha1" {
		h := hmac.New(sha1.New, []byte(manager.hashkey))
		fmt.Fprintf(h, "%s", sig)
		sid = hex.EncodeToString(h.Sum(nil))
	} else {
		h := hmac.New(sha1.New, []byte(manager.hashkey))
		fmt.Fprintf(h, "%s", sig)
		sid = hex.EncodeToString(h.Sum(nil))
	}
	return
}

var GlobalSession *Manager

// A signed cookie (and thus limited to 4kb in size).
// Restriction: Keys may not have a colon in them.
type Session map[string]string

const (
	SESSION_ID_KEY = "_ID"
	TS_KEY         = "_TS"
)

var expireAfterDuration time.Duration

func init() {
	// Set expireAfterDuration, default to 30 days if no value in config
	OnAppStart(func() {
		var err error
		if expiresString, ok := Config.String("session.expires"); !ok {
			expireAfterDuration = 30 * 24 * time.Hour
		} else if expiresString == "session" {
			expireAfterDuration = 0
		} else if expireAfterDuration, err = time.ParseDuration(expiresString); err != nil {
			panic(fmt.Errorf("session.expires invalid: %s", err))
		}

		var (
			found                bool
			SessionOn            bool
			SessionProvider      string
			SessionName          string
			SessionGCMaxLifetime int64
			SessionSavePath      string
		)

		if SessionOn, _ = Config.Bool("session.on"); SessionOn {

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

			GlobalSession, _ = NewManager(SessionProvider,
				SessionName,
				SessionGCMaxLifetime,
				SessionSavePath)
			go GlobalSession.GC()
		}
	})
}

// Return a UUID identifying this session.
func (s Session) Id() string {
	if uuidStr, ok := s[SESSION_ID_KEY]; ok {
		return uuidStr
	}

	uuid, err := simpleuuid.NewTime(time.Now())
	if err != nil {
		panic(err) // I don't think this can actually happen.
	}
	s[SESSION_ID_KEY] = uuid.String()
	return s[SESSION_ID_KEY]
}

// Return a time.Time with session expiration date
func getSessionExpiration() time.Time {
	if expireAfterDuration == 0 {
		return time.Time{}
	}
	return time.Now().Add(expireAfterDuration)
}

// Returns an http.Cookie containing the signed session.
func (s Session) cookie() *http.Cookie {
	var sessionValue string
	ts := getSessionExpiration()
	s[TS_KEY] = getSessionExpirationCookie(ts)
	for key, value := range s {
		if strings.ContainsAny(key, ":\x00") {
			panic("Session keys may not have colons or null bytes")
		}
		if strings.Contains(value, "\x00") {
			panic("Session values may not have null bytes")
		}
		sessionValue += "\x00" + key + ":" + value + "\x00"
	}

	sessionData := url.QueryEscape(sessionValue)
	return &http.Cookie{
		Name:     CookiePrefix + "_SESSION",
		Value:    Sign(sessionData) + "-" + sessionData,
		Path:     "/",
		HttpOnly: CookieHttpOnly,
		Secure:   CookieSecure,
		Expires:  ts.UTC(),
	}
}

func sessionTimeoutExpiredOrMissing(session Session) bool {
	if exp, present := session[TS_KEY]; !present {
		return true
	} else if exp == "session" {
		return false
	} else if expInt, _ := strconv.Atoi(exp); int64(expInt) < time.Now().Unix() {
		return true
	}
	return false
}

// Returns a Session pulled from signed cookie.
func getSessionFromCookie(cookie *http.Cookie) Session {
	session := make(Session)

	// Separate the data from the signature.
	hyphen := strings.Index(cookie.Value, "-")
	if hyphen == -1 || hyphen >= len(cookie.Value)-1 {
		return session
	}
	sig, data := cookie.Value[:hyphen], cookie.Value[hyphen+1:]

	// Verify the signature.
	if !Verify(data, sig) {
		INFO.Println("Session cookie signature failed")
		return session
	}

	ParseKeyValueCookie(data, func(key, val string) {
		session[key] = val
	})

	if sessionTimeoutExpiredOrMissing(session) {
		session = make(Session)
	}

	return session
}

func SessionFilter(c *Controller, fc []Filter) {
	//TODO....set session to controller
	// c.Session = restoreSession(c.Request.Request)
	// Make session vars available in templates as {{.session.xyz}}
	// c.RenderArgs["session"] = c.Session

	fc[0](c, fc[1:])

	// Store the session (and sign it).
	// c.SetCookie(c.Session.cookie())
}

func restoreSession(req *http.Request) Session {
	session := make(Session)
	cookie, err := req.Cookie(CookiePrefix + "_SESSION")
	if err != nil {
		return session
	}

	return getSessionFromCookie(cookie)
}

func getSessionExpirationCookie(t time.Time) string {
	if t.IsZero() {
		return "session"
	}
	return strconv.FormatInt(t.Unix(), 10)
}
