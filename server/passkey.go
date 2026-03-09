package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
)

// --- Internal Types ---

var (
	wauth        *webauthn.WebAuthn
	sessionStore = struct {
		sync.RWMutex
		data map[string]sessionItem
	}{
		data: make(map[string]sessionItem),
	}
)

type sessionItem struct {
	data      *webauthn.SessionData
	createdAt time.Time
}

// PasskeyUser implements the webauthn.User interface for PocketBase records.
type PasskeyUser struct {
	record *core.Record
}

func (u *PasskeyUser) WebAuthnID() []byte {
	return []byte(u.record.Id)
}

func (u *PasskeyUser) WebAuthnName() string {
	return u.record.GetString("email")
}

func (u *PasskeyUser) WebAuthnDisplayName() string {
	return u.record.GetString("email")
}

func (u *PasskeyUser) WebAuthnIcon() string {
	return ""
}

// StoredCredential wraps the standard WebAuthn credential with additional metadata.
type StoredCredential struct {
	webauthn.Credential
	RegisteredAt time.Time `json:"registeredAt"`
}

// WebAuthnCredentials returns the stored credentials for the user from a JSON field.
func (u *PasskeyUser) WebAuthnCredentials() []webauthn.Credential {
	existing := u.record.GetString("passkey_credentials")
	if existing == "" {
		return []webauthn.Credential{}
	}

	var stored []StoredCredential
	if err := json.Unmarshal([]byte(existing), &stored); err != nil {
		return []webauthn.Credential{}
	}

	credentials := make([]webauthn.Credential, len(stored))
	for i, s := range stored {
		credentials[i] = s.Credential
	}
	return credentials
}

// --- Initialization ---

// setupPasskey initializes the WebAuthn configuration and binds API routes.
func setupPasskey(app *pocketbase.PocketBase) error {
	// 1. RPID & RPOrigins configuration from Env
	rpid := os.Getenv("PASSKEY_RPID")
	if rpid == "" {
		rpid = "localhost"
	}

	rpDisplayName := os.Getenv("PASSKEY_RP_DISPLAY_NAME")
	if rpDisplayName == "" {
		rpDisplayName = "pocketbase-passkey"
	}

	rawOrigins := os.Getenv("PASSKEY_RP_ORIGINS")
	var origins []string
	if rawOrigins != "" {
		origins = strings.Split(rawOrigins, ",")
	} else {
		appOrigin := app.Settings().Meta.AppURL
		if appOrigin == "" {
			appOrigin = "http://localhost:8090"
		}
		origins = []string{appOrigin, "http://localhost:3000"}
	}

	var err error
	wauth, err = webauthn.New(&webauthn.Config{
		RPDisplayName: rpDisplayName,
		RPID:          rpid,
		RPOrigins:     origins,
	})
	if err != nil {
		return err
	}

	// 2. Start session cleanup goroutine
	go cleanSessions()

	// 3. Bind Routes
	app.OnServe().BindFunc(func(e *core.ServeEvent) error {
		e.Router.POST("/api/passkey/register/begin", registerBegin(app))
		e.Router.POST("/api/passkey/register/finish", registerFinish(app))
		e.Router.POST("/api/passkey/login/begin", loginBegin(app))
		e.Router.POST("/api/passkey/login/finish", loginFinish(app))
		return e.Next()
	})

	return nil
}

// --- Route Handlers ---

// registerBegin handles the start of a passkey registration.
func registerBegin(app *pocketbase.PocketBase) func(*core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		setBaseHeaders(e)

		userId, err := getUserIdFromJSON(e.Request.Body)
		if err != nil || userId == "" {
			return errorRes(e, http.StatusBadRequest, "userId is required")
		}

		userRecord, err := app.FindRecordById("users", userId)
		if err != nil {
			return errorRes(e, http.StatusNotFound, "user not found")
		}

		user := &PasskeyUser{record: userRecord}

		// Convert existing credentials to exclusion descriptors
		existingCreds := user.WebAuthnCredentials()
		exclusions := make([]protocol.CredentialDescriptor, len(existingCreds))
		for i, cred := range existingCreds {
			exclusions[i] = protocol.CredentialDescriptor{
				Type:         protocol.PublicKeyCredentialType,
				CredentialID: cred.ID,
			}
		}

		options, session, err := wauth.BeginRegistration(
			user,
			webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
				UserVerification: protocol.VerificationPreferred,
			}),
			webauthn.WithExclusions(exclusions),
		)
		if err != nil {
			return errorRes(e, http.StatusInternalServerError, err.Error())
		}

		saveSession(userId, session)
		return e.JSON(http.StatusOK, options)
	}
}

// registerFinish handles the completion of a passkey registration.
func registerFinish(app *pocketbase.PocketBase) func(*core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		setBaseHeaders(e)

		// Read body twice (once for userId, once for webauthn processing)
		bodyBytes, _ := io.ReadAll(e.Request.Body)
		e.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		userId, err := getUserIdFromJSON(bytes.NewReader(bodyBytes))
		if err != nil || userId == "" {
			return errorRes(e, http.StatusBadRequest, "userId is required")
		}

		session, err := getValidSession(userId)
		if err != nil {
			return errorRes(e, http.StatusBadRequest, err.Error())
		}

		userRecord, err := app.FindRecordById("users", userId)
		if err != nil {
			return errorRes(e, http.StatusNotFound, "user not found")
		}

		user := &PasskeyUser{record: userRecord}
		credential, err := wauth.FinishRegistration(user, *session, e.Request)
		if err != nil {
			return errorRes(e, http.StatusBadRequest, err.Error())
		}

		if err := saveCredential(app, userRecord, credential); err != nil {
			return errorRes(e, http.StatusInternalServerError, err.Error())
		}

		deleteSession(userId)
		return e.JSON(http.StatusOK, map[string]string{"status": "registered"})
	}
}

// loginBegin handles the start of a passkey authentication.
func loginBegin(app *pocketbase.PocketBase) func(*core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		setBaseHeaders(e)

		userId, err := getUserIdFromJSON(e.Request.Body)
		if err != nil || userId == "" {
			return errorRes(e, http.StatusBadRequest, "userId is required")
		}

		userRecord, err := app.FindRecordById("users", userId)
		if err != nil {
			return errorRes(e, http.StatusNotFound, "user not found")
		}

		user := &PasskeyUser{record: userRecord}
		options, session, err := wauth.BeginLogin(user)
		if err != nil {
			return errorRes(e, http.StatusInternalServerError, err.Error())
		}

		saveSession(userId, session)
		return e.JSON(http.StatusOK, options)
	}
}

// loginFinish handles the completion of a passkey authentication.
func loginFinish(app *pocketbase.PocketBase) func(*core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		setBaseHeaders(e)

		bodyBytes, _ := io.ReadAll(e.Request.Body)
		e.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		userId, err := getUserIdFromJSON(bytes.NewReader(bodyBytes))
		if err != nil || userId == "" {
			return errorRes(e, http.StatusBadRequest, "userId is required")
		}

		session, err := getValidSession(userId)
		if err != nil {
			return errorRes(e, http.StatusBadRequest, err.Error())
		}

		userRecord, err := app.FindRecordById("users", userId)
		if err != nil {
			return errorRes(e, http.StatusNotFound, "user not found")
		}

		user := &PasskeyUser{record: userRecord}
		credential, err := wauth.FinishLogin(user, *session, e.Request)
		if err != nil {
			return errorRes(e, http.StatusUnauthorized, err.Error())
		}

		// Update sign counter
		updateCredentialCounter(app, userRecord, credential)
		deleteSession(userId)

		token, err := userRecord.NewAuthToken()
		if err != nil {
			return errorRes(e, http.StatusInternalServerError, err.Error())
		}

		return e.JSON(http.StatusOK, map[string]any{
			"token":  token,
			"record": userRecord,
		})
	}
}

// --- Helpers: Session Management ---

func saveSession(id string, data *webauthn.SessionData) {
	sessionStore.Lock()
	defer sessionStore.Unlock()
	sessionStore.data[id] = sessionItem{
		data:      data,
		createdAt: time.Now(),
	}
}

func getValidSession(id string) (*webauthn.SessionData, error) {
	sessionStore.RLock()
	defer sessionStore.RUnlock()
	item, ok := sessionStore.data[id]
	if !ok || time.Since(item.createdAt) > 5*time.Minute {
		return nil, http.ErrHandlerTimeout // Generic err interpreted as expired
	}
	return item.data, nil
}

func deleteSession(id string) {
	sessionStore.Lock()
	defer sessionStore.Unlock()
	delete(sessionStore.data, id)
}

func cleanSessions() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		sessionStore.Lock()
		for id, item := range sessionStore.data {
			if time.Since(item.createdAt) > 5*time.Minute {
				delete(sessionStore.data, id)
			}
		}
		sessionStore.Unlock()
	}
}

// --- Helpers: User & Credential Logic ---

func saveCredential(app *pocketbase.PocketBase, record *core.Record, cred *webauthn.Credential) error {
	existing := record.GetString("passkey_credentials")
	var credentials []StoredCredential
	if existing != "" {
		_ = json.Unmarshal([]byte(existing), &credentials)
	}
	credentials = append(credentials, StoredCredential{
		Credential:   *cred,
		RegisteredAt: time.Now(),
	})

	credJSON, _ := json.Marshal(credentials)
	record.Set("passkey_credentials", string(credJSON))
	return app.Save(record)
}

func updateCredentialCounter(app *pocketbase.PocketBase, record *core.Record, cred *webauthn.Credential) {
	existing := record.GetString("passkey_credentials")
	var credentials []StoredCredential
	if err := json.Unmarshal([]byte(existing), &credentials); err == nil {
		for i, c := range credentials {
			if string(c.ID) == string(cred.ID) {
				credentials[i].Credential = *cred
				break
			}
		}
		credJSON, _ := json.Marshal(credentials)
		record.Set("passkey_credentials", string(credJSON))
		_ = app.Save(record)
	}
}

// --- Helpers: JSON & Response ---

func getUserIdFromJSON(r io.Reader) (string, error) {
	var body struct {
		UserId string `json:"userId"`
	}
	err := json.NewDecoder(r).Decode(&body)
	return body.UserId, err
}

func setBaseHeaders(e *core.RequestEvent) {
	e.Response.Header().Set("Access-Control-Allow-Origin", "*")
	e.Response.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
	e.Response.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}

func errorRes(e *core.RequestEvent, code int, msg string) error {
	return e.JSON(code, map[string]string{"error": msg})
}
