package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
)

// func generatePassword(len int) string {
// 	var sb strings.Builder

// 	for i := 0; i < len; i++ {
// 		sb.WriteByte(byte(rand.Intn(94)))
// 	}
// 	return sb.String()
// }

func newBasicAuth(user string, pass string) httpBasicAuth {
	authobj := httpBasicAuth{}
	var sb strings.Builder

	sb.WriteString(user)
	sb.WriteString(pass)
	authobj.userpassmatch = sha256.Sum256([]byte(sb.String()))
	if authobj.userpassmatch != sha256.Sum256([]byte("")) {
		authobj.enabled = true
	} else {
		authobj.enabled = false
	}
	return authobj
}

type httpBasicAuth struct {
	enabled       bool
	userpassmatch [32]byte
}

func (auth httpBasicAuth) isAuthorized(w http.ResponseWriter, r *http.Request) bool {
	if !auth.enabled {
		return true
	}
	authsuccess := false
	var inpSb strings.Builder
	// Get Inputs from http request
	username, password, ok := r.BasicAuth()
	if ok {
		inpSb.WriteString(username)
		inpSb.WriteString(password)
		inputhash := sha256.Sum256([]byte(inpSb.String()))
		authsuccess = (subtle.ConstantTimeCompare(auth.userpassmatch[:], inputhash[:]) == 1)
	}
	if authsuccess {
		return true
	}

	// If the Authentication header is not present, is invalid, or the
	// username or password is wrong, then set a WWW-Authenticate
	// header to inform the client that we expect them to use basic
	// authentication and send a 401 Unauthorized response.
	w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
	return false
}

// func protectedHandler(next http.HandlerFunc, auth httpBasicAuth) http.HandlerFunc {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		if auth.Authenticate(w, r) {
// 			next.ServeHTTP(w, r)
// 		}
// 	})
// }
