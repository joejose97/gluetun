package auth

import "net/http"

type authorizationChecker interface {
	equal(other authorizationChecker) bool
	isAuthorized(writer http.ResponseWriter, request *http.Request) bool
}
