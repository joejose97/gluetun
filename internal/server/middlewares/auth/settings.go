package auth

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/validate"
	"github.com/qdm12/gotree"
)

type Settings struct {
	// Auths is a list of authentication methods which can be used
	// by each role.
	Auths []Auth
	// Roles is a list of roles with their associated authentication
	// and routes.
	Roles []Role
}

func (s *Settings) SetDefaults() {
	s.Auths = gosettings.DefaultSlice(s.Auths, []Auth{{
		Name:   "public",
		Method: MethodNone,
	}}) // TODO v3.41.0 leave empty
	s.Roles = gosettings.DefaultSlice(s.Roles, []Role{{ // TODO v3.41.0 leave empty
		Name:  "public",
		Auths: []string{"public"},
		Routes: []Route{
			{Method: http.MethodGet, Path: "/openvpn/actions/restart"},
			{Method: http.MethodGet, Path: "/unbound/actions/restart"},
			{Method: http.MethodGet, Path: "/updater/restart"},
			{Method: http.MethodGet, Path: "/v1/version"},
			{Method: http.MethodGet, Path: "/v1/vpn/status"},
			{Method: http.MethodPut, Path: "/v1/vpn/status"},
			{Method: http.MethodGet, Path: "/v1/openvpn/status"},
			{Method: http.MethodPut, Path: "/v1/openvpn/status"},
			{Method: http.MethodGet, Path: "/v1/openvpn/portforwarded"},
			{Method: http.MethodGet, Path: "/v1/dns/status"},
			{Method: http.MethodPut, Path: "/v1/dns/status"},
			{Method: http.MethodGet, Path: "/v1/updater/status"},
			{Method: http.MethodPut, Path: "/v1/updater/status"},
			{Method: http.MethodGet, Path: "/v1/publicip/ip"},
		},
	}})
}

var (
	ErrAuthNameNotDefined = errors.New("authentication name not defined")
	ErrAuthNameNotUnique  = errors.New("authentication name is not unique")
)

func (s Settings) Validate() (err error) {
	authNameToAuthIndex := make(map[string]int, len(s.Auths))
	for i, auth := range s.Auths {
		existingIndex, exists := authNameToAuthIndex[auth.Name]
		if exists {
			return fmt.Errorf("%w: %q for auths %d of %d and %d of %d",
				ErrAuthNameNotUnique, auth.Name,
				i+1, len(s.Auths), existingIndex+1, len(s.Auths))
		}
		authNameToAuthIndex[auth.Name] = i

		err = auth.validate()
		if err != nil {
			return fmt.Errorf("auth %d of %d: %w", i+1, len(s.Auths), err)
		}
	}

	for i, role := range s.Roles {
		for _, auth := range role.Auths {
			_, isDefined := authNameToAuthIndex[auth]
			if !isDefined {
				return fmt.Errorf("%w: %q for role %s (%d of %d)",
					ErrAuthNameNotDefined, auth, role.Name, i+1, len(s.Roles))
			}
		}
		err = role.validate()
		if err != nil {
			return fmt.Errorf("role %s (%d of %d): %w",
				role.Name, i+1, len(s.Roles), err)
		}
	}

	return nil
}

func (s Settings) Copy() (copied Settings) {
	copied.Auths = make([]Auth, len(s.Auths))
	copy(copied.Auths, s.Auths)
	copied.Roles = make([]Role, len(s.Roles))
	for i := range s.Roles {
		copied.Roles[i] = s.Roles[i].copy()
	}
	return copied
}

func (s *Settings) OverrideWith(other Settings) {
	s.Auths = gosettings.OverrideWithSlice(s.Auths, other.Auths)
	s.Roles = gosettings.OverrideWithSlice(s.Roles, other.Roles)
}

func (s Settings) ToLinesNode() (node *gotree.Node) {
	node = gotree.New("Authentication middleware settings:")

	authNames := make([]string, len(s.Auths))
	for i, auth := range s.Auths {
		authNames[i] = auth.Name
	}
	node.Appendf("Authentications defined: %s", andStrings(authNames))

	roleNames := make([]string, len(s.Roles))
	for i, role := range s.Roles {
		roleNames[i] = role.Name
	}
	node.Appendf("Roles defined: %s", andStrings(roleNames))

	return node
}

const (
	MethodNone  = "none"
	MethodBasic = "basic"
)

// Auth contains the authentication method name and fields
// specific to each authentication method.
type Auth struct {
	// Name is the unique authentication name.
	Name string
	// Method is the authentication method to use.
	Method string
	// Username for HTTP Basic authentication method.
	Username string
	// Password for HTTP Basic authentication method.
	Password string
}

func (a Auth) validate() (err error) {
	err = validateAuthMethod(a.Method)
	if err != nil {
		return fmt.Errorf("method for name %s: %w", a.Name, err)
	}
	return nil
}

var (
	ErrMethodNotSupported = errors.New("authentication method not supported")
)

func validateAuthMethod(method string) (err error) {
	err = validate.IsOneOf(method, MethodNone, MethodBasic)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrMethodNotSupported, method)
	}
	return nil
}

// Role contains the role name, authentication method name and
// routes that the role can access.
type Role struct {
	// Name is the role name and is only used for documentation
	// and in the authentication middleware debug logs.
	Name string
	// Auths is a list of authentication names that the role can use,
	// where each must match a defined authentication.
	Auths []string
	// Routes is a list of routes that the role can access.
	Routes []Route
}

func (r Role) validate() (err error) {
	for i, route := range r.Routes {
		err = route.validate()
		if err != nil {
			return fmt.Errorf("route %d of %d: %w",
				i+1, len(r.Routes), err)
		}
	}

	return nil
}

func (r Role) copy() (copied Role) {
	copied.Name = r.Name
	copied.Auths = make([]string, len(r.Auths))
	copy(copied.Auths, r.Auths)
	copied.Routes = make([]Route, len(r.Routes))
	copy(copied.Routes, r.Routes)
	return copied
}

// Route contains the HTTP method and path of a route.
type Route struct {
	// Method is the HTTP method of the route, for example GET.
	Method string
	// Path is the path of the route, for example /v1/vpn/status.
	Path string
}

var (
	ErrRouteNotSupported = errors.New("route not supported by the control server")
)

func (r Route) validate() (err error) {
	_, ok := validRoutes[r]
	if ok {
		return nil
	}

	return fmt.Errorf("%w: %s %s", ErrRouteNotSupported, r.Method, r.Path)
}

// WARNING: do not mutate programmatically.
var validRoutes = map[Route]struct{}{ //nolint:gochecknoglobals
	{Method: http.MethodGet, Path: "/openvpn/actions/restart"}:  {},
	{Method: http.MethodGet, Path: "/unbound/actions/restart"}:  {},
	{Method: http.MethodGet, Path: "/updater/restart"}:          {},
	{Method: http.MethodGet, Path: "/v1/version"}:               {},
	{Method: http.MethodGet, Path: "/v1/vpn/status"}:            {},
	{Method: http.MethodPut, Path: "/v1/vpn/status"}:            {},
	{Method: http.MethodGet, Path: "/v1/vpn/settings"}:          {},
	{Method: http.MethodPut, Path: "/v1/vpn/settings"}:          {},
	{Method: http.MethodGet, Path: "/v1/openvpn/status"}:        {},
	{Method: http.MethodPut, Path: "/v1/openvpn/status"}:        {},
	{Method: http.MethodGet, Path: "/v1/openvpn/portforwarded"}: {},
	{Method: http.MethodGet, Path: "/v1/openvpn/settings"}:      {},
	{Method: http.MethodGet, Path: "/v1/dns/status"}:            {},
	{Method: http.MethodPut, Path: "/v1/dns/status"}:            {},
	{Method: http.MethodGet, Path: "/v1/updater/status"}:        {},
	{Method: http.MethodPut, Path: "/v1/updater/status"}:        {},
	{Method: http.MethodGet, Path: "/v1/publicip/ip"}:           {},
}
