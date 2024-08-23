package auth

import (
	"fmt"
	"net/http"
)

func New(settings Settings, debugLogger DebugLogger) (
	middleware func(http.Handler) http.Handler,
	err error) {
	routeToRoles, err := settingsToLookupMap(settings)
	if err != nil {
		return nil, fmt.Errorf("converting settings to lookup maps: %w", err)
	}

	return func(handler http.Handler) http.Handler {
		return &authHandler{
			childHandler: handler,
			routeToRoles: routeToRoles,
			unprotectedRoutes: map[Route]struct{}{
				{Method: http.MethodGet, Path: "/openvpn/actions/restart"}: {},
				{Method: http.MethodGet, Path: "/unbound/actions/restart"}: {},
				{Method: http.MethodGet, Path: "/updater/restart"}:         {},
				{Method: http.MethodGet, Path: "/v1/version"}:              {},
				{Method: http.MethodGet, Path: "/v1/vpn/status"}:           {},
				{Method: http.MethodPut, Path: "/v1/vpn/status"}:           {},
				// GET /v1/vpn/settings is protected by default
				// PUT /v1/vpn/settings is protected by default
				{Method: http.MethodGet, Path: "/v1/openvpn/status"}:        {},
				{Method: http.MethodPut, Path: "/v1/openvpn/status"}:        {},
				{Method: http.MethodGet, Path: "/v1/openvpn/portforwarded"}: {},
				// GET /v1/openvpn/settings is protected by default
				{Method: http.MethodGet, Path: "/v1/dns/status"}:     {},
				{Method: http.MethodPut, Path: "/v1/dns/status"}:     {},
				{Method: http.MethodGet, Path: "/v1/updater/status"}: {},
				{Method: http.MethodPut, Path: "/v1/updater/status"}: {},
				{Method: http.MethodGet, Path: "/v1/publicip/ip"}:    {},
			},
			logger: debugLogger,
		}
	}, nil
}

type authHandler struct {
	childHandler      http.Handler
	routeToRoles      map[Route][]internalRole
	unprotectedRoutes map[Route]struct{} // TODO v3.41.0 remove
	logger            DebugLogger
}

func (h *authHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	routeKey := Route{
		Method: request.Method,
		Path:   request.URL.Path,
	}
	roles, ok := h.routeToRoles[routeKey]
	if !ok { // no role defined for this route
		h.logger.Debugf("no authentication role defined for route %s %s",
			routeKey.Method, routeKey.Path)
		http.Error(writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	for _, role := range roles {
		if !role.checker.isAuthorized(writer, request) {
			continue
		}
		if role.checker.equal(&noneMethod{}) { // TODO v3.41.0 remove
			_, isUnprotectedByDefault := h.unprotectedRoutes[routeKey]
			if isUnprotectedByDefault {
				h.logger.Warnf("route %s %s is unprotected by default, "+
					"please set up authorization following the documentation at "+
					"https://github.com/gluetun-wiki/setup/advanced/control-server.md#authorization "+
					"since this will become no longer publicly accessible after release v3.40.",
					routeKey.Method, routeKey.Path)
			}
		}

		h.logger.Debugf("access to route %s %s authorized for role %s",
			routeKey.Method, routeKey.Path, role.name)
		h.childHandler.ServeHTTP(writer, request)
		return
	}

	allRoleNames := make([]string, len(roles))
	for i, role := range roles {
		allRoleNames[i] = role.name
	}
	h.logger.Debugf("access to route %s %s unauthorized after checking for roles %s",
		routeKey.Method, routeKey.Path, andStrings(allRoleNames))
	http.Error(writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}
