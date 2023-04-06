package web3authgw

import (
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/golang-jwt/jwt"
)

type ProxyHandler struct {
	cfg   *Config
	proxy map[string]*httputil.ReverseProxy
}

func NewProxyHandler(cfg *Config) *ProxyHandler {
	hostProxy := map[string]*httputil.ReverseProxy{}
	for k, v := range cfg.HostMapping {
		url, err := url.Parse(v)
		if err != nil {
			panic("host url error: " + err.Error())
		}
		proxy := httputil.NewSingleHostReverseProxy(url)
		hostProxy[k] = proxy
	}
	return &ProxyHandler{
		cfg:   cfg,
		proxy: hostProxy,
	}
}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	redirect := func() {
		w.Header().Add("Location", RouterLogin+"?redirect="+r.URL.Path)
		w.WriteHeader(http.StatusFound)
	}
	host := r.Host
	if fn, ok := h.proxy[host]; ok {
		tokenCookie, err := r.Cookie(TokenCookieName)
		if err != nil {
			if err == http.ErrNoCookie {
				redirect()
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		tokenStr := tokenCookie.Value
		claims := &Claims{}

		jwtToken, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
			return []byte(h.cfg.NoncePassword), nil
		})
		if err != nil || !jwtToken.Valid {
			redirect()
			return
		}
		w.Header().Add("Web3-User-Id", claims.Pubkey)
		w.Header().Add("Web3-User-Name", h.cfg.PublicKey2Name[claims.Pubkey])
		fn.ServeHTTP(w, r)
		return
	}
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(host + " not a valid host"))
}
