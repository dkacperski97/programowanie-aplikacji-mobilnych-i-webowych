package handlers

import (
	"net/http"

	"github.com/rbcervilla/redisstore/v8"
)

type sessionHandler struct {
	store       *redisstore.RedisStore
	sessionName string
	handler     http.Handler
	eh          func(w http.ResponseWriter, req *http.Request, code int)
}

func (h sessionHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	session, err := h.store.Get(req, h.sessionName)
	if err != nil {
		h.eh(w, req, http.StatusInternalServerError)
		return
	}

	if session.IsNew || session.Values["user"] == "" {
		http.Redirect(w, req, "/sender/login", http.StatusSeeOther)
		return
	}

	h.handler.ServeHTTP(w, req)
}

// SessionHandler return a http.Handler that wraps h and checks if the session is available
func SessionHandler(store *redisstore.RedisStore, sessionName string, h http.Handler, eh func(w http.ResponseWriter, req *http.Request, code int)) http.Handler {
	return sessionHandler{store, sessionName, h, eh}
}

type withoutSessionHandler struct {
	store       *redisstore.RedisStore
	sessionName string
	handler     http.Handler
	eh          func(w http.ResponseWriter, req *http.Request, code int)
}

func (h withoutSessionHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	session, err := h.store.Get(req, h.sessionName)
	if err != nil {
		h.eh(w, req, http.StatusInternalServerError)
		return
	}

	if session.IsNew || session.Values["user"] == nil {
		h.handler.ServeHTTP(w, req)
		return
	}

	http.Redirect(w, req, "/", http.StatusSeeOther)
}

// SessionHandler return a http.Handler that wraps h and checks if the session is not available
func WithoutSessionHandler(store *redisstore.RedisStore, sessionName string, h http.Handler, eh func(w http.ResponseWriter, req *http.Request, code int)) http.Handler {
	return withoutSessionHandler{store, sessionName, h, eh}
}
