package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"example.com/project/handlers"
	"example.com/project/helpers"
	"example.com/project/models"
	"github.com/coreos/go-oidc"
	sharedModels "github.com/dkacperski97/programowanie-aplikacji-mobilnych-i-webowych-models"
	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"github.com/rbcervilla/redisstore/v8"
)

var (
	client      *redis.Client
	store       *redisstore.RedisStore
	sessionName string
	jwtSecret   []byte
)

func getSession(req *http.Request) *sessions.Session {
	session, err := store.Get(req, sessionName)
	if err != nil {
		return nil
	}
	return session
}

func setAuthorizationHeader(req *http.Request, session *sessions.Session) {
	if session != nil && !session.IsNew && session.Values["token"] != nil {
		req.Header.Set("Authorization", "Bearer "+session.Values["token"].(string))
	}
}

func getLinks(session *sessions.Session) map[string]interface{} {
	var links map[string]interface{}
	request, err := http.NewRequest(http.MethodGet, os.Getenv("WEB_SERVICE_URL"), nil)
	if err == nil {
		setAuthorizationHeader(request, session)
		httpClient := &http.Client{}
		resp, err := httpClient.Do(request)
		if err == nil {
			var result map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&result)
			var ok bool
			links, ok = result["_links"].(map[string]interface{})
			if !ok {
				err = errors.New("_links is undefined")
			}
		}
	}

	if err != nil {
		return nil
	}
	return links
}

func getTemplates(session *sessions.Session, links map[string]interface{}) *template.Template {
	tmp := template.New("_func").Funcs(template.FuncMap{
		"getDate": time.Now,
		"getSession": func() *sessions.Session {
			if session.IsNew {
				return nil
			}
			return session
		},
		"getLinks": func() map[string]interface{} {
			return links
		},
	})
	tmp = template.Must(tmp.ParseGlob("templates/*.html"))
	return tmp
}

func getPageData(req *http.Request) (*sessions.Session, map[string]interface{}, *template.Template) {
	session := getSession(req)
	links := getLinks(session)
	tmp := getTemplates(session, links)
	return session, links, tmp
}

func index(w http.ResponseWriter, req *http.Request) {
	_, _, tmp := getPageData(req)
	err := tmp.ExecuteTemplate(w, "index.html", nil)
	if err != nil {
		handleError(w, req, http.StatusInternalServerError)
	}
}

type registerSenderPageData struct {
	Error error
}

func getRegisterSender(w http.ResponseWriter, req *http.Request) {
	_, _, tmp := getPageData(req)
	err := tmp.ExecuteTemplate(w, "signUpSender.html", &registerSenderPageData{
		Error: nil,
	})
	if err != nil {
		handleError(w, req, http.StatusInternalServerError)
	}
}

func postRegisterSender(w http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}

	user, validationErr, err := models.CreateUser(
		req.Form.Get("login"),
		req.Form.Get("password"),
		req.Form.Get("email"),
		req.Form.Get("firstname"),
		req.Form.Get("lastname"),
		req.Form.Get("address"),
	)
	if err != nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}
	if validationErr != nil {
		_, _, tmp := getPageData(req)
		err = tmp.ExecuteTemplate(w, "signUpSender.html", &registerSenderPageData{
			Error: validationErr,
		})
		if err != nil {
			handleError(w, req, http.StatusInternalServerError)
		}
		return
	}
	user.Save(client)
	http.Redirect(w, req, "/sender/login", http.StatusSeeOther)
}

type loginSenderPageData struct {
	Error error
}

func getLoginSender(w http.ResponseWriter, req *http.Request) {
	_, _, tmp := getPageData(req)
	err := tmp.ExecuteTemplate(w, "loginSender.html", &registerSenderPageData{
		Error: nil,
	})
	if err != nil {
		handleError(w, req, http.StatusInternalServerError)
	}
}

func postLoginSender(w http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}

	isValid, err := models.Verify(client, req.Form.Get("login"), req.Form.Get("password"))
	if err != nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}

	if !isValid {
		_, _, tmp := getPageData(req)
		err = tmp.ExecuteTemplate(w, "loginSender.html", &registerSenderPageData{
			Error: errors.New("Niepoprawne dane logowania"),
		})
		if err != nil {
			handleError(w, req, http.StatusInternalServerError)
		}
		return
	}

	session := getSession(req)
	if session == nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}

	session.Values["user"] = req.Form.Get("login")
	session.Values["loginTime"] = time.Now()

	session.Values["token"], err = helpers.GetSenderToken(req.Form.Get("login"), jwtSecret)
	if err != nil || session.Values["token"] == nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}
	authorizationCookieValue := "Authorization=Bearer " + session.Values["token"].(string) + "; Path=/; Max-Age=86400"
	if os.Getenv("SECURE_COOKIE") == "TRUE" {
		authorizationCookieValue += "; Secure"
	}
	w.Header().Set("Set-Cookie", authorizationCookieValue)

	if err = sessions.Save(req, w); err != nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}

	http.Redirect(w, req, "/", http.StatusSeeOther)
}

func logoutSender(w http.ResponseWriter, req *http.Request) {
	session := getSession(req)
	if session == nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}

	isAuthUser := session.Values["profile"] != nil

	session.Options.MaxAge = -1

	if err := sessions.Save(req, w); err != nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Set-Cookie", "Authorization=; Max-Age=-1")

	if isAuthUser {
		http.Redirect(w, req, "/auth/logout", http.StatusSeeOther)
	}

	http.Redirect(w, req, "/", http.StatusSeeOther)
}

func getLink(links map[string]interface{}, name string) (string, error) {
	link, exists := links[name].(map[string]interface{})
	if exists == false {
		return "", errors.New(name + " is undefined")
	}
	url, exists := link["href"].(string)
	if exists == false {
		return "", errors.New(name + " is undefined")
	}
	return url, nil
}

type showDashboardPageData struct {
	Labels []interface{}
}

func showDashboard(w http.ResponseWriter, req *http.Request) {
	session, links, tmp := getPageData(req)
	if session == nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}

	labelsURL, err := getLink(links, "labels")
	if err != nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}

	request, err := http.NewRequest(http.MethodGet, os.Getenv("WEB_SERVICE_URL")+labelsURL, nil)
	if err != nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}
	setAuthorizationHeader(request, session)
	httpClient := &http.Client{}
	resp, err := httpClient.Do(request)
	if err != nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	resources, ok := result["_embedded"].(map[string]interface{})
	if !ok {
		handleError(w, req, http.StatusInternalServerError)
		return
	}
	labels, ok := resources["labels"].([]interface{})
	if !ok {
		handleError(w, req, http.StatusInternalServerError)
		return
	}

	err = tmp.ExecuteTemplate(w, "dashboard.html", &showDashboardPageData{
		Labels: labels,
	})
	if err != nil {
		handleError(w, req, http.StatusInternalServerError)
	}
}

type createLabelPageData struct {
	Error error
}

func getCreateLabel(w http.ResponseWriter, req *http.Request) {
	_, _, tmp := getPageData(req)
	err := tmp.ExecuteTemplate(w, "createLabel.html", &createLabelPageData{
		Error: nil,
	})
	if err != nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}
}

func postCreateLabel(w http.ResponseWriter, req *http.Request) {
	session, links, tmp := getPageData(req)
	if session == nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}
	err := req.ParseForm()
	if err != nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}
	sender, exists := session.Values["user"]
	if exists == false {
		handleError(w, req, http.StatusInternalServerError)
		return
	}
	label, validationErr, err := sharedModels.CreateLabel(
		sender.(string),
		req.Form.Get("recipient"),
		req.Form.Get("locker"),
		req.Form.Get("size"),
	)
	if err != nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}
	if validationErr != nil {
		err = tmp.ExecuteTemplate(w, "createLabel.html", &createLabelPageData{
			Error: validationErr,
		})
		if err != nil {
			handleError(w, req, http.StatusInternalServerError)
		}
		return
	}
	labelsLink, exists := links["labels"].(map[string]interface{})
	if exists == false {
		handleError(w, req, http.StatusInternalServerError)
		return
	}
	labelsURL, exists := labelsLink["href"].(string)
	if exists == false {
		handleError(w, req, http.StatusInternalServerError)
		return
	}

	body, err := json.Marshal(label)
	if err != nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}

	request, err := http.NewRequest(http.MethodPost, os.Getenv("WEB_SERVICE_URL")+labelsURL, bytes.NewBuffer(body))
	request.Header.Set("Content-type", "application/json")
	if err != nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}
	setAuthorizationHeader(request, session)
	httpClient := &http.Client{}
	resp, err := httpClient.Do(request)
	if err != nil || resp.StatusCode != http.StatusCreated {
		handleError(w, req, http.StatusInternalServerError)
		return
	}
	http.Redirect(w, req, "/sender/dashboard", http.StatusSeeOther)
}

func removeLabel(w http.ResponseWriter, req *http.Request) {
	session := getSession(req)
	if session == nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}
	err := req.ParseForm()
	if err != nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}

	request, err := http.NewRequest(http.MethodDelete, os.Getenv("WEB_SERVICE_URL")+req.Form.Get("labelUrl"), nil)
	if err != nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}
	setAuthorizationHeader(request, session)
	httpClient := &http.Client{}
	resp, err := httpClient.Do(request)
	if err != nil || resp.StatusCode != http.StatusOK {
		handleError(w, req, http.StatusInternalServerError)
		return
	}

	http.Redirect(w, req, "/sender/dashboard", http.StatusSeeOther)
}

func checkAvailability(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	login := vars["login"]

	numberOfKeys, err := client.Exists(context.Background(), "user:"+login).Uint64()
	if err != nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}
	loginAvailability := "available"
	if numberOfKeys != 0 {
		loginAvailability = "taken"
	}
	data := map[string]interface{}{
		login: loginAvailability,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func getWebSocket(w http.ResponseWriter, req *http.Request) {
	if os.Getenv("PORT") == "" {
		handleError(w, req, http.StatusInternalServerError)
		return
	}
	data := map[string]interface{}{
		"url": os.Getenv("NOTIFICATION_SERVICE_URL"),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func authCallback(w http.ResponseWriter, req *http.Request) {
	session := getSession(req)
	if session == nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}

	if req.URL.Query().Get("state") != session.Values["state"] {
		handleError(w, req, http.StatusBadRequest)
		return
	}

	authenticator, err := models.NewAuthenticator()
	if err != nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}

	token, err := authenticator.Config.Exchange(context.Background(), req.URL.Query().Get("code"))
	if err != nil {
		handleError(w, req, http.StatusUnauthorized)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		handleError(w, req, http.StatusInternalServerError)
		return
	}

	oidcConfig := &oidc.Config{
		ClientID: os.Getenv("AUTH0_CLIENT_ID"),
	}

	idToken, err := authenticator.Provider.Verifier(oidcConfig).Verify(context.Background(), rawIDToken)
	if err != nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}

	var profile map[string]interface{}
	if err := idToken.Claims(&profile); err != nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}

	session.Values["user"] = profile["sub"]
	session.Values["loginTime"] = time.Now()
	session.Values["state"] = nil
	session.Values["token"], err = helpers.GetSenderToken(profile["sub"].(string), jwtSecret)

	if err != nil || session.Values["token"] == nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}
	authorizationCookieValue := "Authorization=Bearer " + session.Values["token"].(string) + "; Path=/; Max-Age=86400"
	if os.Getenv("SECURE_COOKIE") == "TRUE" {
		authorizationCookieValue += "; Secure"
	}
	w.Header().Set("Set-Cookie", authorizationCookieValue)

	session.Values["profile"] = profile
	if err = sessions.Save(req, w); err != nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}

	http.Redirect(w, req, "/", http.StatusSeeOther)
}

func authLogin(w http.ResponseWriter, req *http.Request) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}
	state := base64.StdEncoding.EncodeToString(b)

	session := getSession(req)
	if session == nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}
	session.Values["state"] = state
	err = session.Save(req, w)
	if err != nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}

	authenticator, err := models.NewAuthenticator()
	if err != nil {
		handleError(w, req, http.StatusInternalServerError)
		return
	}

	http.Redirect(w, req, authenticator.Config.AuthCodeURL(state), http.StatusTemporaryRedirect)
}

func authLogout(w http.ResponseWriter, req *http.Request) {
	logoutURL, err := url.Parse(os.Getenv("AUTH0_DOMAIN"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	logoutURL.Path += "/v2/logout"
	returnToURL, err := url.Parse(os.Getenv("AUTH0_RETURN_TO_URL"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	parameters := url.Values{}
	parameters.Add("returnTo", returnToURL.String())
	parameters.Add("client_id", os.Getenv("AUTH0_CLIENT_ID"))
	logoutURL.RawQuery = parameters.Encode()

	http.Redirect(w, req, logoutURL.String(), http.StatusTemporaryRedirect)
}

type handleErrorPageData struct {
	StatusCode int
	StatusText string
}

func handleError(w http.ResponseWriter, req *http.Request, code int) {
	w.WriteHeader(code)
	_, _, tmp := getPageData(req)
	err := tmp.ExecuteTemplate(w, "error.html", &handleErrorPageData{
		StatusCode: code,
		StatusText: http.StatusText(code),
	})
	if err != nil {
		fmt.Fprintln(w, http.StatusText(http.StatusInternalServerError))
		return
	}
}

func getRedisClient() *redis.Client {
	redisPort := os.Getenv("REDIS_PORT")
	if redisPort == "" {
		redisPort = "6379"
	}
	redisHost := os.Getenv("REDIS_HOST")
	if redisHost == "" {
		redisHost = "localhost"
	}
	redisPass := os.Getenv("REDIS_PASS")
	redisDbString := os.Getenv("REDIS_DB")
	redisDb, err := strconv.Atoi(redisDbString)
	if err != nil {
		redisDb = 0
	}
	return redis.NewClient(&redis.Options{
		Addr:     redisHost + ":" + redisPort,
		Password: redisPass,
		DB:       redisDb,
	})
}

func main() {
	err := godotenv.Load()
	if err == nil {
		log.Print(".env file loaded")
	}

	client = getRedisClient()
	defer client.Close()

	store, err = redisstore.NewRedisStore(context.Background(), client)
	if err != nil {
		log.Print("Failed to create redis store: ", err)
	}
	var secureCookie bool
	if os.Getenv("SECURE_COOKIE") == "" || os.Getenv("SECURE_COOKIE") == "FALSE" {
		secureCookie = false
	} else {
		secureCookie = true
	}
	store.Options(sessions.Options{
		Secure:   secureCookie,
		HttpOnly: true,
		Path:     "/",
		MaxAge:   60 * 60 * 24,
	})
	sessionName = os.Getenv("SESSION_NAME")
	if sessionName == "" {
		sessionName = "session"
	}
	jwtSecret = []byte(os.Getenv("JWT_SECRET"))
	gob.Register(&time.Time{})
	gob.Register(&map[string]interface{}{})

	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	r := mux.NewRouter()
	r.HandleFunc("/", index)
	r.Handle("/sender/register", handlers.WithoutSessionHandler(store, sessionName, http.HandlerFunc(getRegisterSender), handleError)).Methods(http.MethodGet)
	r.Handle("/sender/register", handlers.WithoutSessionHandler(store, sessionName, http.HandlerFunc(postRegisterSender), handleError)).Methods(http.MethodPost)
	r.Handle("/sender/login", handlers.WithoutSessionHandler(store, sessionName, http.HandlerFunc(getLoginSender), handleError)).Methods(http.MethodGet)
	r.Handle("/sender/login", handlers.WithoutSessionHandler(store, sessionName, http.HandlerFunc(postLoginSender), handleError)).Methods(http.MethodPost)
	r.Handle("/sender/logout", handlers.SessionHandler(store, sessionName, http.HandlerFunc(logoutSender), handleError))
	r.Handle("/sender/dashboard", handlers.SessionHandler(store, sessionName, http.HandlerFunc(showDashboard), handleError))
	r.Handle("/sender/labels/create", handlers.SessionHandler(store, sessionName, http.HandlerFunc(getCreateLabel), handleError)).Methods(http.MethodGet)
	r.Handle("/sender/labels/create", handlers.SessionHandler(store, sessionName, http.HandlerFunc(postCreateLabel), handleError)).Methods(http.MethodPost)
	r.Handle("/sender/labels/{labelId}/remove", handlers.SessionHandler(store, sessionName, http.HandlerFunc(removeLabel), handleError)).Methods(http.MethodPost)
	r.HandleFunc("/ws-url", getWebSocket).Methods(http.MethodGet)
	r.HandleFunc("/check/{login}", checkAvailability)
	r.Handle("/auth/callback", handlers.WithoutSessionHandler(store, sessionName, http.HandlerFunc(authCallback), handleError)).Methods(http.MethodGet)
	r.Handle("/auth/login", handlers.WithoutSessionHandler(store, sessionName, http.HandlerFunc(authLogin), handleError)).Methods(http.MethodGet)
	r.Handle("/auth/logout", handlers.WithoutSessionHandler(store, sessionName, http.HandlerFunc(authLogout), handleError)).Methods(http.MethodGet)
	http.Handle("/", r)

	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
	}

	s := &http.Server{
		Addr:    ":" + port,
		Handler: nil,
	}

	log.Println("Listening on :" + port + " ...")
	err = s.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
