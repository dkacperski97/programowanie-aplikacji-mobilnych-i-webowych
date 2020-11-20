package main

import (
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"example.com/project/handlers"
	"example.com/project/models"
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
)

func getTemplates(req *http.Request) *template.Template {
	session, err := store.Get(req, sessionName)
	if err != nil {
		log.Fatal("Failed getting session: ", err)
	}

	tmp := template.New("_func").Funcs(template.FuncMap{
		"getDate": time.Now,
		"getSession": func() *sessions.Session {
			if session.IsNew {
				return nil
			}
			return session
		},
	})
	tmp = template.Must(tmp.ParseGlob("templates/*.html"))
	return tmp
}

func index(w http.ResponseWriter, req *http.Request) {
	tmp := getTemplates(req)
	err := tmp.ExecuteTemplate(w, "index.html", nil)
	if err != nil {
		panic(err)
	}
}

type registerSenderPageData struct {
	Error error
}

func getRegisterSender(w http.ResponseWriter, req *http.Request) {
	tmp := getTemplates(req)
	err := tmp.ExecuteTemplate(w, "signUpSender.html", &registerSenderPageData{
		Error: nil,
	})
	if err != nil {
		panic(err)
	}
}

func postRegisterSender(w http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		log.Fatal(err)
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
		panic(err)
	}
	if validationErr != nil {
		tmp := getTemplates(req)
		err = tmp.ExecuteTemplate(w, "signUpSender.html", &registerSenderPageData{
			Error: validationErr,
		})
		if err != nil {
			panic(err)
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
	tmp := getTemplates(req)
	err := tmp.ExecuteTemplate(w, "loginSender.html", &registerSenderPageData{
		Error: nil,
	})
	if err != nil {
		panic(err)
	}
}

func postLoginSender(w http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		log.Fatal(err)
	}

	isValid := models.Verify(client, req.Form.Get("login"), req.Form.Get("password"))

	if !isValid {
		tmp := getTemplates(req)
		err = tmp.ExecuteTemplate(w, "loginSender.html", &registerSenderPageData{
			Error: errors.New("Niepoprawne dane logowania"),
		})
		if err != nil {
			panic(err)
		}
		return
	}

	session, err := store.Get(req, sessionName)
	if err != nil {
		log.Fatal("Failed getting session: ", err)
	}

	session.Values["user"] = req.Form.Get("login")
	session.Values["loginTime"] = time.Now()

	if err = sessions.Save(req, w); err != nil {
		log.Fatal("Failed saving session: ", err)
	}

	http.Redirect(w, req, "/", http.StatusSeeOther)
}

func logoutSender(w http.ResponseWriter, req *http.Request) {
	session, err := store.Get(req, sessionName)
	if err != nil {
		log.Fatal("Failed getting session: ", err)
	}

	session.Options.MaxAge = -1

	if err = sessions.Save(req, w); err != nil {
		log.Fatal("Failed deleting session: ", err)
	}

	http.Redirect(w, req, "/", http.StatusSeeOther)
}

type showDashboardPageData struct {
	Labels []models.Label
}

func showDashboard(w http.ResponseWriter, req *http.Request) {
	session, err := store.Get(req, sessionName)
	if err != nil {
		log.Fatal("Failed getting session: ", err)
	}
	sender, exists := session.Values["user"]
	if exists == false {
		log.Fatal("Failed getting session value")
	}
	labels, err := models.GetLabelsBySender(client, sender.(string))
	if err != nil {
		log.Fatal("Failed getting labels: ", err)
	}
	tmp := getTemplates(req)
	err = tmp.ExecuteTemplate(w, "dashboard.html", &showDashboardPageData{
		Labels: labels,
	})
	if err != nil {
		panic(err)
	}
}

type createLabelPageData struct {
	Error error
}

func getCreateLabel(w http.ResponseWriter, req *http.Request) {
	tmp := getTemplates(req)
	err := tmp.ExecuteTemplate(w, "createLabel.html", &createLabelPageData{
		Error: nil,
	})
	if err != nil {
		panic(err)
	}
}

func postCreateLabel(w http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		log.Fatal(err)
	}
	session, err := store.Get(req, sessionName)
	if err != nil {
		log.Fatal("Failed getting session: ", err)
	}
	sender, exists := session.Values["user"]
	if exists == false {
		log.Fatal("Failed getting session value")
	}
	label, validationErr, err := models.CreateLabel(
		sender.(string),
		req.Form.Get("recipient"),
		req.Form.Get("locker"),
		req.Form.Get("size"),
	)
	if err != nil {
		panic(err)
	}
	if validationErr != nil {
		tmp := getTemplates(req)
		err = tmp.ExecuteTemplate(w, "createLabel.html", &createLabelPageData{
			Error: validationErr,
		})
		if err != nil {
			panic(err)
		}
		return
	}
	label.Save(client)
	http.Redirect(w, req, "/sender/dashboard", http.StatusSeeOther)
}

func removeLabel(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	labelID := vars["labelId"]

	session, err := store.Get(req, sessionName)
	if err != nil {
		log.Fatal("Failed getting session: ", err)
	}
	sender, exists := session.Values["user"]
	if exists == false {
		log.Fatal("Failed getting session value")
	}

	err = models.RemoveLabel(
		client,
		sender.(string),
		labelID,
	)
	if err != nil {
		panic(err)
	}
	http.Redirect(w, req, "/sender/dashboard", http.StatusSeeOther)
}

func checkAvailability(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	login := vars["login"]

	numberOfKeys, err := client.Exists(context.Background(), "user:"+login).Uint64()
	if err != nil {
		panic(err)
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

func getRedisClient() *redis.Client {
	redisPort := os.Getenv("REDIS_PORT")
	if redisPort == "" {
		redisPort = "6379"
	}
	redisHost := os.Getenv("REDIS_HOST")
	if redisHost == "" {
		redisHost = "localhost"
	}
	return redis.NewClient(&redis.Options{
		Addr:     redisHost + ":" + redisPort,
		Password: "",
		DB:       0,
	})
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	client = getRedisClient()
	defer client.Close()

	store, err = redisstore.NewRedisStore(context.Background(), client)
	if err != nil {
		log.Fatal("Failed to create redis store: ", err)
	}
	sessionName = os.Getenv("SESSION_NAME")
	if sessionName == "" {
		sessionName = "session"
	}
	gob.Register(&time.Time{})

	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	r := mux.NewRouter()
	r.HandleFunc("/", index)
	r.HandleFunc("/sender/register", getRegisterSender).Methods("GET")
	r.HandleFunc("/sender/register", postRegisterSender).Methods("POST")
	r.HandleFunc("/sender/login", getLoginSender).Methods("GET")
	r.HandleFunc("/sender/login", postLoginSender).Methods("POST")
	r.HandleFunc("/sender/logout", logoutSender)
	r.Handle("/sender/dashboard", handlers.SessionHandler(store, sessionName, http.HandlerFunc(showDashboard)))
	r.Handle("/sender/labels/create", handlers.SessionHandler(store, sessionName, http.HandlerFunc(getCreateLabel))).Methods("GET")
	r.Handle("/sender/labels/create", handlers.SessionHandler(store, sessionName, http.HandlerFunc(postCreateLabel))).Methods("POST")
	r.Handle("/sender/labels/{labelId}/remove", handlers.SessionHandler(store, sessionName, http.HandlerFunc(removeLabel))).Methods("POST")
	r.HandleFunc("/check/{login}", checkAvailability)
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
