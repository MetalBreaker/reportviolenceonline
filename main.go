package main

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"simpleserver/templates"
	"strings"
	"time"

	"github.com/go-chi/chi/middleware"

	"github.com/alexedwards/scs"
	"github.com/go-chi/chi"
	_ "github.com/lib/pq"
)

var counter int
var fs http.FileSystem
var router *chi.Mux
var db *sql.DB
var dberr error
var sessionManager *scs.Manager

func fsHandler(w http.ResponseWriter, req *http.Request) {
	file := path.Clean(chi.URLParam(req, "*"))
	fileServer := http.FileServer(fs)
	_, err := fs.Open(file)
	// Check if file exists and/or if we have permission to access it
	if err != nil || strings.HasSuffix(file, "/") {
		router.NotFoundHandler().ServeHTTP(w, req)
		return
	}
	fileServer.ServeHTTP(w, req)
}

func main() {
	sessionManager.Lifetime(time.Hour)
	sessionManager.Secure(true)
	if _, err := os.Stat("../cookiestorage.txt"); os.IsNotExist(err) {
		ioutil.WriteFile("../cookiestorage.txt", []byte(randomASCII(32, 32)), 0640)
	}
	cookiekey, _ := ioutil.ReadFile("../cookiestorage.txt")
	sessionManager = scs.NewCookieManager(string(cookiekey))

	db, dberr = sql.Open("postgres", "connString")
	if dberr != nil {
		panic(dberr.Error())
	}
	defer db.Close()

	initializeDB(db)

	adminuser, adminpass := addSuperuser(db)
	fmt.Println("Superuser username: " + adminuser)
	fmt.Println("Superuser password: " + adminpass)

	router = chi.NewRouter()
	router.Use(middleware.Recoverer)

	fs = http.FileSystem(http.Dir("public"))
	router.Get("/", func(w http.ResponseWriter, req *http.Request) {
		p := &templates.MainPage{}
		templates.WritePageTemplate(w, p, []string{"333"})
	})

	router.Get("/*", fsHandler)

	if err := http.ListenAndServeTLS(":8080", "crtPath", "keyPath", router); err != nil {
		panic(err)
	}
}
