package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strconv"

	controllerHkp "hkp-clavis/internal/controller/hkp"
	"hkp-clavis/internal/model"
	"hkp-clavis/internal/repo/storage/postgresql"
	storageService "hkp-clavis/internal/service/storage/serv"

	hkp "github.com/emersion/go-openpgp-hkp"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/lmittmann/tint"
)

var Logger *slog.Logger

func main() {

	Logger = slog.New(tint.NewHandler(os.Stdout, nil))

	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, reading from system environment")
	}

	listenAddress := os.Getenv("LISTEN_ADDRESS")
	listenPort := os.Getenv("LISTEN_PORT")

	listenAddress = fmt.Sprintf("%s:%s", listenAddress, listenPort)

	pgUser := os.Getenv("POSTGRES_USER")
	pgPassword := os.Getenv("POSTGRES_PASSWORD")
	pgAddress := os.Getenv("POSTGRES_ADDRESS")
	pgPort := os.Getenv("POSTGRES_PORT")
	pgDatabase := os.Getenv("POSTGRES_DATABASE")

	// By default all uids in key does not verify
	// For dev/debug you can set it to true
	verify := os.Getenv("VERIFY_DEFAULT")
	defaultVerify := getEnvAsBool(verify, true)

	pgUri := fmt.Sprintf(
		"postgresql://%s:%s@%s:%s/%s",
		pgUser,
		pgPassword,
		pgAddress,
		pgPort,
		pgDatabase)

	// For memory allocation controller
	keyMngr := model.NewKeyManager()

	dbpool, err := pgxpool.New(context.TODO(), pgUri)
	if err != nil {
		panic(err)
	}

	db := postgresql.New(context.TODO(), dbpool, keyMngr)
	storage := storageService.New(db, keyMngr, defaultVerify)

	controller, err := controllerHkp.New(storage)
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	hkpHandler := hkp.Handler{
		Adder:    controller,
		Lookuper: controller,
	}
	mux.HandleFunc("/pks/lookup", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pgp-keys")
		w.Header().Set("Connection", "close")
		w.Header().Set("Cache-Control", "no-cache")

		hkpHandler.ServeHTTP(w, r)
	})
	mux.HandleFunc("/pks/add", func(w http.ResponseWriter, r *http.Request) {
		hkpHandler.ServeHTTP(w, r)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Index Page")
	})

	handler := LogMiddleware(mux)

	Logger.Info("Server is listening on address: %s", handler)
	http.ListenAndServe(listenAddress, handler)
}

func getEnvAsBool(name string, defaultVal bool) bool {
	valStr, exists := os.LookupEnv(name) // Use LookupEnv for better checking
	if !exists || valStr == "" {
		return defaultVal
	}
	if val, err := strconv.ParseBool(valStr); err == nil {
		return val
	}
	return defaultVal
}
