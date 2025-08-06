package main

import (
	"context"
	"fmt"
	"net/http"

	"gadrid/internal/repo/storage/postgresql"
	storageService "gadrid/internal/service/storage/serv"

	hkp "github.com/emersion/go-openpgp-hkp"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	listenAddress = "localhost:8181"
)

func main() {

	dbpool, err := pgxpool.New(context.TODO(), "postgresql://test_user:test_password@localhost:5433/test_hagrid_db")
	if err != nil {
		panic(err)
	}

	dbRepo := postgresql.New(context.TODO(), dbpool)
	storageService := storageService.New(dbRepo)

	handler := hkp.Handler{
		Adder:    storageService,
		Lookuper: storageService,
	}

	http.HandleFunc("/pks/lookup", func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	})
	http.HandleFunc("/pks/add", func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Index Page")
	})
	fmt.Println("Server is listening on address:", listenAddress)
	http.ListenAndServe(listenAddress, nil)
}
