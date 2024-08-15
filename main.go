package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/AdeleRICHARD/handler"
)

func main() {
	httpMux := http.NewServeMux()
	apiCfg := handler.ApiCfg{}

	// Logger config to write in stdout
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Properly wrap the file server with middleware
	fileServer := http.StripPrefix("/app", http.FileServer(http.Dir(".")))
	httpMux.Handle("/app/", apiCfg.MiddlewareMetricsInc(fileServer))

	// Register other handlers directly
	httpMux.Handle("/assets/", http.StripPrefix("/assets", http.FileServer(http.Dir("assets"))))
	httpMux.HandleFunc("GET /admin/metrics", apiCfg.MetricsHandler)

	httpMux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	})

	httpMux.HandleFunc("POST /api/chirps", apiCfg.CreateChirps)
	httpMux.HandleFunc("GET /api/chirps", apiCfg.GetChirps)
	httpMux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.GetChirpFromID)

	httpMux.HandleFunc("POST /api/users", apiCfg.CreateUsers)
	httpMux.HandleFunc("POST /api/login", apiCfg.Login)

	httpMux.HandleFunc("/api/reset", apiCfg.ResetHandler)

	// Start the server
	serve := http.Server{
		Handler: httpMux,
		Addr:    ":8080",
	}

	err := serve.ListenAndServe()
	if err != nil {
		fmt.Println("Server failed to start:", err)
	}
}
