package main

import (
	"fmt"
	"net/http"
)

func main() {
	httpMux := http.NewServeMux()

	// Create your apiConfig instance
	apiCfg := &apiConfig{}

	// Properly wrap the file server with middleware
	fileServer := http.StripPrefix("/app", http.FileServer(http.Dir(".")))
	httpMux.Handle("/app/", apiCfg.middlewareMetricsInc(fileServer))

	// Register other handlers directly
	httpMux.Handle("/assets/", http.StripPrefix("/assets", http.FileServer(http.Dir("assets"))))
	httpMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	})

	httpMux.HandleFunc("/metrics", apiCfg.metricsHandler)
	httpMux.HandleFunc("/reset", apiCfg.resetHandler)

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

type apiConfig struct {
	fileserverHits int
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits++
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, r *http.Request) {
	hitsResp := fmt.Sprintf("Hits: %d\n", cfg.fileserverHits)
	w.Write([]byte(hitsResp))
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits = 0
	w.Write([]byte("OK"))
	w.WriteHeader(200)
}
