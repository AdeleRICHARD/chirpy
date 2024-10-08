package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/AdeleRICHARD/handler"
	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load()
	jwtSecret := os.Getenv("JWT_SECRET")
	polkaKey := os.Getenv("POLKA_KEY")

	httpMux := http.NewServeMux()
	apiCfg := handler.ApiCfg{
		JwtSecret: []byte(jwtSecret),
		PolkaKey:  polkaKey,
	}

	dbg := flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()
	if *dbg {
		if err := os.Remove(handler.DB_PATH); err != nil {
			log.Fatal("error when deleting database")
		}
	}

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

	httpMux.HandleFunc("POST /admin/reset", apiCfg.DeleteAllUsers)

	httpMux.HandleFunc("POST /api/chirps", apiCfg.CreateChirps)
	httpMux.HandleFunc("GET /api/chirps", apiCfg.GetChirps)
	httpMux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.GetChirpFromID)
	httpMux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.DeleteChirpFromID)

	httpMux.HandleFunc("POST /api/users", apiCfg.CreateUsers)
	httpMux.HandleFunc("POST /api/login", apiCfg.Login)
	httpMux.HandleFunc("PUT /api/users", apiCfg.UpdateUsers)

	httpMux.HandleFunc("POST /api/refresh", apiCfg.RefreshToken)
	httpMux.HandleFunc("POST /api/revoke", apiCfg.RevokeToken)

	httpMux.HandleFunc("POST /api/polka/webhooks", apiCfg.HandleWebhook)

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
