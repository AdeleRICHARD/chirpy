package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/AdeleRICHARD/database"
)

func main() {
	httpMux := http.NewServeMux()

	// Create your apiConfig instance
	apiCfg := &apiConfig{}

	// Configurer le logger pour écrire sur stderr
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Properly wrap the file server with middleware
	fileServer := http.StripPrefix("/app", http.FileServer(http.Dir(".")))
	httpMux.Handle("/app/", apiCfg.middlewareMetricsInc(fileServer))

	// Register other handlers directly
	httpMux.Handle("/assets/", http.StripPrefix("/assets", http.FileServer(http.Dir("assets"))))
	httpMux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandler)

	httpMux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	})

	httpMux.HandleFunc("POST /api/chirps", apiCfg.CreateChirps)
	httpMux.HandleFunc("GET /api/chirps", apiCfg.GetChirps)
	httpMux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirpFromID)

	httpMux.HandleFunc("/api/reset", apiCfg.resetHandler)

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

type responseBody struct {
	ID   int    `json:"id"`
	Body string `json:"body"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits++
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, r *http.Request) {

	htmlTemplate := `
<!DOCTYPE html>
<html>
<head>
    <title>Welcome</title>
</head>
<body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
</body>
</html>`

	htmlAdmin := fmt.Sprintf(htmlTemplate, cfg.fileserverHits)

	w.Write([]byte(htmlAdmin))
	w.WriteHeader(http.StatusOK)
	w.Header().Add("Content-Type", "text/html")
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits = 0
	w.Write([]byte("OK"))
	w.WriteHeader(200)
}

func (cfg *apiConfig) CreateChirps(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	msg, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithError(w, 500, "Something went wrong")
		return
	}

	type requestBody struct {
		Body string `json:"body"`
	}

	params := requestBody{}
	err = json.Unmarshal(msg, &params)
	if err != nil {
		respondWithError(w, 500, "Something went wrong")
		return
	}

	if len(params.Body) > 140 {
		respondWithError(w, 400, "Chirp is too long")
		return
	}

	db, err := database.NewDB("database.json")
	if err != nil {
		fmt.Println("Impossible to create db: ", err)
		return
	}

	chirp, err := db.CreateChirp(params.Body)
	if err != nil {
		fmt.Println("Could not create chirp ", err)
		return
	}

	respondWithJson(w, 201, responseBody{
		ID:   chirp.ID,
		Body: params.Body,
	})
}

func (cfg *apiConfig) GetChirps(w http.ResponseWriter, r *http.Request) {
	db, err := database.NewDB("database.json")
	if err != nil {
		fmt.Println("Impossible to get db: ", err)
		return
	}

	if chirps, err := db.GetChirps(); err == nil {
		respondWithJson(w, 200, chirps)
		return
	}

	respondWithError(w, 410, "no chirps found in the database")
}

func (cfg *apiConfig) getChirpFromID(w http.ResponseWriter, r *http.Request) {
	db, err := database.NewDB("database.json")
	if err != nil {
		fmt.Println("Impossible to get db: ", err)
		return
	}

	chirpID := r.PathValue("chirpID")

	if chirp, err := db.GetChirp(chirpID); err == nil {
		respondWithJson(w, 200, chirp)
		return
	}

	respondWithError(w, 404, fmt.Sprintf("no chirp found in the database for this id : %s", chirpID))
}

func respondWithJson(w http.ResponseWriter, code int, payload interface{}) error {
	response, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control'Allow-Origin", "*")
	w.WriteHeader(code)
	w.Write(response)
	return nil
}

func respondWithError(w http.ResponseWriter, code int, msg string) error {
	return respondWithJson(w, code, map[string]string{"error": msg})
}

func removeBadWords(sentence string) (string, bool) {
	var isCleaned []bool
	badWords := []string{"kerfuffle", "sharbert", "fornax"}
	for _, word := range strings.Split(sentence, " ") {
		wordLower := strings.ToLower(word)
		if slices.Contains(badWords, wordLower) {
			sentence = strings.ReplaceAll(sentence, word, "****")
			isCleaned = append(isCleaned, true)
		}
	}

	if slices.Contains(isCleaned, true) {
		return sentence, true
	}

	return sentence, false
}
