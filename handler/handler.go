package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/AdeleRICHARD/database"
	"golang.org/x/crypto/bcrypt"
)

type ApiCfg struct {
	fileserverHits int
	JwtSecret      string
}

type responseBody struct {
	ID   int    `json:"id"`
	Body string `json:"body"`
}

type responseBodyUser struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
}

func (cfg *ApiCfg) MiddlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits++
		next.ServeHTTP(w, r)
	})
}

func (cfg *ApiCfg) MetricsHandler(w http.ResponseWriter, _ *http.Request) {

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

func (cfg *ApiCfg) ResetHandler(w http.ResponseWriter, _ *http.Request) {
	cfg.fileserverHits = 0
	w.Write([]byte("OK"))
	w.WriteHeader(200)
}

func (cfg *ApiCfg) CreateChirps(w http.ResponseWriter, r *http.Request) {
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

func (cfg *ApiCfg) GetChirps(w http.ResponseWriter, r *http.Request) {
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

func (cfg *ApiCfg) GetChirpFromID(w http.ResponseWriter, r *http.Request) {
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

func (cfg *ApiCfg) CreateUsers(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	msg, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithError(w, 500, "Something went wrong")
		return
	}

	type requestBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	params := requestBody{}
	err = json.Unmarshal(msg, &params)
	if err != nil {
		respondWithError(w, 500, "Something went wrong")
		return
	}

	pwdEncrypted, err := bcrypt.GenerateFromPassword([]byte(params.Password), 4)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("An error happened while encrypting %v", err))
	}
	db, err := database.NewDB("database.json")
	if err != nil {
		fmt.Println("Impossible to create db: ", err)
		return
	}

	user, err := db.CreateUser(params.Email, pwdEncrypted)
	if err != nil {
		fmt.Println("Could not create user 0", err)
		return
	}

	respondWithJson(w, 201, responseBodyUser{
		ID:    user.ID,
		Email: params.Email,
	})
}

func (cfg *ApiCfg) Login(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	msg, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithError(w, 500, "Something went wrong")
		return
	}

	type requestBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	params := requestBody{}
	err = json.Unmarshal(msg, &params)
	if err != nil {
		respondWithError(w, 500, "Something went wrong")
		return
	}

	db, err := database.NewDB("database.json")
	if err != nil {
		fmt.Println("Impossible to create db: ", err)
		return
	}

	user, err := db.GetUser(params.Password)
	if err != nil {
		respondWithError(w, 401, "Unauthorized")
	}

	respondWithJson(w, 200, responseBodyUser{
		ID:    user.ID,
		Email: user.Email,
	})
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
