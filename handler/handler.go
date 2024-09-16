package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/AdeleRICHARD/database"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const DB_PATH string = "database.json"

type ApiCfg struct {
	fileserverHits int
	JwtSecret      []byte
}

type responseBody struct {
	ID   int    `json:"id"`
	Body string `json:"body"`
}

type responseBodyUser struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
	Token string `json:"token,omitempty"`
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

	db, err := database.NewDB(DB_PATH)
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
	db, err := database.NewDB(DB_PATH)
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
	db, err := database.NewDB(DB_PATH)
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
	db, err := database.NewDB(DB_PATH)
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

func (cfg *ApiCfg) UpdateUsers(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	msg, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithError(w, 500, "Error in body while updating")
		return
	}

	type requestBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	params := requestBody{}
	err = json.Unmarshal(msg, &params)
	if err != nil {
		respondWithError(w, 500, "Error while unmarshalling")
		return
	}

	db, err := database.NewDB(DB_PATH)
	if err != nil {
		fmt.Println("Impossible to create db: ", err)
		return
	}

	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := &jwt.RegisteredClaims{}

	// Parse the token
	tokenParsed, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.JwtSecret), nil
	})

	if err != nil || !tokenParsed.Valid {
		respondWithError(w, http.StatusUnauthorized, "Unauthorized user")
		return
	}

	userId := claims.Subject
	if userId == "" {
		respondWithError(w, http.StatusInternalServerError, "No id found in token")
	}

	newPwdEncrypted, err := bcrypt.GenerateFromPassword([]byte(params.Password), 4)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("An error happened while encrypting %v", err))
	}

	userUpdated, err := db.UpdateUser(userId, database.User{
		Email:    params.Email,
		Password: newPwdEncrypted,
	})

	if err != nil || userUpdated == nil {
		respondWithError(w, http.StatusInternalServerError, "No user updated")
	}

	respondWithJson(w, http.StatusOK, responseBodyUser{
		Email: userUpdated.Email,
		ID:    userUpdated.ID,
	})
}

func (cfg *ApiCfg) Login(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	msg, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithError(w, 500, "Error in body")
		return
	}

	type requestBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		ExpireAt int    `json:"expires_in_seconds,omitempty"`
	}

	params := requestBody{}
	err = json.Unmarshal(msg, &params)
	if err != nil {
		respondWithError(w, 500, "Error whil unmarshalling")
		return
	}

	db, err := database.NewDB(DB_PATH)
	if err != nil {
		fmt.Println("Impossible to create db: ", err)
		return
	}

	user, err := db.GetUserByPwd(params.Password)
	if err != nil {
		respondWithError(w, 401, "Unauthorized")
	}

	expireAt := ConvertExpireTime(strconv.Itoa(params.ExpireAt))
	expireString := strconv.FormatInt(int64(expireAt), 10)
	if err != nil {
		respondWithError(w, 400, "Invalid expiration duration")
		return
	}
	if expireAt == 0 {
		respondWithError(w, 400, "Invalid expiration duration")
	}

	token, err := createJWTToken(expireString, strconv.Itoa(user.ID), cfg.JwtSecret)
	if err != nil {
		fmt.Println(err)
		respondWithError(w, 500, "Error while querying jwt token")
	}
	respondWithJson(w, 200, responseBodyUser{
		ID:    user.ID,
		Email: user.Email,
		Token: token,
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

func createJWTToken(expire, id string, secretKey []byte) (string, error) {
	durationExpire := ConvertExpireTime(expire)
	if durationExpire == 0 {
		fmt.Println("ERROR duration")
		return "", nil
	}
	expireDuration := time.Now().Add(time.Duration(durationExpire) * time.Second)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(expireDuration),
		Subject:   id,
	})

	response, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return response, nil
}

func ConvertExpireTime(expireTime string) int {
	expireTimeInt, err := strconv.Atoi(expireTime)
	if err != nil {
		return 0
	}
	var expiresInSeconds int64
	const maxExpiration = 24 * time.Hour // 24 heures en durée

	if expireTimeInt == 0 {
		expiresInSeconds = int64(maxExpiration.Seconds())
	} else {
		if time.Duration(expireTimeInt)*time.Second > maxExpiration {
			expiresInSeconds = int64(maxExpiration.Seconds())
		} else {
			expiresInSeconds = int64(expireTimeInt)
		}
	}

	fmt.Printf("Expiration set to: %d seconds\n", expiresInSeconds)

	return int(expiresInSeconds)
}
