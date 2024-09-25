package handler

import (
	"crypto/rand"
	"encoding/hex"
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
	ID       int    `json:"id"`
	Body     string `json:"body"`
	AuthorId int    `json:"author_id"`
}

type responseBodyUser struct {
	ID           int    `json:"id"`
	Email        string `json:"email"`
	Token        string `json:"token,omitempty"`
	RefreshToken string `json:"refresh_token"`
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

	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	user, err := cfg.userAuthenticated(token, db)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Could not get infos on user")
		return
	}

	if user == nil {
		respondWithError(w, http.StatusUnauthorized, "User not logged in")
		return
	}

	chirp, err := db.CreateChirp(params.Body, user.ID)
	if err != nil {
		fmt.Println("Could not create chirp ", err)
		return
	}

	respondWithJson(w, 201, responseBody{
		ID:       chirp.ID,
		Body:     params.Body,
		AuthorId: user.ID,
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

func (cfg *ApiCfg) DeleteChirpFromID(w http.ResponseWriter, r *http.Request) {
	db, err := database.NewDB(DB_PATH)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "No database created or found")
	}

	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	user, err := cfg.userAuthenticated(token, db)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "User not logged in")
	}

	chirpId := r.PathValue("chirpID")
	chirp, err := db.GetChirp(chirpId)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "No chirps found")
	}

	if strconv.Itoa(user.ID) == chirp.UserId {
		err := db.DeleteChirp(*chirp)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "Could not delete chirp")
		}
		respondWithJson(w, http.StatusNoContent, "Chirps deleted")
		return
	}

	respondWithError(w, http.StatusForbidden, "You cannot delete this chirp")
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

	userId, err := cfg.getUserByJWT(token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Unauthorized user")
		return
	}

	newPwdEncrypted, err := bcrypt.GenerateFromPassword([]byte(params.Password), 4)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("An error happened while encrypting %v", err))
		return
	}

	user, err := db.GetUserById(userId)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "No user to update")
		return
	}

	user.Email = params.Email
	user.Password = newPwdEncrypted

	userUpdated, err := db.UpdateUser(userId, *user)

	if err != nil || userUpdated == nil {
		respondWithError(w, http.StatusInternalServerError, "No user updated")
		return
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
		return
	}

	/* V1
	expireAt := ConvertExpireTime(strconv.Itoa(params.ExpireAt))
	expireString := strconv.FormatInt(int64(expireAt), 10)
	if err != nil {
		respondWithError(w, 400, "Invalid expiration duration")
		return
	}
	if expireAt == 0 {
		respondWithError(w, 400, "Invalid expiration duration")
	} */

	token, err := createJWTToken(strconv.Itoa(user.ID), cfg.JwtSecret)
	if err != nil {
		fmt.Println(err)
		respondWithError(w, 500, "Error while querying jwt token")
		return
	}

	refreshToken, err := createRefreshToken()
	if err != nil {
		respondWithError(w, 500, "Error while creating refresh token")
		return
	}

	user.RefreshToken = refreshToken
	userId := strconv.Itoa(user.ID)
	user.ExpirationToken = time.Now().Add(60 * 24 * time.Hour)

	userDB, err := db.UpdateUser(userId, user)
	if err != nil {
		respondWithError(w, 500, "Error while storing refresh token")
		return
	}

	respondWithJson(w, 200, responseBodyUser{
		ID:           userDB.ID,
		Email:        userDB.Email,
		Token:        token,
		RefreshToken: refreshToken,
	})
}

func (cfg *ApiCfg) RefreshToken(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	db, err := database.NewDB(DB_PATH)
	if err != nil {
		respondWithError(w, 500, "No database created")
		return
	}

	userId, found, err := db.GetUserRefreshToken(token)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error while querying database for token")
		return
	}

	if !*found {
		respondWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	strId := strconv.Itoa(userId)
	user, err := db.GetUserById(strId)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "No user found with this id")
		return
	}

	if user.RefreshToken == "" || user.ExpirationToken.Compare(time.Now()) == -1 {
		respondWithError(w, http.StatusUnauthorized, "Unauthorized user")
		return
	}

	newToken, err := createJWTToken(strId, cfg.JwtSecret)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Impossible to create new refresh token")
		return
	}

	respondWithJson(w, http.StatusOK, responseBodyUser{
		Token: newToken,
	})
}

func (cfg *ApiCfg) RevokeToken(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	db, err := database.NewDB(DB_PATH)
	if err != nil {
		respondWithError(w, 500, "No database created")
		return
	}

	userId, _, err := db.GetUserRefreshToken(token)
	if err != nil || userId == 0 {
		respondWithError(w, http.StatusNotFound, "No user found for this token")
		return
	}

	strId := strconv.Itoa(userId)

	user, err := db.GetUserById(strId)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "No user found for this id")
		return
	}

	user.RefreshToken = ""
	user.ExpirationToken = time.Time{}

	err = db.Delete(*user)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error while revoking token")
		return
	}

	respondWithJson(w, http.StatusNoContent, "token sucessfully revoked")
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

func createJWTToken(id string, secretKey []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		Subject:   id,
	})

	response, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return response, nil
}

func createRefreshToken() (string, error) {
	randomData := make([]byte, 32)
	_, err := rand.Read(randomData)
	if err != nil {
		return "", err
	}

	token := hex.EncodeToString(randomData)

	return token, nil
}

func (cfg *ApiCfg) getUserByJWT(token string) (string, error) {
	claims := &jwt.RegisteredClaims{}

	// Parse the token
	tokenParsed, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.JwtSecret), nil
	})

	if err != nil || !tokenParsed.Valid {
		return "", err
	}

	userId := claims.Subject
	if userId == "" {
		return "", err
	}

	return userId, nil
}

func (cfg *ApiCfg) userAuthenticated(token string, db *database.DB) (*database.User, error) {
	id, err := cfg.getUserByJWT(token)
	if err != nil {
		return nil, err
	}

	user, err := db.GetUserById(id)
	if err != nil {
		return nil, err
	}

	if user != nil {
		return user, nil
	}

	return nil, nil
}

// V1
/*
func ConvertExpireTime(expireTime string) int {
	expireTimeInt, err := strconv.Atoi(expireTime)
	if err != nil {
		return 0
	}
	var expiresInSeconds int64
	const maxExpiration = 24 * time.Hour

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
} */
