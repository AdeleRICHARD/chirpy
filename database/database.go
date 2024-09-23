package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"slices"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type DB struct {
	path string
	mux  *sync.RWMutex
}

type DBStructure struct {
	Chirps []Chirp `json:"chirps"`
	Users  []User  `json:"users"`
}

type Chirp struct {
	ID     int    `json:"id"`
	Body   string `json:"body"`
	UserId string `json:"author_id"`
}

type User struct {
	ID              int       `json:"id"`
	Email           string    `json:"email"`
	Password        []byte    `json:"password"`
	ExpirationToken time.Time `json:"expiration_token"`
	RefreshToken    string    `json:"refresh_token"`
}

// NewDB creates a new database connection
// and creates the database file if it doesn't exist
func NewDB(path string) (*DB, error) {
	db := &DB{
		path: path,
		mux:  &sync.RWMutex{},
	}

	// Ensure the database file exists
	if err := db.ensureDB(); err != nil {
		return nil, err
	}

	return db, nil
}

// CreateChirp creates a new chirp and saves it to disk
func (db *DB) CreateChirp(body string, userId int) (*Chirp, error) {
	var newChirp Chirp
	dbStructure, err := db.loadDB()
	if errors.Is(err, ErrDBNotCreated) {
		return nil, err
	}

	maxID := 0
	if len(dbStructure.Chirps) > 0 {
		// Find the highest ID
		for _, chirp := range dbStructure.Chirps {
			if chirp.ID > maxID {
				maxID = chirp.ID
			}
		}
		newChirp.ID = maxID + 1
	} else {
		newChirp.ID = 1
	}
	newChirp.Body = body
	newChirp.UserId = strconv.Itoa(userId)

	// Add chirp to db structure
	dbStructure.Chirps = append(dbStructure.Chirps, newChirp)

	if err := db.writeDB(&dbStructure); err != nil {
		return nil, err
	}

	log.Println("Chirp created")

	return &newChirp, nil

}

func (db *DB) CreateUser(email string, pwd []byte) (*User, error) {
	var newUser User
	dbStructure, err := db.loadDB()
	if errors.Is(err, ErrDBNotCreated) {
		return nil, err
	}

	maxID := 0
	if len(dbStructure.Users) > 0 {
		// Find the highest ID
		for _, user := range dbStructure.Users {
			if user.ID > maxID {
				maxID = user.ID
			}
		}
		newUser.ID = maxID + 1
	} else {
		newUser.ID = 1
	}

	newUser.Email = email
	newUser.Password = pwd
	dbStructure.Users = append(dbStructure.Users, newUser)

	if err := db.writeDB(&dbStructure); err != nil {
		return nil, err
	}

	log.Println("User created")

	return &newUser, nil

}

// GetChirps returns all chirps in the database
func (db *DB) GetChirps() ([]Chirp, error) {
	db.mux.RLock()
	defer db.mux.RUnlock()

	dbStructure, err := db.loadDB()
	if err != nil {
		return nil, err
	}

	return dbStructure.Chirps, nil
}

func (db *DB) GetChirp(chirpID string) (*Chirp, error) {
	db.mux.RLock()
	defer db.mux.RUnlock()

	if chirpID == "" {
		return nil, errors.New("no chirp id given")
	}
	dbStructure, err := db.loadDB()
	if err != nil {
		return nil, err
	}

	for _, chirp := range dbStructure.Chirps {
		chirpIDInt, err := strconv.Atoi(chirpID)
		if err != nil {
			return nil, err
		}
		if chirp.ID == chirpIDInt {
			return &chirp, nil
		}
	}

	return nil, fmt.Errorf("no chirp found for this id: %s", chirpID)
}

func (db *DB) UpdateUser(id string, params User) (*User, error) {
	userToUpdate, err := db.GetUserById(id)
	if err != nil {
		return nil, err
	}

	if userToUpdate == nil {
		return nil, fmt.Errorf("No user found with this id %s", id)
	}

	dbStructure, err := db.loadDB()
	if err != nil {
		return nil, err
	}

	for i, user := range dbStructure.Users {
		if user.ID == userToUpdate.ID {

			if params.RefreshToken != "" && params.ExpirationToken != (time.Time{}) {
				dbStructure.Users[i].ExpirationToken = params.ExpirationToken
				dbStructure.Users[i].RefreshToken = params.RefreshToken
				dbStructure.Users[i].Email = params.Email
				dbStructure.Users[i].Password = params.Password
			} else {
				dbStructure.Users[i].Email = params.Email
				dbStructure.Users[i].Password = params.Password
			}

			if err := db.writeDB(&dbStructure); err != nil {
				return nil, err
			}

			return &User{
				Email: dbStructure.Users[i].Email,
				ID:    dbStructure.Users[i].ID,
			}, nil
		}
	}

	return nil, fmt.Errorf("User not found")
}

func (db *DB) Delete(userToDelete User) error {
	if err := db.ensureDB(); err != nil {
		return err
	}

	dbStructure, err := db.loadDB()
	if err != nil {
		return err
	}

	index := slices.IndexFunc(dbStructure.Users, func(u User) bool {
		return u.ID == userToDelete.ID
	})

	if index == -1 {
		return fmt.Errorf("No user found with id %d", userToDelete.ID)
	}

	if userToDelete.RefreshToken != "" {
		dbStructure.Users[index].RefreshToken = ""
		dbStructure.Users[index].ExpirationToken = time.Time{}
	} else {
		dbStructure.Users[index].Email = userToDelete.Email
		dbStructure.Users[index].Password = userToDelete.Password
		dbStructure.Users[index].RefreshToken = ""
		dbStructure.Users[index].ExpirationToken = time.Time{}
	}

	if err := db.writeDB(&dbStructure); err != nil {
		return err
	}

	return nil
}

// ensureDB creates a new database file if it doesn't exist
func (db *DB) ensureDB() error {
	db.mux.Lock()
	defer db.mux.Unlock()

	if _, err := os.Stat(db.path); os.IsNotExist(err) {
		// File does not exist, create it
		initialDB := DBStructure{Chirps: make([]Chirp, 0)}
		data, err := json.Marshal(initialDB)
		if err != nil {
			return ErrDBNotCreated
		}
		if err := os.WriteFile(db.path, data, 0644); err != nil {
			log.Println("New database created")
			println(err.Error())
			return ErrDBNotCreated
		}
	}

	return nil
}

// loadDB reads the database file into memory
func (db *DB) loadDB() (DBStructure, error) {
	db.mux.RLock()
	defer db.mux.RUnlock()

	log.Println("Loading database")
	file, err := os.ReadFile(db.path)
	if err != nil {
		return DBStructure{}, err
	}

	var dbStructure DBStructure
	err = json.Unmarshal(file, &dbStructure)
	if err != nil {
		return DBStructure{}, err
	}

	return dbStructure, nil
}

// writeDB writes the database file to disk
func (db *DB) writeDB(dbStructure *DBStructure) error {
	data, err := json.Marshal(dbStructure)
	if err != nil {
		return err
	}

	log.Println("Writing to database")
	if err := os.WriteFile(db.path, data, 0644); err != nil {
		return err
	}

	return nil
}

func (db *DB) GetUserByPwd(pwd string) (User, error) {
	dbData, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	found := slices.IndexFunc(dbData.Users, func(user User) bool {
		return bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(pwd)) == nil
	})

	if found == -1 {
		return User{}, errors.New("there is no user for this email")
	}

	return User{
		Email: dbData.Users[found].Email,
		ID:    dbData.Users[found].ID,
	}, nil
}

func (db *DB) GetUserById(id string) (*User, error) {
	if err := db.ensureDB(); err != nil {
		return nil, err
	}

	dbData, err := db.loadDB()
	if err != nil {
		return nil, err
	}

	found := slices.IndexFunc(dbData.Users, func(user User) bool {
		userId := strconv.Itoa(user.ID)
		return userId == id
	})

	if found == -1 {
		return nil, fmt.Errorf("there is no user for this id : %s", id)
	}

	return &User{
		Email:           dbData.Users[found].Email,
		ID:              dbData.Users[found].ID,
		RefreshToken:    dbData.Users[found].RefreshToken,
		ExpirationToken: dbData.Users[found].ExpirationToken,
	}, nil
}

func (db *DB) GetUserRefreshToken(token string) (int, *bool, error) {
	if err := db.ensureDB(); err != nil {
		return 0, nil, err
	}

	dbData, err := db.loadDB()
	if err != nil {
		return 0, nil, err
	}

	found := slices.IndexFunc(dbData.Users, func(user User) bool {
		return token == user.RefreshToken
	})

	tokenOk := new(bool)
	if found == -1 {
		*tokenOk = false
		return 0, tokenOk, nil
	}

	if dbData.Users[found].ExpirationToken.Compare(time.Now()) == -1 {
		*tokenOk = false
		return 0, tokenOk, nil
	}

	*tokenOk = true
	return dbData.Users[found].ID, tokenOk, nil
}
