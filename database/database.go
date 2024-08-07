package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
)

type DB struct {
	path string
	mux  *sync.RWMutex
}

type DBStructure struct {
	Chirps []Chirp `json:"chirps"`
}

type Chirp struct {
	ID   int    `json:"id"`
	Body string `json:"body"`
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
func (db *DB) CreateChirp(body string) (*Chirp, error) {
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

	// Add chirp to db structure
	dbStructure.Chirps = append(dbStructure.Chirps, newChirp)

	if err := db.writeDB(dbStructure); err != nil {
		return nil, err
	}

	log.Println("Chirp created")

	return &newChirp, nil

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
func (db *DB) writeDB(dbStructure DBStructure) error {
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
