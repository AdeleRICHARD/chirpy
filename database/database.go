package database

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"sync"
)

type DB struct {
	path string
	mux  *sync.RWMutex
}

type DBStructure struct {
	Chirps map[int]Chirp `json:"chirps"`
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

	log.Println("New database created")

	return db, nil
}

// CreateChirp creates a new chirp and saves it to disk
func (db *DB) CreateChirp(body string) (*Chirp, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	var newChirp Chirp
	dbStructure, err := db.loadDB()
	if errors.Is(err, ErrDBNotCreated) {
		return nil, err
	}

	if len(dbStructure.Chirps) > 0 {
		newChirp.ID = dbStructure.Chirps[len(dbStructure.Chirps)-1].ID + 1
		newChirp.Body = body

		return &newChirp, nil
	}

	// create New chirp
	newChirp.Body = body
	newChirp.ID = 1

	// Add chirp to db structure
	dbStructure.Chirps[newChirp.ID] = newChirp

	if err := db.writeDB(dbStructure); err != nil {
		return nil, err
	}

	return &newChirp, nil

}

// GetChirps returns all chirps in the database
func (db *DB) GetChirp() ([]Chirp, error) {
	if err := db.ensureDB(); err != nil {
		return nil, err
	}

	_, err := db.loadDB()
	if err != nil {
		return nil, err
	}

	return nil, nil

}

// ensureDB creates a new database file if it doesn't exist
func (db *DB) ensureDB() error {
	if _, err := os.Stat(db.path); os.IsNotExist(err) {
		// File does not exist, create it
		initialDB := DBStructure{Chirps: make(map[int]Chirp)}
		data, err := json.Marshal(initialDB)
		if err != nil {
			return ErrDBNotCreated
		}
		if err := os.WriteFile(db.path, data, 0644); err != nil {
			println(err.Error())
			return ErrDBNotCreated
		}
	}

	return nil
}

// loadDB reads the database file into memory
func (db *DB) loadDB() (DBStructure, error) {
	return DBStructure{}, nil
}

// writeDB writes the database file to disk
func (wb *DB) writeDB(dbStructure DBStructure) error {
	return nil
}
