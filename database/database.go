package database

import "sync"

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
	return nil, nil
}

// CreateChirp creates a new chirp and saves it to disk
func (db *DB) CreateChirp(body string) (Chirp, error) {
	return Chirp{}, nil
}

// GetChirps returns all chirps in the database
func (db *DB) GetChirp() ([]Chirp, error) {
	return []Chirp{}, nil
}

// ensureDB creates a new database file if it doesn't exist
func (db *DB) ensureDB() error {
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
