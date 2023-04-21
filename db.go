package main

import (
	"log"

	"github.com/jmoiron/sqlx"
)

func initSqliteDB() *sqlx.DB {
	db, err := sqlx.Connect("sqlite3", "board.db")
	if err != nil {
		log.Fatalln(err)
	}
	return db
}

func initBoardSchema(db *sqlx.DB) {
	schema := `
	CREATE TABLE IF NOT EXISTS discussions (
	    id INTEGER PRIMARY KEY,
	    author TEXT NOT NULL,
	    message TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS replies (
	    id INTEGER PRIMARY KEY,
	    discussion_id INTEGER NOT NULL,
	    author TEXT NOT NULL,
	    message TEXT NOT NULL,
	    FOREIGN KEY (discussion_id) REFERENCES discussions(id) ON DELETE CASCADE
	);
	`
	_, err := db.Exec(schema)
	if err != nil {
		log.Fatalln(err)
	}
}


func createReply(db *sqlx.DB, postID int, authorHash string, replyBody string) error {
	_, err := db.Exec("INSERT INTO replies (discussion_id, author, message) VALUES (?, ?, ?)", postID, authorHash, replyBody)
	return err
}
