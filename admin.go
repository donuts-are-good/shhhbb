package main

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

type Staff struct {
	ID       int    `db:"id"`
	Username string `db:"username"`
	Password string `db:"password"`
	Role     string `db:"role"`
}

type Role struct {
	Name        string       `db:"name"`
	Permissions []Permission `db:"permissions"`
}

type Permission struct {
	Role      Role
	Resources []string
}

func initAdminDB() *sqlx.DB {
	db, err := sqlx.Connect("sqlite3", "admin.db")
	if err != nil {
		fmt.Printf("Error connecting to admin database: %v\n", err)
		return nil
	}
	return db
}

func initAdminSchema(db *sqlx.DB) {
	createStaffTable := `
		CREATE TABLE IF NOT EXISTS staff (
			id INTEGER PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL,
			role TEXT NOT NULL
		);
	`

	createRolesTable := `
	CREATE TABLE IF NOT EXISTS roles (
		name TEXT PRIMARY KEY,
		permissions TEXT NOT NULL
	);
`

	createUsersTable := `
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY,
	username TEXT UNIQUE NOT NULL,
	email TEXT UNIQUE NOT NULL,
	password TEXT NOT NULL
);
`

	createBansTable := `
CREATE TABLE IF NOT EXISTS bans (
	id INTEGER PRIMARY KEY,
	user_id INTEGER NOT NULL,
	reason TEXT NOT NULL,
	start_date DATETIME NOT NULL,
	end_date DATETIME,
	FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
`

	createModerationLogsTable := `
CREATE TABLE IF NOT EXISTS moderation_logs (
	id INTEGER PRIMARY KEY,
	staff_id INTEGER NOT NULL,
	user_id INTEGER NOT NULL,
	action TEXT NOT NULL,
	reason TEXT,
	date_time DATETIME NOT NULL,
	FOREIGN KEY (staff_id) REFERENCES staff (id) ON DELETE CASCADE,
	FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
`

	_, err := db.Exec(createUsersTable)
	if err != nil {
		fmt.Printf("Error creating users table: %v\n", err)
		return
	}

	_, err = db.Exec(createBansTable)
	if err != nil {
		fmt.Printf("Error creating bans table: %v\n", err)
		return
	}

	_, err = db.Exec(createModerationLogsTable)
	if err != nil {
		fmt.Printf("Error creating moderation logs table: %v\n", err)
		return
	}

	_, err = db.Exec(createStaffTable)
	if err != nil {
		fmt.Printf("Error creating staff table: %v\n", err)
		return
	}

	_, err = db.Exec(createRolesTable)
	if err != nil {
		fmt.Printf("Error creating roles table: %v\n", err)
		return
	}
}
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin" || pass != "password" {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func overviewHandler(adminDB *sqlx.DB, w http.ResponseWriter, r *http.Request) {
	// Retrieve moderation statistics from the database
	stats := struct {
		FlaggedPosts int
		ActiveBans   int
	}{}

	err := adminDB.Get(&stats, `
		SELECT COUNT(*) AS flagged_posts
		FROM posts
		WHERE flagged = 1
	`)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = adminDB.Get(&stats, `
		SELECT COUNT(*) AS active_bans
		FROM bans
		WHERE active = 1
	`)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl := template.Must(template.ParseFiles("templates/overview.html"))
	tmpl.Execute(w, stats)
}
func userManagementHandler(adminDB *sqlx.DB, w http.ResponseWriter, r *http.Request) {
	// Retrieve user profiles from the database
	users := []struct {
		Username string
		Email    string
	}{}

	err := adminDB.Select(&users, `
		SELECT username, email
		FROM users
	`)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl := template.Must(template.ParseFiles("templates/user-management.html"))
	tmpl.Execute(w, users)
}
func moderationLogsHandler(adminDB *sqlx.DB, w http.ResponseWriter, r *http.Request) {
	// Retrieve moderation logs from the database
	logs := []struct {
		Action   string
		User     string
		DateTime string
	}{}

	err := adminDB.Select(&logs, `
		SELECT action, user_id, date_time
		FROM moderation_logs
		ORDER BY date_time DESC
		LIMIT 100
	`)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Replace user_id with username
	for i, log := range logs {
		user := struct {
			Username string
		}{}

		err := adminDB.Get(&user, `
			SELECT username
			FROM users
			WHERE id = ?
		`, log.User)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		logs[i].User = user.Username
	}

	tmpl := template.Must(template.ParseFiles("templates/moderation-logs.html"))
	tmpl.Execute(w, logs)
}

func adminAPI() {
	adminDB := initAdminDB()
	if adminDB == nil {
		return
	}
	defer adminDB.Close()

	mux := http.NewServeMux()

	mux.Handle("/admin/overview", authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		overviewHandler(adminDB, w, r)
	})))

	mux.Handle("/admin/user-management", authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userManagementHandler(adminDB, w, r)
	})))

	mux.Handle("/admin/moderation-logs", authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		moderationLogsHandler(adminDB, w, r)
	})))

	http.ListenAndServe(":12223", mux)
}
