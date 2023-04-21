package main

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"golang.org/x/term"
)

type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func initAPISchema(db *sqlx.DB) {
	schema := `
	CREATE TABLE IF NOT EXISTS auth_tokens (
	    id INTEGER PRIMARY KEY,
	    user_hash TEXT NOT NULL,
	    token TEXT NOT NULL UNIQUE,
	    created_at TIMESTAMP NOT NULL
	);
	`
	_, err := db.Exec(schema)
	if err != nil {
		log.Fatalln(err)
	}
}

func api(db *sqlx.DB) {
	initAPISchema(db)

	http.HandleFunc("/chat/messages", tokenAuth(db)(chatMessagesHandler))
	http.HandleFunc("/chat/create", tokenAuth(db)(chatCreateHandler))
	http.HandleFunc("/chat/direct/create", tokenAuth(db)(directMessageHandler))
	http.HandleFunc("/posts/list", tokenAuth(db)(func(w http.ResponseWriter, r *http.Request) {
		postsListHandler(w, r, db)
	}))
	http.HandleFunc("/posts/replies", tokenAuth(db)(func(w http.ResponseWriter, r *http.Request) {
		repliesListHandler(w, r, db)
	}))
	http.HandleFunc("/posts/reply", tokenAuth(db)(func(w http.ResponseWriter, r *http.Request) {
		replyCreateHandler(w, r, db)
	}))

	http.ListenAndServe(":8080", nil)
}

func tokenAuth(db *sqlx.DB) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("Authorization")
			if token == "" {
				resp := APIResponse{Success: false, Error: "missing Authorization header"}
				json.NewEncoder(w).Encode(resp)
				return
			}

			pubkeyHash, err := getPubkeyHash(db, token)
			if err != nil {
				resp := APIResponse{Success: false, Error: err.Error()}
				json.NewEncoder(w).Encode(resp)
				return
			}

			ctx := context.WithValue(r.Context(), "pubkey_hash", pubkeyHash)
			next(w, r.WithContext(ctx))
		}
	}
}

func chatMessagesHandler(w http.ResponseWriter, r *http.Request) {
	pubkeyHash := r.Context().Value("pubkey_hash").(string)
	log.Printf("pubkeyHash: %s api: chatMessagesHandler\n", pubkeyHash)
	messages := getLast100ChatMessages()
	resp := APIResponse{Success: true, Data: messages}
	json.NewEncoder(w).Encode(resp)
}

func chatCreateHandler(w http.ResponseWriter, r *http.Request) {
	senderHash := r.FormValue("sender_hash")
	message := r.FormValue("message")
	if err := createChatMessage(senderHash, message); err == nil {
		json.NewEncoder(w).Encode(APIResponse{Success: true})
	} else {
		json.NewEncoder(w).Encode(APIResponse{Success: false, Error: err.Error()})
	}
}

func directMessageHandler(w http.ResponseWriter, r *http.Request) {
	senderHash := r.FormValue("sender")
	recipientHash := r.FormValue("recipient")
	message := r.FormValue("message")
	err := createDirectMessage(senderHash, recipientHash, message)
	if err == nil {
		json.NewEncoder(w).Encode(APIResponse{Success: true})
	} else {
		json.NewEncoder(w).Encode(APIResponse{Success: false, Error: err.Error()})
	}
}

func postsListHandler(w http.ResponseWriter, r *http.Request, db *sqlx.DB) {
	posts := listPosts(db)
	resp := APIResponse{Success: true, Data: posts}
	json.NewEncoder(w).Encode(resp)
}

func repliesListHandler(w http.ResponseWriter, r *http.Request, db *sqlx.DB) {
	postID, _ := strconv.Atoi(r.FormValue("post_id"))
	replies := getReplies(db, postID)
	resp := APIResponse{Success: true, Data: replies}
	json.NewEncoder(w).Encode(resp)
}

func replyCreateHandler(w http.ResponseWriter, r *http.Request, db *sqlx.DB) {
	postID, _ := strconv.Atoi(r.FormValue("post_id"))
	authorHash := r.FormValue("author_hash")
	replyBody := r.FormValue("reply")
	if err := createReply(db, postID, authorHash, replyBody); err == nil {
		json.NewEncoder(w).Encode(APIResponse{Success: true})
	} else {
		json.NewEncoder(w).Encode(APIResponse{Success: false, Error: err.Error()})
	}
}

func createChatMessage(senderHash, message string) error {
	broadcast(senderHash, message)
	return nil
}

func listPosts(db *sqlx.DB) []discussion {
	var posts []discussion
	err := db.Select(&posts, `
		SELECT id, author, message
		FROM discussions
		ORDER BY id DESC
	`)
	if err != nil {
		log.Printf("Error retrieving posts: %v", err)
		return nil
	}
	return posts
}

func getReplies(db *sqlx.DB, postID int) []*reply {
	var replies []*reply
	err := db.Select(&replies, "SELECT author, message FROM replies WHERE discussion_id = ?", postID)
	if err != nil {
		log.Printf("Error retrieving replies: %v", err)
		return nil
	}
	return replies
}
func getLast100ChatMessages() []string {
	var messages []string
	for e := messageCache.Front(); e != nil; e = e.Next() {
		messages = append(messages, e.Value.(string))
	}
	return messages
}

func createDirectMessage(senderHash, recipientHash, message string) error {
	usersMutex.Lock()
	defer usersMutex.Unlock()
	recipient, ok := users[recipientHash]
	if !ok {
		return fmt.Errorf("user not found")
	}
	if recipient.Conn == nil {
		return fmt.Errorf("user connection is not available")
	}
	formattedMessage := fmt.Sprintf("[DM from %s] %s\n", senderHash, message)
	fmt.Fprintln(recipient.Conn, formattedMessage)
	return nil
}
func handleTokenNew(db *sqlx.DB, term *term.Terminal, userHash string) {
	token, err := createToken(db, userHash)
	if err != nil {
		term.Write([]byte("Error generating token: " + err.Error() + "\n"))
	} else {
		term.Write([]byte("New token created: " + token + "\n"))
	}
}

func handleTokenList(db *sqlx.DB, term *term.Terminal, userHash string) {
	tokens, err := listTokens(db, userHash)
	if err != nil {
		term.Write([]byte("Error listing tokens: " + err.Error() + "\n"))
	} else {
		term.Write([]byte("Your tokens:\n"))
		for _, token := range tokens {
			term.Write([]byte(" - " + token + "\n"))
		}
	}
}

func handleTokenRevoke(db *sqlx.DB, input string, term *term.Terminal, userHash string) {
	parts := strings.Split(input, " ")
	if len(parts) < 3 {
		term.Write([]byte("Usage: /tokens revoke <token>\n"))
	} else {
		token := parts[2]
		err := revokeToken(db, userHash, token)
		if err != nil {
			term.Write([]byte("Error revoking token: " + err.Error() + "\n"))
		} else {
			term.Write([]byte("Token revoked successfully.\n"))
		}
	}
}

func createToken(db *sqlx.DB, userHash string) (string, error) {
	token := generateRandomToken()
	_, err := db.Exec("INSERT INTO auth_tokens (user_hash, token, created_at) VALUES (?, ?, ?)", userHash, token, time.Now())
	if err != nil {
		return "", err
	}
	return token, nil
}

func listTokens(db *sqlx.DB, userHash string) ([]string, error) {
	var tokens []string
	err := db.Select(&tokens, "SELECT token FROM auth_tokens WHERE user_hash = ?", userHash)
	if err != nil {
		return nil, err
	}
	return tokens, nil
}

func revokeToken(db *sqlx.DB, userHash, token string) error {
	result, err := db.Exec("DELETE FROM auth_tokens WHERE user_hash = ? AND token = ?", userHash, token)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("token not found or not owned by the user")
	}

	return nil
}

func generateRandomToken() string {
	token := make([]byte, 20)
	_, err := rand.Read(token)
	if err != nil {
		panic(err)
	}

	return base32.StdEncoding.EncodeToString(token)
}

func getPubkeyHash(db *sqlx.DB, token string) (string, error) {
	var userHash string
	err := db.Get(&userHash, "SELECT user_hash FROM auth_tokens WHERE token = ?", token)
	if err != nil {
		return "", fmt.Errorf("invalid token")
	}

	var pubkeyHash string
	err = db.Get(&pubkeyHash, "SELECT pubkey_hash FROM users WHERE hash = ?", userHash)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve pubkey hash")
	}

	return pubkeyHash, nil
}
