package main

import (
	"container/list"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

var users = make(map[string]*user)
var usersMutex sync.Mutex
var messageCache *list.List

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

type user struct {
	Pubkey  string          `json:"pubkey" db:"pubkey"`
	Hash    string          `json:"hash" db:"hash"`
	Conn    ssh.Channel     `json:"-"`
	Ignored map[string]bool `json:"-"`
}

type discussion struct {
	ID      int      `json:"id" db:"id"`
	Author  string   `json:"author" db:"author"`
	Message string   `json:"message" db:"message"`
	Replies []*reply `json:"replies"`
}

type reply struct {
	Author  string `json:"author" db:"author"`
	Message string `json:"message" db:"message"`
}

func addDiscussion(db *sqlx.DB, author, message string) int {
	res, err := db.Exec("INSERT INTO discussions (author, message) VALUES (?, ?)", author, message)
	if err != nil {
		log.Println(err)
		return -1
	}
	id, err := res.LastInsertId()
	if err != nil {
		log.Println(err)
		return -1
	}
	return int(id)
}

func addReply(db *sqlx.DB, postNumber int, author, message string) bool {
	_, err := db.Exec("INSERT INTO replies (discussion_id, author, message) VALUES (?, ?, ?)", postNumber, author, message)
	if err != nil {
		log.Println(err)
		return false
	}
	return true

}
func listDiscussions(db *sqlx.DB, term *term.Terminal) {
	var discussions []*discussion
	err := db.Select(&discussions, "SELECT id, author, message FROM discussions")
	if err != nil {
		log.Printf("Error retrieving discussions: %v", err)
		term.Write([]byte("Error retrieving discussions.\n"))
		return
	}
	term.Write([]byte("Discussions:\n"))
	for _, disc := range discussions {
		term.Write([]byte(fmt.Sprintf("%d. [%s] %s\n", disc.ID, disc.Author, disc.Message)))
	}
}

func listReplies(db *sqlx.DB, postNumber int, term *term.Terminal) {
	var disc discussion
	err := db.Get(&disc, "SELECT id, author, message FROM discussions WHERE id = ?", postNumber)
	if err != nil {
		log.Printf("Error retrieving discussion: %v", err)
		term.Write([]byte("Invalid post number.\n"))
		return
	}
	term.Write([]byte(fmt.Sprintf("Replies to post %d [%s]:\n", disc.ID, disc.Author)))

	var replies []*reply
	err = db.Select(&replies, "SELECT author, message FROM replies WHERE discussion_id = ?", postNumber)
	if err != nil {
		log.Printf("Error retrieving replies: %v", err)
		term.Write([]byte("Error retrieving replies.\n"))
		return
	}
	for i, rep := range replies {
		term.Write([]byte(fmt.Sprintf("%d. [%s] %s\n", i+1, rep.Author, rep.Message)))
	}
}

func init() {
	messageCache = list.New()
}

func addToCache(message string) {
	messageCache.PushBack(message)
	if messageCache.Len() > 100 {
		messageCache.Remove(messageCache.Front())
	}
}

func printCachedMessages(term *term.Terminal) {
	for e := messageCache.Front(); e != nil; e = e.Next() {
		term.Write([]byte(e.Value.(string) + "\r\n"))
	}
}

func configureSSHServer(privateKeyPath string) (*ssh.ServerConfig, error) {
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}
	privateKey, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			fmt.Printf("Received public key of type %s from user %s\n", key.Type(), conn.User())
			return &ssh.Permissions{
				Extensions: map[string]string{
					"pubkey": string(key.Marshal()),
				},
			}, nil
		},
	}
	config.AddHostKey(privateKey)
	return config, nil
}

func addUser(hash string, u *user) {
	usersMutex.Lock()
	defer usersMutex.Unlock()
	u.Ignored = make(map[string]bool)
	users[hash] = u
}

func removeUser(hash string) {
	usersMutex.Lock()
	defer usersMutex.Unlock()
	delete(users, hash)
}

func getAllUsers() []*user {
	usersMutex.Lock()
	defer usersMutex.Unlock()
	allUsers := make([]*user, 0, len(users))
	for _, user := range users {
		allUsers = append(allUsers, user)
	}
	return allUsers
}

func main() {
	db := initSqliteDB()
	defer db.Close()

	initBoardSchema(db)

	var privateKeyPath string
	flag.StringVar(&privateKeyPath, "key", "./keys/ssh_host_ed25519_key", "Path to the private key")
	flag.Parse()
	if _, err := os.Stat("./keys"); os.IsNotExist(err) {
		fmt.Println("Error: ./keys directory does not exist. Please create it and generate an ed25519 keypair.")
		return
	}
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		fmt.Printf("Error: private key file %s does not exist. Please generate an ed25519 keypair.\n", privateKeyPath)
		return
	}
	users = make(map[string]*user)
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <port>\n", os.Args[0])
		return
	}
	config, err := configureSSHServer(privateKeyPath)
	if err != nil {
		fmt.Println("Error configuring SSH server:", err.Error())
		return
	}

	listener, err := net.Listen("tcp", ":"+os.Args[1])
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		return
	}
	defer listener.Close()
	fmt.Println("Listening on :" + os.Args[1])
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting:", err.Error())
			continue
		}
		go func(conn net.Conn) {
			defer conn.Close()
			sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
			if err != nil {
				fmt.Println("Error upgrading connection to SSH:", err.Error())
				return
			}
			defer sshConn.Close()
			go ssh.DiscardRequests(reqs)
			for newChannel := range chans {
				if newChannel.ChannelType() != "session" {
					newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
					continue
				}
				channel, requests, err := newChannel.Accept()
				if err != nil {
					fmt.Println("Error accepting channel:", err.Error())
					return
				}
				go handleConnection(db, channel, sshConn, requests)
			}
		}(conn)
	}
}

func generateHash(pubkey string) string {
	h := sha3.NewShake256()
	h.Write([]byte(pubkey))
	checksum := make([]byte, 16)
	h.Read(checksum)
	return base64.StdEncoding.EncodeToString(checksum)
}

func disconnect(hash string) {
	removeUser(hash)
}

func broadcast(message string) {
	addToCache(message)
	log.Println("msg len: ", len(message))
	log.Println("msg txt: ", message)
	sender := message[1:9]
	for _, user := range getAllUsers() {
		if _, ignored := user.Ignored[sender]; !ignored {
			fmt.Fprintln(user.Conn, "\r\n"+message)
		}
	}
}

func cleanString(dirtyString string) (string, error) {
	var clean strings.Builder
	for _, r := range dirtyString {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			clean.WriteRune(r)
		}
	}

	if clean.Len() < 8 {
		return "", errors.New("not enough characters after cleaning")
	}

	return clean.String()[:8], nil
}

func sendMessage(senderHash, recipientHash, message string, term *term.Terminal) {
	usersMutex.Lock()
	recipient, ok := users[recipientHash]
	usersMutex.Unlock()
	if !ok {
		fmt.Fprintf(users[senderHash].Conn, "\n\rUser with hash %s not found\n", recipientHash)
		return
	}
	if recipient.Ignored[senderHash] {
		return
	}
	message = "\r\n[DirectMessage][" + senderHash + "]> " + message + "\r\n"
	fmt.Fprintln(recipient.Conn, message)
	term.Write([]byte(message))
}

func handleConnection(db *sqlx.DB, channel ssh.Channel, sshConn *ssh.ServerConn, requests <-chan *ssh.Request) {
	defer channel.Close()
	if sshConn.Permissions == nil || sshConn.Permissions.Extensions == nil {
		fmt.Fprintln(channel, "Unable to retrieve your public key.")
		return
	}
	pubkey, ok := sshConn.Permissions.Extensions["pubkey"]
	if !ok {
		fmt.Fprintln(channel, "Unable to retrieve your public key.")
		return
	}
makeUsername:
	hash, err := cleanString(generateHash(pubkey))
	if err != nil {
		goto makeUsername // yolo, im not sorry for using goto
	}
	hash = "@" + hash
	addUser(hash, &user{Pubkey: pubkey, Hash: hash, Conn: channel})
	term := term.NewTerminal(channel, "\r\n> ")
	welcome := welcomeMessageAscii()
	printCachedMessages(term)
	term.Write([]byte(welcome))
	term.Write([]byte("\nWelcome :) You are " + hash))
	for {
		input, err := term.ReadLine()
		if err != nil {
			if err == io.EOF {
				disconnect(hash)
				return
			}
			term.Write([]byte("Error reading input: "))
			term.Write([]byte(err.Error()))
			term.Write([]byte("\n"))
			disconnect(hash)
			return
		} else if strings.HasPrefix(input, "/ignore") {
			parts := strings.Split(input, " ")
			if len(parts) != 2 {
				term.Write([]byte("Usage: /ignore <user hash>\n"))
				continue
			}
			ignoredUser := parts[1]
			usersMutex.Lock()
			_, exists := users[ignoredUser]
			usersMutex.Unlock()
			if !exists {
				term.Write([]byte("User " + ignoredUser + " not found.\n"))
			} else if ignoredUser == hash {
				term.Write([]byte("You cannot ignore yourself.\n"))
			} else {
				users[hash].Ignored[ignoredUser] = true
				term.Write([]byte("User " + ignoredUser + " is now ignored.\n"))
			}
		} else if strings.HasPrefix(input, "/help") {
			writeHelpMenu(term)
		} else if strings.HasPrefix(input, "/users") {
			writeUsersOnline(term)
		} else if strings.HasPrefix(input, "/pubkey") {
			term.Write([]byte("Your pubkey hash: " + hash + "\n"))
		} else if strings.HasPrefix(input, "/message") {
			parts := strings.Split(input, " ")
			if len(parts) < 3 {
				term.Write([]byte("Usage: /message <user hash> <direct message text>\n"))
				continue
			}
			recipientHash := parts[1]
			message := strings.Join(parts[2:], " ")
			sendMessage(hash, recipientHash, message, term)
		} else if strings.HasPrefix(input, "/post") {
			parts := strings.SplitN(input, " ", 2)
			if len(parts) < 2 {
				term.Write([]byte("Usage: /post <message>\n"))
				continue
			}
			postNumber := addDiscussion(db, hash, parts[1])
			term.Write([]byte(fmt.Sprintf("Posted new discussion with post number %d.\n", postNumber)))
		} else if strings.HasPrefix(input, "/list") {
			listDiscussions(db, term)
		} else if strings.HasPrefix(input, "/replies") {
			parts := strings.SplitN(input, " ", 2)
			if len(parts) < 2 {
				term.Write([]byte("Usage: /replies <post number>\n"))
				continue
			}
			postNum, err := strconv.Atoi(parts[1])
			if err != nil {
				term.Write([]byte("Invalid post number. Usage: /replies <post number>\n"))
				continue
			}
			listReplies(db, postNum, term)
		} else if strings.HasPrefix(input, "/reply") {
			parts := strings.SplitN(input, " ", 3)
			if len(parts) < 3 {
				term.Write([]byte("Usage: /reply <post number> <reply body>\n"))
				continue
			}
			postNum, err := strconv.Atoi(parts[1])
			if err != nil {
				term.Write([]byte("Invalid post number. Usage: /reply <post number> <reply body>\n"))
				continue
			}
			replyBody := parts[2]
			replySuccess := addReply(db, postNum, hash, replyBody)
			if !replySuccess {
				term.Write([]byte("Failed to reply to post. Please check the post number and try again.\n"))
			} else {
				term.Write([]byte("Reply successfully added to post.\n"))
			}
		} else {
			message := fmt.Sprintf("[%s]: %s", hash, input)
			if len(input) > 0 || !strings.HasPrefix(input, "/") {
				broadcast(message + "\r")
			}
		}
	}
}

func welcomeMessageAscii() string {
	welcome := `

           BB           BB           BB           BB           BB           
,adPPYba,  BB,dPPYba,   BB,dPPYba,   BB,dPPYba,   BB,dPPYba,   BB,dPPYba,   
I8[    ""  BBP'    "8a  BBP'    "8a  BBP'    "8a  BBP'    "8a  BBP'    "8a  
'"Y8ba,    BB       BB  BB       BB  BB       BB  BB       d8  BB       d8  
aa    ]8I  BB       BB  BB       BB  BB       BB  BBb,   ,a8"  BBb,   ,a8"  
'"YbbdP"'  BB       BB  BB       BB  BB       BB  8Y"Ybbd8"'   8Y"Ybbd8"'   BBS
> MIT 2023, https://github.com/donuts-are-good/shhhbb v.0.1.2    

 [RULES]                         [GOALS]
  - your words are your own       - a space for hackers & devs
  - your eyes are your own        - make cool things
  - no chat logs are kept         - collaborate & share
  - have fun :)                   - evolve

Say hello and press [enter] to chat
Type /help for more commands.

`
	return welcome
}

func writeUsersOnline(term *term.Terminal) {
	term.Write([]byte("Connected users:\n"))
	for _, user := range users {
		term.Write([]byte("- " + user.Hash + "\n"))
	}
}
func writeHelpMenu(term *term.Terminal) {
	term.Write([]byte("Available commands:\n" +
		"/help\t- show this help message\n" +
		"/pubkey\t- show your pubkey hash\n" +
		"/users\t- list all connected users\n" +
		"/message <user hash> <body>\t- send a direct message to a user\n\n" +
		"Message Board:\n" +
		"/post <message>\t- post a new discussion\n" +
		"/list\t- list all discussions\n" +
		"/replies <post number>\t- list all replies to a discussion\n" +
		"/reply <post number> <reply body>\t- reply to a discussion\n"))
}
