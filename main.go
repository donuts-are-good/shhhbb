package main

import (
	"bufio"
	"container/list"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func init() {
	messageCache = list.New()
}
func main() {
	// whitelist, err := loadPubkeyList("whitelist.txt")
	// if err != nil {
	// 	log.Printf("Error loading whitelist: %v", err)
	// 	return
	// }

	// blacklist, err := loadPubkeyList("blacklist.txt")
	// if err != nil {
	// 	log.Printf("Error loading blacklist: %v", err)
	// 	return
	// }

	db := initSqliteDB()
	if db == nil {
		log.Panic("couldn't load main db")
		return
	}
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

	go api(db)

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
				// go handleConnection(db, channel, sshConn, requests, whitelist, blacklist)
				go handleConnection(db, channel, sshConn, requests)
			}
		}(conn)
	}
}

// func handleConnection(db *sqlx.DB, channel ssh.Channel, sshConn *ssh.ServerConn, requests <-chan *ssh.Request, whitelist map[string]bool, blacklist map[string]bool) {
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
	hash := formatUsernameFromPubkey(pubkey)

	// if _, ok := whitelist[hash]; !ok {
	// 	fmt.Fprintln(channel, "You are not authorized to connect to this server.")
	// 	disconnect(hash)
	// 	return
	// }

	// if _, ok := blacklist[hash]; ok {
	// 	fmt.Fprintln(channel, "You have been banned from this server.")
	// 	disconnect(hash)
	// 	return
	// }

	addUser(hash, &user{Pubkey: pubkey, Hash: hash, Conn: channel})

	term := term.NewTerminal(channel, "")
	term.SetPrompt("")
	saveCursorPos(channel)

	restoreCursorPos(channel)

	welcome := welcomeMessageAscii()

	term.Write([]byte(welcome))
	printMOTD(loadMOTD(motdFilePath), term)
	printCachedMessages(term)
	term.Write([]byte("\nWelcome :) You are " + hash + "\n"))
	for {
		input, err := term.ReadLine()
		if err != nil {
			if err == io.EOF {
				disconnect(hash)
				return
			}
			readlineErrCheck(term, err, hash)
			return
		}

		switch {
		case strings.HasPrefix(input, "/ignore"):
			handleIgnore(input, term, hash)
		case strings.HasPrefix(input, "/help") || strings.HasPrefix(input, "/?"):
			writeHelpMenu(term)
		case strings.HasPrefix(input, "/license"):
			writeLicenseProse(term)
		case strings.HasPrefix(input, "/version"):
			writeVersionInfo(term)
		case strings.HasPrefix(input, "/users"):
			writeUsersOnline(term)
		case strings.HasPrefix(input, "/bulletin") || strings.HasPrefix(input, "/motd"):
			printMOTD(motdFilePath, term)
		case strings.HasPrefix(input, "/pubkey"):
			term.Write([]byte("Your pubkey hash: " + hash + "\n"))
		case strings.HasPrefix(input, "/message"):
			handleMessage(input, term, hash)
		case strings.HasPrefix(input, "/post"):
			handlePost(input, term, db, hash)
		case strings.HasPrefix(input, "/list"):
			listDiscussions(db, term)
		case strings.HasPrefix(input, "/history"):
			printCachedMessages(term)
		case strings.HasPrefix(input, "/tokens new"):
			handleTokenNew(db, term, hash)
		case strings.HasPrefix(input, "/tokens list"):
			handleTokenList(db, term, hash)
		case strings.HasPrefix(input, "/tokens revoke"):
			handleTokenRevoke(db, input, term, hash)
		case strings.HasPrefix(input, "/quit") || strings.HasPrefix(input, "/q") ||
			strings.HasPrefix(input, "/exit") || strings.HasPrefix(input, "/x") ||
			strings.HasPrefix(input, "/leave") || strings.HasPrefix(input, "/part"):
			disconnect(hash)
		case strings.HasPrefix(input, "/replies"):
			handleReplies(input, term, db)
		case strings.HasPrefix(input, "/reply"):
			handleReply(input, term, db, hash)
		default:
			if len(input) > 0 {
				if strings.HasPrefix(input, "/") {
					term.Write([]byte("Unrecognized command. Type /help for available commands.\n"))
				} else {
					message := fmt.Sprintf("[%s] %s: %s", time.Now().String()[11:16], hash, input)
					broadcast(hash, message+"\r")
				}
			}
		}
	}
}

// func loadPubkeyList(filename string) (map[string]bool, error) {
// 	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0644)
// 	if err != nil {
// 		return nil, fmt.Errorf("unable to open %s: %v", filename, err)
// 	}
// 	defer file.Close()

// 	pubkeyList := make(map[string]bool)

// 	scanner := bufio.NewScanner(file)
// 	for scanner.Scan() {
// 		pubkey := scanner.Text()
// 		pubkeyList[pubkey] = true
// 	}

// 	if err := scanner.Err(); err != nil {
// 		return nil, fmt.Errorf("error reading %s: %v", filename, err)
// 	}

// 	return pubkeyList, nil
// }

func saveCursorPos(channel ssh.Channel) {
	writeString(channel, "\033[s")
}

func restoreCursorPos(channel ssh.Channel) {
	writeString(channel, "\033[u")
}

func moveCursorUp(channel ssh.Channel, n int) {
	writeString(channel, fmt.Sprintf("\033[%dA", n))
}
func moveCursorDown(w io.Writer, lines int) {
	fmt.Fprintf(w, "\033[%dB", lines)
}
func writeString(channel ssh.Channel, s string) {
	channel.Write([]byte(s))
}

func generateHash(pubkey string) string {
	h := sha3.NewShake256()
	h.Write([]byte(pubkey))
	checksum := make([]byte, 16)
	h.Read(checksum)
	return base64.StdEncoding.EncodeToString(checksum)
}

func disconnect(hash string) {
	usersMutex.Lock()
	user, exists := users[hash]
	usersMutex.Unlock()

	if exists {
		user.Conn.Close()
	}

	removeUser(hash)
}

func broadcast(senderHash, message string) {
	addToCache(message)
	for _, user := range getAllUsers() {
		if user.Hash == senderHash {
			continue
		}
		saveCursorPos(user.Conn)
		moveCursorUp(user.Conn, 1)
		fmt.Fprintln(user.Conn, message)
		restoreCursorPos(user.Conn)
		moveCursorDown(user.Conn, 1)
		fmt.Fprint(user.Conn, "\n")
		if user.Conn == nil {
			log.Printf("broadcast: user with hash %v has nil connection\n", user.Hash)
			continue
		}
		log.Printf("Broadcasted message to user with hash %v\n", user.Hash)
	}
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
	var discussions []struct {
		ID         int    `db:"id"`
		Author     string `db:"author"`
		Message    string `db:"message"`
		ReplyCount int    `db:"reply_count"`
	}
	err := db.Select(&discussions, `
		SELECT d.id, d.author, d.message, COUNT(r.id) as reply_count
		FROM discussions d
		LEFT JOIN replies r ON d.id = r.discussion_id
		GROUP BY d.id
	`)
	if err != nil {
		log.Printf("Error retrieving discussions: %v", err)
		term.Write([]byte("Error retrieving discussions.\n"))
		return
	}

	sort.Slice(discussions, func(i, j int) bool {
		weightID := 0.3
		weightReplyCount := 0.7

		scoreI := weightID*float64(discussions[i].ID) + weightReplyCount*float64(discussions[i].ReplyCount)
		scoreJ := weightID*float64(discussions[j].ID) + weightReplyCount*float64(discussions[j].ReplyCount)

		return scoreI > scoreJ
	})

	term.Write([]byte("Discussions:\n\n[id.]\t[💬replies]\t[topic]\n\n"))
	for _, disc := range discussions {
		term.Write([]byte(fmt.Sprintf("%d.\t💬%d\t[%s] %s\n", disc.ID, disc.ReplyCount, disc.Author, disc.Message)))
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
func printMOTD(motd string, term *term.Terminal) {
	if motd != "" {
		term.Write([]byte(motd + "\r\n"))
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
	message = "\r\n[DirectMessage][" + senderHash + "] " + message + "\r\n"
	fmt.Fprintln(recipient.Conn, message)
	term.Write([]byte(message))
}

func loadMOTD(motdFilePath string) string {

	var motdMessage string
	file, err := os.Open(motdFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			os.Create(motdFilePath)
			if err != nil {
				log.Println("we weren't able to create it either: " + err.Error())
				return ""
			}
			log.Println("motd didn't exist: " + err.Error())
			return ""
		}
		log.Println("error opening motdFilePath: " + err.Error())
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "#") {
			motdMessage += line + "\n"
		}
	}

	return motdMessage
}

func handleReply(input string, term *term.Terminal, db *sqlx.DB, hash string) error {
	parts := strings.SplitN(input, " ", 3)
	if len(parts) < 3 {
		return fmt.Errorf("usage: /reply <post number> <reply body>")
	}
	postNum, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("invalid post number. Usage: /reply <post number> <reply body>")
	}
	replyBody := parts[2]
	replySuccess := addReply(db, postNum, hash, replyBody)
	if !replySuccess {
		return fmt.Errorf("failed to reply to post. Please check the post number and try again")
	} else {
		term.Write([]byte("Reply successfully added to post.\n"))
		return nil
	}
}

func handleReplies(input string, term *term.Terminal, db *sqlx.DB) {
	parts := strings.SplitN(input, " ", 2)
	if len(parts) < 2 {
		term.Write([]byte("Usage: /replies <post number>\n"))
		return
	}
	postNum, err := strconv.Atoi(parts[1])
	if err != nil {
		term.Write([]byte("Invalid post number. Usage: /replies <post number>\n"))
		return
	}
	listReplies(db, postNum, term)
}

func handleIgnore(input string, term *term.Terminal, hash string) {
	parts := strings.Split(input, " ")
	if len(parts) != 2 {
		term.Write([]byte("Usage: /ignore <user hash>\n"))
		return
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
}

func readlineErrCheck(term *term.Terminal, err error, hash string) {
	term.Write([]byte("Error reading input: "))
	term.Write([]byte(err.Error()))
	term.Write([]byte("\n"))
	disconnect(hash)
}

func handlePost(input string, term *term.Terminal, db *sqlx.DB, hash string) {
	parts := strings.SplitN(input, " ", 2)
	if len(parts) < 2 {
		term.Write([]byte("Usage: /post <message>\n"))
	} else {
		postNumber := addDiscussion(db, hash, parts[1])
		term.Write([]byte(fmt.Sprintf("Posted new discussion with post number %d.\n", postNumber)))
	}
}

func handleMessage(input string, term *term.Terminal, hash string) {
	parts := strings.Split(input, " ")
	if len(parts) < 3 {
		term.Write([]byte("Usage: /message <user hash> <direct message text>\n"))
	} else {
		recipientHash := parts[1]
		message := strings.Join(parts[2:], " ")
		sendMessage(hash, recipientHash, message, term)
	}
}

func formatUsernameFromPubkey(pubkey string) string {
	hash, err := cleanString(generateHash(pubkey))
	if err != nil {
		log.Println("error generating username: ", err)
	}
	hash = "@" + hash
	return hash
}

func welcomeMessageAscii() string {
	welcome := `

           BB           BB           BB           BB           BB           
,adPPYba,  BB,dPPYba,   BB,dPPYba,   BB,dPPYba,   BB,dPPYba,   BB,dPPYba,   
I8[    ""  BBP'    "8a  BBP'    "8a  BBP'    "8a  BBP'    "8a  BBP'    "8a  
'"Y8ba,    BB       BB  BB       BB  BB       BB  BB       d8  BB       d8  
aa    ]8I  BB       BB  BB       BB  BB       BB  BBb,   ,a8"  BBb,   ,a8"  
'"YbbdP"'  BB       BB  BB       BB  BB       BB  8Y"Ybbd8"'   8Y"Ybbd8"'   BBS
> MIT 2023, https://github.com/donuts-are-good/shhhbb ` + semverInfo + `   

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
	term.Write([]byte(`
[General Commands]
	/help		
		- show this help message
	/pubkey		
		- show your pubkey hash, which is also your username
	/users		
		- list all online users
	/message <user hash> <body> 
		- ex: /message @A1Gla593 hey there friend
		- send a direct message to a user
	/quit, /q, /exit, /x
		- disconnect, exit, goodbye

[Chat commands]
	/history
		- reloads the last 100 lines of chat history

[Message Board]
	/post <message>
		- ex: /post this is my cool title
		- posts a new discussion topic 
	/list
		- list all discussions 
	/replies <post number>
		- ex: /replies 1
		- list all replies to a discussion
	/reply <post number> <reply body>
		- ex: /reply 1 hello everyone
		- reply to a discussion

[API Commands]
	/tokens new
		- create a new shhhbb API token 
	/tokens list
		- view your shhhbb API tokens
	/tokens revoke <token>
		- revoke an shhhbb API token

[Misc. Commands]
	/license
		- display the license text for shhhbb 
	/version
		- display the shhhbb version information	
	
` + "\n"))
}
func writeLicenseProse(term *term.Terminal) {
	term.Write([]byte(`
MIT License
Copyright (c) 2023 donuts-are-good https://github.com/donuts-are-good
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`))
}
func writeVersionInfo(term *term.Terminal) {
	term.Write([]byte(`
shhhbb bbs ` + semverInfo + `
MIT License 2023 donuts-are-good
https://github.com/donuts-are-good/shhhbb
`))
}
