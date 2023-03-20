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
	"strings"
	"sync"
	"unicode"

	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

var users = make(map[string]*user)
var usersMutex sync.Mutex

var messageCache *list.List

type user struct {
	pubkey  string
	hash    string
	conn    ssh.Channel
	ignored map[string]bool
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
	u.ignored = make(map[string]bool)
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
				go handleConnection(channel, sshConn, requests)
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
		if _, ignored := user.ignored[sender]; !ignored {
			fmt.Fprintln(user.conn, "\r\n"+message)
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
		fmt.Fprintf(users[senderHash].conn, "\n\rUser with hash %s not found\n", recipientHash)
		return
	}
	if recipient.ignored[senderHash] {
		return
	}
	message = "\r\n[DirectMessage][" + senderHash + "]> " + message + "\r\n"
	fmt.Fprintln(recipient.conn, message)
	term.Write([]byte(message))
}

func handleConnection(channel ssh.Channel, sshConn *ssh.ServerConn, requests <-chan *ssh.Request) {
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
	addUser(hash, &user{pubkey: pubkey, hash: hash, conn: channel})
	term := term.NewTerminal(channel, "\r\n> ")
	welcome := `

           BB           BB           BB           BB           BB           
,adPPYba,  BB,dPPYba,   BB,dPPYba,   BB,dPPYba,   BB,dPPYba,   BB,dPPYba,   
I8[    ""  BBP'    "8a  BBP'    "8a  BBP'    "8a  BBP'    "8a  BBP'    "8a  
'"Y8ba,    BB       BB  BB       BB  BB       BB  BB       d8  BB       d8  
aa    ]8I  BB       BB  BB       BB  BB       BB  BBb,   ,a8"  BBb,   ,a8"  
'"YbbdP"'  BB       BB  BB       BB  BB       BB  8Y"Ybbd8"'   8Y"Ybbd8"'   BBS
> MIT 2023, https://github.com/donuts-are-good/shhhbb v.0.0.1 alpha		    

 [RULES]                         [GOALS]
  - your words are your own       - a space for hackers & devs
  - your eyes are your own        - make cool things
  - no logs are kept              - collaborate & share
  - have fun :)                   - evolve

Say hello and press [enter] to chat

`
	printCachedMessages(term)
	term.Write([]byte(welcome))
	term.Write([]byte("You are " + hash + "\nType /help for help.\n\n"))
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
		}
		if strings.HasPrefix(input, "/ignore") {
			parts := strings.Split(input, " ")
			if len(parts) != 2 {
				term.Write([]byte("Usage: /ignore <user hash>\n"))
				continue
			}
			ignoredUser := parts[1]
			users[hash].ignored[ignoredUser] = true
			term.Write([]byte("User " + ignoredUser + " is now ignored.\n"))
		} else if strings.HasPrefix(input, "/help") {
			writeHelpMenu(term)
		} else if strings.HasPrefix(input, "/users") {
			writeUsersOnline(term)
		} else if strings.HasPrefix(input, "/pubkey") {
			term.Write([]byte("Your pubkey hash: " + hash + "\n"))
		} else if strings.HasPrefix(input, "/nick") {
			term.Write([]byte("Change your nick..."))
			parts := strings.Split(input, " ")
			if len(parts) < 2 {
				term.Write([]byte("Usage: /nick <newname>\n"))
				continue
			} else if len(parts) > 2 {
				term.Write([]byte("Usage: /nick <newname>\n"))
			}
			term.Write([]byte("We received: @" + input))
			cleanedInput, cleanedInputErr := cleanString(input)
			if cleanedInputErr != nil {
				term.Write([]byte("There was an error handling your name change..."))
			}
			term.Write([]byte("Bytes accepted: @" + cleanedInput))
			// this may need to be a per-session change.
			hash = cleanedInput
			term.Write([]byte("Name changed to: @" + cleanedInput))
		} else if strings.HasPrefix(input, "/message") {
			parts := strings.Split(input, " ")
			if len(parts) < 3 {
				term.Write([]byte("Usage: /message <user hash> <direct message text>\n"))
				continue
			}
			recipientHash := parts[1]
			message := strings.Join(parts[2:], " ")
			sendMessage(hash, recipientHash, message, term)
		} else {
			message := fmt.Sprintf("[%s]: %s", hash, input)
			if len(input) > 0 || !strings.HasPrefix(input, "/") {
				broadcast(message + "\r")
			}
		}
	}
}

func writeUsersOnline(term *term.Terminal) {
	term.Write([]byte("Connected users:\n"))
	for _, user := range users {
		term.Write([]byte("- " + user.hash + "\n"))
	}
}
func writeHelpMenu(term *term.Terminal) {
	term.Write([]byte("Available commands:\n/help\t- show this help message\n/pubkey\t- show your pubkey hash\n/users\t- list all connected users\n/message <user hash> <body>\t- send a direct message to a user\n"))
}
