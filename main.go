package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

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

var users = make(map[string]*user)
var usersMutex sync.Mutex // Add a mutex to manage concurrent access to users
type user struct {
	pubkey string
	hash   string
	conn   ssh.Channel
}

func addUser(hash string, u *user) {
	usersMutex.Lock()
	defer usersMutex.Unlock()
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
				// defer channel.Close()
				go handleConnection(channel, sshConn, requests)
			}
		}(conn)
	}
}
func generateHash(pubkey string) string {
	h := sha3.NewShake256()
	h.Write([]byte(pubkey))
	checksum := make([]byte, 8)
	h.Read(checksum)
	return base64.StdEncoding.EncodeToString(checksum)
}
func disconnect(hash string) {
	removeUser(hash)
}
func broadcast(message string) {
	for _, user := range getAllUsers() {
		fmt.Fprintln(user.conn, message)
	}
}
func sendMessage(senderHash, recipientHash, message string, term *term.Terminal) {
	usersMutex.Lock()
	recipient, ok := users[recipientHash]
	usersMutex.Unlock()
	if !ok {
		fmt.Fprintf(users[senderHash].conn, "User with hash %s not found\n", recipientHash)
		return
	}
	message = fmt.Sprintf("\n--DIRECT MESSAGE--\n-- From %s--\n%s\n-------------------\n", senderHash, message)
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
	hash := generateHash(pubkey)
	addUser(hash, &user{pubkey: pubkey, hash: hash, conn: channel})
	term := term.NewTerminal(channel, "> ")
	welcome := `
                         
	

           BB           BB           BB           BB           BB           
           BB           BB           BB           BB           BB           
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

`

	term.Write([]byte(welcome))
	term.Write([]byte("Your pubkey hash is " + hash + "\nType /help for help.\n\n"))
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
		if strings.HasPrefix(input, "/help") {
			term.Write([]byte("Available commands:\n"))
			term.Write([]byte("/help\t- show this help message\n"))
			term.Write([]byte("/pubkey\t- show your pubkey hash\n"))
			term.Write([]byte("/users\t- list all connected users\n"))
			term.Write([]byte("/message <user hash> <body>\t- send a direct message to a user\n"))
		} else if strings.HasPrefix(input, "/users") {
			term.Write([]byte("Connected users:\n"))
			for _, user := range users {
				term.Write([]byte("- "))
				term.Write([]byte(user.hash))
				term.Write([]byte("\n"))
			}
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
		} else {
			message := fmt.Sprintf("[%s]: %s", hash, input)
			broadcast(message)
		}
	}
}
