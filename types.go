package main

import (
	"container/list"
	"sync"

	"golang.org/x/crypto/ssh"
)

var users = make(map[string]*user)
var usersMutex sync.Mutex
var messageCache *list.List
var semverInfo = "v0.4.0"
var motdFilePath = "./general-motd.txt"

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
