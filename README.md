<img width="737" alt="image" src="https://user-images.githubusercontent.com/96031819/228712817-54829adf-1dd3-48b4-ba14-16fc53d0e7fd.png">

![donuts-are-good's followers](https://img.shields.io/github/followers/donuts-are-good?&color=555&style=for-the-badge&label=followers) ![donuts-are-good's stars](https://img.shields.io/github/stars/donuts-are-good?affiliations=OWNER%2CCOLLABORATOR&color=555&style=for-the-badge) ![donuts-are-good's visitors](https://komarev.com/ghpvc/?username=donuts-are-good&color=555555&style=for-the-badge&label=visitors)

# shhhbb
ssh based BBS & chat over SSH

<video controls>
  <source src="https://user-images.githubusercontent.com/96031819/225815939-1e7c5837-30c9-4d5b-938e-4dcb1b710401.mp4" type="video/mp4">
</video>

![demo video link](https://user-images.githubusercontent.com/96031819/225815939-1e7c5837-30c9-4d5b-938e-4dcb1b710401.mp4)

**try it**: `ssh -p 2223 shhhbb.com`


**instructions:** 
1. create a directory called `./keys` 
2. generate an ed25519 keypair in there without password
`ssh-keygen -t ed25519 -C "my cool keypair" -f ./keys/ssh_host_ed25519_key`
3. launch with `./shhhbb 2223` where `2223` is the port

connect with `ssh -o "ForwardAgent=no" -o "IdentitiesOnly=yes" -p 2223 shhhbb.com` where shhhbb.com is your domain or ip

## api 

the api is designed to allow users to create and retrieve chat messages and posts. it is secured with token-based authentication using bearer tokens.

### base url

http://localhost:8080

### authentication
all endpoints require authentication with a bearer token. to obtain a bearer token, the user must first log in and then authenticate themselves with their token in subsequent requests.

```
/token new
/token list
/token revoke
```

### endpoints

**get /chat/messages**
*retrieve the last 100 chat messages.*

- parameters: none
- authentication: bearer token required
- response: a json object with a boolean success field and an array data field containing objects with the following properties:
  - sender: the hash of the message sender
  - message: the message body
  - timestamp: the time the message was sent in iso 8601 format

**post /chat/create**
*create a new chat message.*

- parameters:
  - sender_hash: the hash of the message sender
  - message: the message body
- authentication: bearer token required
- response: a json object with a boolean success field

**post /chat/direct/create**
*create a new direct message.*

- parameters:
  - sender: the hash of the message sender
  - recipient: the hash of the message recipient
  - message: the message body
- authentication: bearer token required
- response: a json object with a boolean success field

**get /posts/list**
*retrieve a list of posts.*

- parameters: none
- authentication: bearer token required
- response: a json object with a boolean success field and an array data field containing objects with the following properties:
  - post_id: the id of the post
  - author_hash: the hash of the post author
  - post_body: the post body
  - timestamp: the time the post was created in iso 8601 format

**post /posts/create**
*create a new post.*

- parameters:
  - author_hash: the hash of the post author
  - post_body: the post body
- authentication: bearer token required
- response: a json object with a boolean success field

**get /posts/replies**
*retrieve a list of replies to a post.*

- parameters:
  - post_id: the id of the post to retrieve replies for
- authentication: bearer token required
- response: a json object with a boolean success field and an array data field containing objects with the following properties:
  - reply_id: the id of the reply
  - post_id: the id of the post being replied to
  - author_hash: the hash of the reply author
  - reply_body: the reply body
  - timestamp: the time the reply was created in iso 8601 format

**post /posts/reply**
*create a new reply to a post.*

- parameters:
  - post_id: the id of the post being replied to
  - author_hash: the hash of the reply author
  - reply_body: the reply body
- authentication: bearer token required
- response: a json object with a boolean success field