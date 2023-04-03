<img width="737" alt="image" src="https://user-images.githubusercontent.com/96031819/228712817-54829adf-1dd3-48b4-ba14-16fc53d0e7fd.png">

# shhhbb
ed25519 based BBS & chat over SSH


![donuts-are-good's followers](https://img.shields.io/github/followers/donuts-are-good?&color=555&style=for-the-badge&label=followers) ![donuts-are-good's stars](https://img.shields.io/github/stars/donuts-are-good?affiliations=OWNER%2CCOLLABORATOR&color=555&style=for-the-badge) ![donuts-are-good's visitors](https://komarev.com/ghpvc/?username=donuts-are-good&color=555555&style=for-the-badge&label=visitors)

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
