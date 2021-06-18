# A toy Eternal Lands server

This crate implements a toy server for the online MMORPG [Eternal Lands](http://www.eternal-lands.com).
It was created to investigate the possibilities of encrypting the network traffic between the
client and the server using TLS (or the highest supported variant of SSL supported by both
the client and the server). It is not meant as a serious server implementation, and does not do
much apart from logging some information abut incoming traffic and trying to set up an encrypted
connection. At the moment you cannot even log in using this server!

## Installation

Compile the program:
```
cargo build
```
Generate a certificate and private key using the provided script:
```
./gen_cert_key.sh
```
And start the server:
```
./target/debug/toy_el_server # or "cargo run"
```
The server will listen for new connection on port 2121 on localhost.

