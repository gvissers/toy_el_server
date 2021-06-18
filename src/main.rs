//! # A toy Eternal Lands server
//!
//! This crate implements a toy server for the online MMORPG [Eternal Lands](http://www.eternal-lands.com).
//! I was created to investigate the possibilities of encrypting the network traffic between the
//! client and the server using TLS (or the highest supported variant of SSL supported by both
//! the client and the server. It is not meant as a serious server implementation, and does not do
//! much apart from logging some information abut incoming traffic and trying to set up an encrypted
//! connection. At the moment you cannot even log in using this server!

use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslStream};
use std::io::Read;
use std::io::Write;

/// The minimum protocol version required to set up an encrypted connection
const ENCRYPTION_PROTOCOL: (u16, u16) = (10, 29);

/// Convert a string in EL format to UTF-8. EL mostly uses ISO-8859-1, with certain byte values
/// interpreted as color codes. Color codes and other special characters are represented by
/// escape sequences in the output.
fn to_utf8(text: &[u8]) -> String
{
    const COLOR_TABLE: [&str; 7] = ["red", "orange", "yellow", "green", "blue", "purple", "gray1"];
    let mut res = String::new();
    for &b in text
    {
        match b
        {
            10        => { res += "\\n"; },
            127..=154 => { res += &format!("\\{}{}", COLOR_TABLE[((b-127)%7) as usize], 1+(b-127)/7); }
            _         =>  { res.push(b as char) }
        }
    }
    res
}

/// Convert a text string to EL format. Unrepresentable characters are replaced by a question
/// mark.
fn to_iso_8859_1(text: &str) -> impl Iterator<Item=u8> + '_
{
    text.chars().map(|c| { let x = c as u32; if x < 127 || (x > 154 && x < 256) { c as u8 } else { b'?' } })
}

/// Command codes for the server, sent by the client
#[derive(Clone, Copy, Debug)]
enum ServerCommand
{
    /// Text message
    RawText,
    /// Mystery, seems to be unhandled by the official server
    SendOpeningScreen = 9,
    /// Protocol and client version
    SendVersion,
    /// Heartbeat to keep the connection alive
    HeartBeat = 14,
    /// Response to encryption invitation
    LetsEncrypt = 101,
    /// Login attempt
    LogIn = 140
}

/// Command codes for the client, sent by the server
#[derive(Clone, Copy)]
enum ClientCommand
{
    /// Text message
    RawText,
    /// Invitation to encrypt the connection
    LetsEncrypt = 101,
    /// Login error message
    LogInNotOk = 251
}

#[derive(Clone, Copy)]
enum ChatChannel
{
//     Local,
//     Personal,
//     Guild,
    Server = 3,
//     Moderator,
//     Channel1,
//     Channel2,
//     Channel3,
//     ModeratorPM,
//     Popup = 0xff
}

/// The current encryption status of the connection
#[derive(Clone, Copy)]
enum EncryptionStatus
{
    /// Unencrypted
    Unencrypted,
    /// Unencrypted, invitiation to encrypt was sent to the client
    Invited,
    /// TLS is currently being set up
    Negotiating,
    /// Encrypted
    Encrypted
}

/// Enumeration for newtork streams
enum Socket
{
    /// Normal, unencrypted network stream
    Unencrypted(std::net::TcpStream),
    /// Encrypted stream
    Encrypted(SslStream<std::net::TcpStream>),
    /// Dummy stream, used to temporarily take ownership of an unencrypted connection to move it
    /// into an encrypted stream
    Dummy
}

impl Socket
{
    /// Set up an encrypted channel on this connection
    fn encrypt(&mut self, ssl_acceptor: &SslAcceptor) -> Result<(), String>
    {
        let socket = std::mem::replace(self, Socket::Dummy);
        if let Socket::Unencrypted(plain_socket) = socket
        {
            match ssl_acceptor.accept(plain_socket)
            {
                Ok(stream) => {
                    *self = Socket::Encrypted(stream);
                    println!("Connection is now encrypted");
                    Ok(())
                },
                Err(err) => {
                    eprintln!("Failed to encrypt the connection: {}", err);
                    Err(String::from("Failed to encrypt"))
                }
            }
        }
        else
        {
            // Well, that was pointless
            *self = socket;
            Ok(())
        }
    }
}

impl std::io::Read for Socket
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize>
    {
        match self
        {
            Socket::Unencrypted(stream) => stream.read(buf),
            Socket::Encrypted(stream) => stream.read(buf),
            Socket::Dummy => panic!("Read from dummy socket")
        }
    }
}

impl std::io::Write for Socket
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize>
    {
        match self
        {
            Socket::Unencrypted(stream) => stream.write(buf),
            Socket::Encrypted(stream) => stream.write(buf),
            Socket::Dummy => panic!("Write on dummy socket")
        }
    }

    fn flush(&mut self) -> std::io::Result<()>
    {
        match self
        {
            Socket::Unencrypted(stream) => stream.flush(),
            Socket::Encrypted(stream) => stream.flush(),
            Socket::Dummy => panic!("Flush on dummy socket")
        }
    }
}

/// Structure decribing a game client. Does not contain overly much at the moment :)
struct Client
{
    /// The network connection with the game client
    socket: Socket,
    /// The current status of encrypting the network connection
    encryption_status: EncryptionStatus
}

impl Client
{
    /// Crete a new client, connected on socket `socket`
    fn new(socket: std::net::TcpStream) -> Self
    {
        Client { socket: Socket::Unencrypted(socket), encryption_status: EncryptionStatus::Unencrypted }
    }

    /// Send a message with command code `cmd` and auxiliary data `data` to the client. `data` may
    /// be empty.
    fn send(&mut self, cmd: ClientCommand, data: &[u8]) -> Result<(), String>
    {
        let len = data.len() as u16 + 1;
        let mut msg = vec![cmd as u8];
        msg.push(len as u8);
        msg.push((len >> 8) as u8);
        msg.extend_from_slice(data);
        self.socket.write_all(&msg).map_err(|err| format!("Failed to send data: {}", err))
    }

    /// Send a text message in channel `channel` to the client.
    fn send_text(&mut self, channel: ChatChannel, text: &str) -> Result<(), String>
    {
        let mut msg = vec![channel as u8];
        msg.extend(to_iso_8859_1(text));
        self.send(ClientCommand::RawText, &msg)
    }

    /// Handle a version message with data `data` from the client. If the client version is recent
    /// enough, send back an invitation to encrypt the connection.
    fn handle_version(&mut self, data: &[u8]) -> Result<(), String>
    {
        if data.len() != 14
        {
            Err(format!("Invalid version packet length {}", data.len()))
        }
        else
        {
            let protocol_major = ((data[1] as u16) << 8) | data[0] as u16;
            let protocol_minor = ((data[3] as u16) << 8) | data[2] as u16;
            let client_major = data[4] as u8;
            let client_minor = data[5] as u8;
            let client_release = data[6] as u8;
            let client_build = data[7] as u8;
            let ip = &data[8..12];
            let port = ((data[13] as u16) << 8) | data[12] as u16;
            // We'll assume the client set the IP address and port number correctly
            println!("Got {:?}, protocol = {}.{}, client = {}.{}.{}.{}, IP = {}.{}.{}.{}, port = {}",
                ServerCommand::SendVersion,
                protocol_major, protocol_minor,
                client_major, client_minor, client_release, client_build,
                ip[0], ip[1], ip[2], ip[3], port);

            if (protocol_major, protocol_minor) > ENCRYPTION_PROTOCOL
            {
                // Let's see if the client wants to encrypt the connection
                self.send(ClientCommand::LetsEncrypt, &[])?;
                self.encryption_status = EncryptionStatus::Invited;
            }
            Ok(())
        }
    }

    /// Handle a login request from the client. Or rather, log the request, and tell the client we
    /// don't support logins.
    fn handle_login(&mut self, data: &[u8]) -> Result<(), String>
    {
        let len_data = data.len();
        if len_data == 0 || data[len_data-1] != 0
        {
            Err(String::from("Invalid login data"))
        }
        else
        {
            let mut it = data[..len_data-1].split(|&b| b == b' ');
            if let Some(username) = it.next()
            {
                if let Some(password) = it.next()
                {
                    println!("Log in {} with a {}-byte password", to_utf8(username), password.len());
                    self.send(ClientCommand::LogInNotOk, "Sorry, the Toy server does not accept logins".as_bytes())?;
                    Ok(())
                }
                else
                {
                    Err(String::from("No password in login attempt"))
                }
            }
            else
            {
                Err(String::from("No username in login attempt"))
            }
        }
    }

    /// Handle a reply to an encryption invitation. If the client wants to encrypt the connection,
    /// the next traffic on the connection will be the TLS handshake.
    fn handle_encryption_reply(&mut self, data: &[u8]) -> Result<(), String>
    {
        if data.len() == 0
        {
            Err(String::from("Invalid encryption reply"))
        }
        else
        {
            let encrypt = data[0] != 0;
            if encrypt
            {
                self.encryption_status = EncryptionStatus::Negotiating;
                println!("Client wants to encrypt");
            }
            else
            {
                self.encryption_status = EncryptionStatus::Unencrypted;
                println!("Client does not want to encrypt");
            }
            Ok(())
        }
    }

    /// Hndle an incomming message with command code `code` and auxiliary data `data`.
    fn handle_message(&mut self, code: u8, data: &[u8]) -> Result<(), String>
    {
        match Self::get_command(code)
        {
            None => { eprintln!("Got unknown opcode {}", code); },
            Some(cmd) => {
                match cmd
                {
                    ServerCommand::RawText => { println!("Got {:?}: {}", cmd, to_utf8(data)); },
                    ServerCommand::SendOpeningScreen => {
                        println!("Got {:?}", cmd);
                        // Looks like this may be ignored by the official server, but here we go:
                        self.send_text(ChatChannel::Server, "Welcome to the Toy Server!")?;
                    },
                    ServerCommand::SendVersion => { self.handle_version(data)?; },
                    ServerCommand::HeartBeat => { println!("Got {:?}", cmd); }
                    ServerCommand::LetsEncrypt => { self.handle_encryption_reply(data)?; },
                    ServerCommand::LogIn => { self.handle_login(data)?; }
                }
            }
        }
        Ok(())
    }

    /// Split the incoming data in `buffer` into messages, and handle these. If an incomplete
    /// message is left, it will be moved to the beginning of the buffer. Returns the new
    /// used size of the buffer.
    fn handle_packets(&mut self, buffer: &mut [u8]) -> Result<usize, String>
    {
        let mut offset = 0;
        while offset + 3 <= buffer.len()
        {
            let rem = &buffer[offset..];
            let msg_len = 2 + ((rem[2] as usize) << 8) + rem[1] as usize;
            if msg_len < 3 || msg_len > buffer.len()
            {
                return Err(String::from("Invalid message length"));
            }
            if msg_len > rem.len()
            {
                break;
            }

            let code = rem[0];
            let data = &rem[3..msg_len];
            self.handle_message(code, data)?;

            offset += msg_len;
        }
        let new_size = buffer.len() - offset;
        buffer.copy_within(offset.., 0);

        Ok(new_size)
    }

    /// Read data from the connection into buffer `buffer`, and return the number of bytes read.
    fn read_buffer(&mut self, buffer: &mut [u8]) -> Result<usize, String>
    {
        match self.socket.read(buffer)
        {
            Ok(0) => {
                eprintln!("Client shut down the connection");
                Err(String::from("Disconnected"))
            },
            Err(err) => {
                eprintln!("Failed to read from client socket: {}", err);
                Err(String::from("Read error"))
            },
            Ok(nr_bytes) => Ok(nr_bytes)
        }
    }

    /// Do a regular read of data into `buffer`, i.e. read as much as possible, and then handle
    /// any complete messages in the buffer. `buffer_used` is the number of bytes that are already
    /// in `buffer`; new data is appended after these. Returns the length of the buffer after
    /// reading and handling incoming messages.
    fn read_regular(&mut self, buffer: &mut [u8], buffer_used: usize) -> Result<usize, String>
    {
        let nr_bytes = self.read_buffer(&mut buffer[buffer_used..])?;
        self.handle_packets(&mut buffer[..buffer_used+nr_bytes])
            .map_err(|err| { eprintln!("Protocol error: {}", err); err })
    }

    /// Read at most a single message from the connection, and (if it is complete) process it.
    /// This is done after an invitation to encrypt the connection has been sent to the client,
    /// to prevent the server from reading the TLS handshake data as client messages. Returns
    /// the number of bytes in the buffer after reading and handling incoming messages.
    fn read_piecemeal(&mut self, buffer: &mut [u8], buffer_used: usize) -> Result<usize, String>
    {
        // Ensure no complete message is left in the buffer
        let mut used = self.handle_packets(&mut buffer[..buffer_used])
            .map_err(|err| { eprintln!("Protocol error: {}", err); err })?;

        if used < 3
        {
            // Read data up to the length field
            used += self.read_buffer(&mut buffer[used..3])?;
        }

        if used >= 3
        {
            // An incomplete message is left in the buffer, try to complete it
            let msg_len = 2 + ((buffer[2] as usize) << 8) | buffer[1] as usize;
            if msg_len < 3 || msg_len > buffer.len()
            {
                return Err(String::from("Invalid message length"));
            }

            if used < msg_len
            {
                used += self.read_buffer(&mut buffer[used..msg_len])?;
            }
            if used >= msg_len
            {
                used = self.handle_packets(&mut buffer[..buffer_used])
                    .map_err(|err| { eprintln!("Protocol error: {}", err); err })?;
            }
        }

        Ok(used)
    }

    /// The client event loop: read incoming data from the server, and handle the messages within.
    /// This loops runs until the client closes the connection, or an unrecoverable error occurs.
    fn handle_traffic(mut self, ssl_acceptor: std::sync::Arc<SslAcceptor>)
    {
        let mut buffer = [0u8; 8192];
        let mut buffer_used = 0;
        loop
        {
            match self.encryption_status
            {
                EncryptionStatus::Unencrypted|EncryptionStatus::Encrypted => {
                    match self.read_regular(&mut buffer, buffer_used)
                    {
                        Ok(len) => { buffer_used = len; }
                        Err(_) => { break; }
                    }
                },
                EncryptionStatus::Invited => {
                    match self.read_piecemeal(&mut buffer, buffer_used)
                    {
                        Ok(len) => { buffer_used = len; }
                        Err(_) => { break; }
                    }
                },
                EncryptionStatus::Negotiating => {
                    if self.socket.encrypt(&ssl_acceptor).is_err()
                    {
                        break;
                    }
                    self.encryption_status = EncryptionStatus::Encrypted;
                }
            }
        }
    }

    /// Turn a command code byte into the corresponding server command
    fn get_command(code: u8) -> Option<ServerCommand>
    {
        match code
        {
            0 => Some(ServerCommand::RawText),
            9 => Some(ServerCommand::SendOpeningScreen),
            10 => Some(ServerCommand::SendVersion),
            14 => Some(ServerCommand::HeartBeat),
            101 => Some(ServerCommand::LetsEncrypt),
            140 => Some(ServerCommand::LogIn),
            _ => None
        }
    }
}

fn main()
{
    let key_file_name = "toy_el_server.key";
    let certs_file_name = "toy_el_server.cert";

    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    if let Err(err) = acceptor.set_private_key_file(key_file_name, SslFiletype::PEM)
    {
        eprintln!("Failed to set private key from file \"{}\": {}", key_file_name, err);
    }
    else if let Err(err) = acceptor.set_certificate_chain_file(certs_file_name)
    {
        eprintln!("Failed to set certificates from file \"{}\": {}", certs_file_name, err);
    }
    else if let Err(err) = acceptor.check_private_key()
    {
        eprintln!("Private key check failed: {}", err);
    }
    else
    {
        let acceptor = std::sync::Arc::new(acceptor.build());

        match std::net::TcpListener::bind("localhost:2121")
        {
            Ok(listener) => {
                println!("Socket set up, waiting for connections");
                for stream in listener.incoming()
                {
                    match stream
                    {
                        Ok(socket) => {
                            println!("Got new client from {:?}", socket.peer_addr());
                            let acceptor = acceptor.clone();
                            std::thread::spawn(|| { Client::new(socket).handle_traffic(acceptor); });
                        },
                        Err(err) => {
                            eprintln!("Failed to accept a client: {}", err);
                        }
                    }
                }
            },
            Err(err) => {
                eprintln!("Failed to set up server socket: {}", err);
            }
        }
    }
}
