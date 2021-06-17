use openssl::ssl::{SslConnector, SslMethod};
use std::io::Read;
use std::io::Write;

struct Client
{
    socket: std::net::TcpStream
}

impl Client
{
    fn new(socket: std::net::TcpStream) -> Self
    {
        Client { socket }
    }

    fn send(&mut self, cmd: ClientCommand, data: &[u8]) -> Result<(), String>
    {
        let len = data.len() as u16 + 1;
        let mut msg = vec![cmd as u8];
        msg.push(len as u8);
        msg.push((len >> 8) as u8);
        msg.extend_from_slice(data);
        self.socket.write_all(&msg).map_err(|err| format!("Failed to send data: {}", err))
    }

    fn send_text(&mut self, channel: ChatChannel, text: &str) -> Result<(), String>
    {
        let mut msg = vec![channel as u8];
        // Taking a shortcut here, assuming text is strict ascii
        msg.extend_from_slice(text.as_bytes());
        self.send(ClientCommand::RawText, &msg)
    }

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
            // Let's assume the client set the IP address and port number correctly
            println!("Got {:?}, protocol = {}.{}, client = {}.{}.{}.{}, IP = {}.{}.{}.{}, port = {}",
                ServerCommand::SendVersion,
                protocol_major, protocol_minor,
                client_major, client_minor, client_release, client_build,
                ip[0], ip[1], ip[2], ip[3], port);

            if protocol_major >= 11
            {
                // Let's see if the client wants to encrypt the connection
                self.send(ClientCommand::LetsEncrypt, &[]);
            }
            Ok(())
        }
    }

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
                    self.send(ClientCommand::LogInNotOk, "Sorry, the Toy server does not accept logins".as_bytes());
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

    fn handle_message(&mut self, code: u8, data: &[u8]) -> Result<(), String>
    {
        match get_command(code)
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
                    ServerCommand::LetsEncrypt => { /* ignore for now */ },
                    ServerCommand::LogIn => { self.handle_login(data)?; }
                }
            }
        }
        Ok(())
    }

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

    fn handle_traffic(mut self)
    {
        let mut buffer = [0u8; 8192];
        let mut buffer_used = 0;
        loop
        {
            match self.socket.read(&mut buffer[buffer_used..])
            {
                Ok(0) => {
                    println!("Client shut down the connection");
                    break;
                },
                Ok(nr_bytes) => {
                    buffer_used += nr_bytes;
                    match self.handle_packets(&mut buffer[..buffer_used])
                    {
                        Ok(len) => { buffer_used = len; },
                        Err(err) => { eprintln!("Protocol error: {}", err); break; }
                    }
                },
                Err(err) => {
                    eprintln!("Failed to read from client socket: {}", err);
                    break;
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum ServerCommand
{
    RawText,
    SendOpeningScreen = 9,
    SendVersion,
    HeartBeat = 14,
    LetsEncrypt = 101,
    LogIn = 140
}

#[derive(Clone, Copy)]
enum ClientCommand
{
    RawText,
    LetsEncrypt = 101,
    LogInNotOk = 251
}

#[derive(Clone, Copy)]
enum ChatChannel
{
    Local,
    Personal,
    Guild,
    Server,
    Moderator,
    Channel1,
    Channel2,
    Channel3,
    ModeratorPM,
    Popup = 0xff
}

fn get_command(code: u8) -> Option<ServerCommand>
{
    match code
    {
          0 => Some(ServerCommand::RawText),
          9 => Some(ServerCommand::SendOpeningScreen),
         10 => Some(ServerCommand::SendVersion),
         14 => Some(ServerCommand::HeartBeat),
        140 => Some(ServerCommand::LogIn),
          _ => None
    }
}

fn to_utf8(text: &[u8]) -> String
{
    let mut res = String::new();
    for &b in text
    {
        match b
        {
            10       => { res += "\\n"; },
            32..=126 => { res.push(b as char) },
            127      => { res += "\\{red1}"; },
            128      => { res += "\\{orange1}"; },
            129      => { res += "\\{yellow1}"; },
            130      => { res += "\\{green1}"; },
            131      => { res += "\\{blue1}"; },
            132      => { res += "\\{purple1}"; },
            133      => { res += "\\{gray1}"; },
            134      => { res += "\\{red2}"; },
            135      => { res += "\\{orange2}"; },
            136      => { res += "\\{yellow2}"; },
            137      => { res += "\\{green2}"; },
            138      => { res += "\\{blue2}"; },
            139      => { res += "\\{purple2}"; },
            140      => { res += "\\{gray2}"; },
            141      => { res += "\\{red3}"; },
            142      => { res += "\\{orange3}"; },
            143      => { res += "\\{yellow3}"; },
            144      => { res += "\\{green3}"; },
            145      => { res += "\\{blue3}"; },
            146      => { res += "\\{purple3}"; },
            147      => { res += "\\{gray3}"; },
            148      => { res += "\\{red4}"; },
            149      => { res += "\\{orange4}"; },
            150      => { res += "\\{yellow4}"; },
            151      => { res += "\\{green4}"; },
            152      => { res += "\\{blue4}"; },
            153      => { res += "\\{purple4}"; },
            154      => { res += "\\{gray4}"; },
            193      => { res.push('Á'); },
            196      => { res.push('Ä'); },
            197      => { res.push('Å'); },
            198      => { res.push('Æ'); },
            201      => { res.push('É'); },
            205      => { res.push('Í'); },
            209      => { res.push('Ñ'); },
            211      => { res.push('Ó'); },
            214      => { res.push('Ö'); },
            216      => { res.push('Ø'); },
            218      => { res.push('Ú'); },
            220      => { res.push('Ü'); },
            223      => { res.push('ß'); },
            224      => { res.push('à'); },
            225      => { res.push('á'); },
            226      => { res.push('â'); },
            228      => { res.push('ä'); },
            229      => { res.push('å'); },
            230      => { res.push('æ'); },
            231      => { res.push('ç'); },
            232      => { res.push('è'); },
            233      => { res.push('é'); },
            234      => { res.push('ê'); },
            235      => { res.push('ë'); },
            236      => { res.push('ì'); },
            237      => { res.push('í'); },
            239      => { res.push('ï'); },
            241      => { res.push('ñ'); },
            242      => { res.push('ò'); },
            243      => { res.push('ó'); },
            244      => { res.push('ô'); },
            246      => { res.push('ö'); },
            248      => { res.push('ø'); },
            249      => { res.push('ù'); },
            250      => { res.push('ú'); },
            252      => { res.push('ü'); },
            _        => { res.push('�'); }
        }
    }
    res
}

fn main()
{
    let mut ctx = SslConnector::builder(SslMethod::tls()).unwrap();
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
                        std::thread::spawn(|| { Client::new(socket).handle_traffic(); });
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
