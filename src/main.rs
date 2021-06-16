use std::io::Read;
use std::io::Write;

#[derive(Clone, Copy, Debug)]
enum ServerCommand
{
    RawText,
    SendOpeningScreen = 9,
    SendVersion,
    HeartBeat = 14,
    Invalid
}

#[derive(Clone, Copy)]
enum ClientCommand
{
    RawText
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

const CMD_LUT: [ServerCommand; 16] = [
    ServerCommand::RawText,
    ServerCommand::Invalid,
    ServerCommand::Invalid,
    ServerCommand::Invalid,
    ServerCommand::Invalid,
    ServerCommand::Invalid,
    ServerCommand::Invalid,
    ServerCommand::Invalid,
    ServerCommand::Invalid,
    ServerCommand::SendOpeningScreen,
    ServerCommand::SendVersion,
    ServerCommand::Invalid,
    ServerCommand::Invalid,
    ServerCommand::Invalid,
    ServerCommand::HeartBeat,
    ServerCommand::Invalid,
];

fn get_command(code: u8) -> Option<ServerCommand>
{
    ((code as usize) < CMD_LUT.len()).then(|| CMD_LUT[code as usize])
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

fn send(client: &mut std::net::TcpStream, cmd: ClientCommand, data: &[u8]) -> Result<(), String>
{
    let len = data.len() as u16 + 1;
    let mut msg = vec![cmd as u8];
    msg.push(len as u8);
    msg.push((len >> 8) as u8);
    msg.extend_from_slice(data);
    client.write_all(&msg).map_err(|err| format!("Failed to send data: {}", err))
}

fn send_text(client: &mut std::net::TcpStream, channel: ChatChannel, text: &str) -> Result<(), String>
{
    let mut msg = vec![channel as u8];
    // Taking a shortcut here, assuming text is strict ascii
    msg.extend_from_slice(text.as_bytes());
    send(client, ClientCommand::RawText, &msg)
}

fn handle_version(data: &[u8]) -> Result<(), String>
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
        Ok(())
    }
}

fn handle_message(client: &mut std::net::TcpStream, code: u8, data: &[u8]) -> Result<(), String>
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
                    send_text(client, ChatChannel::Server, "Welcome to the EL Toy Server!")?;
                },
                ServerCommand::SendVersion => { handle_version(data)?; },
                ServerCommand::HeartBeat => { println!("Got {:?}", cmd); },
                ServerCommand::Invalid => { println!("Got {:?} {}", cmd, code); }
            }
        }
    }
    Ok(())
}

fn handle_packets(client: &mut std::net::TcpStream, buffer: &mut [u8]) -> Result<usize, String>
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
        handle_message(client, code, data)?;

        offset += msg_len;
    }
    let new_size = buffer.len() - offset;
    buffer.copy_within(offset.., 0);

    Ok(new_size)
}

fn handle_client(mut client: std::net::TcpStream)
{
    let mut buffer = [0u8; 8192];
    let mut buffer_used = 0;
    loop
    {
        match client.read(&mut buffer[buffer_used..])
        {
            Ok(0) => {
                println!("Client shut down the connection");
                break;
            },
            Ok(nr_bytes) => {
                buffer_used += nr_bytes;
                match handle_packets(&mut client, &mut buffer[..buffer_used])
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

fn main()
{
    match std::net::TcpListener::bind("localhost:2121")
    {
        Ok(listener) => {
            println!("Socket set up, waiting for connections");
            for stream in listener.incoming()
            {
                match stream
                {
                    Ok(client) => {
                        println!("Got new client from {:?}", client.peer_addr());
                        std::thread::spawn(|| { handle_client(client); });
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
