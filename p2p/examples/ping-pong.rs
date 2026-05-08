//! Performs handshake and responds to all [`Ping`] requests with [`Pong`].
//!
//! The protocol version used is 70015.
//!
//! To run, provide the required positional args, for example:
//! cargo run --example ping-pong <remote-ip> <network>
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, process};

use bitcoin_p2p_min::message::{Empty, Ping, Pong};
use bitcoin_p2p_min::message_compact_blocks::SendCmpct;
use bitcoin_p2p_min::message_network::{ClientSoftwareVersion, UserAgent, UserAgentVersion};
use bitcoin_p2p_min::{
    self, address, message, message_network, Magic, NetworkExt, ProtocolVersion, ServiceFlags,
};
use network::Network;

use crate::message::V1MessageHeader;

const SOFTWARE_VERSION: ClientSoftwareVersion =
    ClientSoftwareVersion::SemVer { major: 0, minor: 1, revision: 0 };
const USER_AGENT_VERSION: UserAgentVersion = UserAgentVersion::new(SOFTWARE_VERSION);
const SOFTWARE_NAME: &str = "ping-pong";

fn pad<'a>(value: &'a str) -> [u8; 12] {
    if value.len() > 12 {
        panic!("len greater than 12");
    }

    let bytes  = value.as_bytes();
    let cmd = &mut [0; 12];

    for i in 0..11 {
        if let Some(x) = bytes.get(i) {
            cmd[i] = *x as u8;
        } else {
            cmd[i] = 0;
        }
    }
    
    *cmd
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("not enough arguments");
        process::exit(1);
    }

    let str_network = &args[2];
    let network = Network::from_core_arg(str_network).unwrap();
    let port = network.default_p2p_port();
    let magic: Magic = Magic::try_from(network).unwrap();

    let str_address = &args[1];

    let ip: Ipv4Addr = str_address.parse().unwrap_or_else(|error| {
        eprintln!("error parsing address: {error:?}");
        process::exit(1);
    });

    let remote_socket: SocketAddr = SocketAddr::new(IpAddr::V4(ip), port);
    let version_message_body = build_version_message(remote_socket);
    let version_message_header = V1MessageHeader::new(magic, &version_message_body, "version");

    if let Ok(mut stream) = TcpStream::connect(remote_socket) {
        encoding::encode_to_writer(&version_message_header, &mut stream).unwrap();
        encoding::encode_to_writer(&version_message_body, &mut stream).unwrap();

        let read_stream = stream.try_clone().unwrap();
        let mut stream_reader = BufReader::new(read_stream);
        loop {
            let V1MessageHeader { command, .. } =
                encoding::decode_from_read::<V1MessageHeader, _>(&mut stream_reader).unwrap();
            //let cmd: &[u8; 12] = &command.0;
            match command.0 {
                val if val == pad("ping") => {
                    // receive ping and respond with pong.
                    let ping = encoding::decode_from_read::<Ping, _>(&mut stream_reader).unwrap();
                    println!("{:?}", ping);
                    let pong = Pong::from_ping(&ping);
                    println!("{:?}", pong);
                    let msg_header = V1MessageHeader::new(magic, &pong, "pong");
                    let _ = encoding::encode_to_writer(&msg_header, &stream);
                    let _ = encoding::encode_to_writer(&pong, &stream);
                }
                val if val == pad("sendcmpct") => {
                    let _ = encoding::decode_from_read::<SendCmpct, _>(&mut stream_reader).unwrap();
                }
                val if val == pad("verack") => {}
                val if val == pad("version") => {
                    // receive version and respond with verack.
                    let _ = encoding::decode_from_read::<message_network::VersionMessage, _>(
                        &mut stream_reader,
                    )
                    .unwrap();

                    let empty = Empty;
                    let verack = V1MessageHeader::new(magic, &empty, "verack");
                    encoding::encode_to_writer(&verack, &mut stream).unwrap();
                }
                val if val == pad("feefilter") => {
                    let _ = encoding::decode_from_read::<message::FeeFilter, _>(&mut stream_reader)
                        .unwrap();
                }
                _ => unimplemented!("{:?}", command),
            }
        }
    } else {
        eprintln!("failed to open connection");
    }
}

fn build_version_message(address: SocketAddr) -> message_network::VersionMessage {
    // Building version message, see https://en.bitcoin.it/wiki/Protocol_documentation#version
    let my_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

    // The version of the p2p protocol this client will use
    let protocol_version = ProtocolVersion::INVALID_CB_NO_BAN_VERSION;

    // "bitfield of features to be enabled for this connection"
    let services = ServiceFlags::NONE;

    // "standard UNIX timestamp in seconds"
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time error").as_secs();

    // "The network address of the node receiving this message"
    let addr_recv = address::Address::new(&address, ServiceFlags::NONE);

    // "The network address of the node emitting this message"
    let addr_from = address::Address::new(&my_address, ServiceFlags::NONE);

    // "Node random nonce, randomly generated every time a version packet is sent. This nonce is used to detect connections to self."
    // Because this crate does not include the `rand` dependency, this is a fixed value.
    let nonce: u64 = 42;

    // "The last block received by the emitting node"
    let start_height: i32 = 0;

    // A formatted string describing the software in use.
    let user_agent = UserAgent::new(SOFTWARE_NAME, &USER_AGENT_VERSION);

    // Construct the message
    message_network::VersionMessage::new(
        protocol_version,
        services,
        timestamp as i64,
        addr_recv,
        addr_from,
        nonce,
        user_agent,
        start_height,
    )
}
