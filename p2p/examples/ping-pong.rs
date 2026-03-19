//! An example written using the Sans I/O paradigm.
//!
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

use crate::message::V1MessageHeader;
use network::Network;
use bitcoin_p2p_messages::NetworkExt;
use bitcoin_p2p_messages::message::{NetworkMessage, Ping, Pong, V1NetworkMessage};
use bitcoin_p2p_messages::message_compact_blocks::SendCmpct;
use bitcoin_p2p_messages::message_network::{
    ClientSoftwareVersion, UserAgent, UserAgentVersion, VersionMessage,
};
use bitcoin_p2p_messages::{
    self, address, message, message_network, Magic, ProtocolVersion, ServiceFlags,
};

const SOFTWARE_VERSION: ClientSoftwareVersion =
    ClientSoftwareVersion::SemVer { major: 0, minor: 1, revision: 0 };
const USER_AGENT_VERSION: UserAgentVersion = UserAgentVersion::new(SOFTWARE_VERSION);
const SOFTWARE_NAME: &str = "ping-pong";

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
    let version_message = build_version_message(remote_socket);
    let version_message = message::V1NetworkMessage::new(Magic::REGTEST, version_message);

    if let Ok(mut stream) = TcpStream::connect(remote_socket) {
        encoding::encode_to_writer(&version_message, &mut stream).unwrap();

        let read_stream = stream.try_clone().unwrap();
        let mut stream_reader = BufReader::new(read_stream);
        loop {
            let V1MessageHeader { command, .. } =
                encoding::decode_from_read::<V1MessageHeader, _>(&mut stream_reader).unwrap();

            match command.as_ref() {
                "ping" => {
                    // receive ping and respond with pong.
                    let ping = encoding::decode_from_read::<Ping, _>(&mut stream_reader).unwrap();
                    println!("{:?}", ping);

                    let pong = Pong::from_ping(&ping);
                    println!("{:?}", pong);

                    let msg_header = V1MessageHeader::new(magic, &pong, "pong");
                    let _ = encoding::encode_to_writer(&msg_header, &stream);
                    let _ = encoding::encode_to_writer(&pong, &stream);
                }
                "sendcmpct" => {
                    let _ = encoding::decode_from_read::<SendCmpct, _>(&mut stream_reader).unwrap();
                }
                "verack" => {}
                "version" => {
                    // receive version and respond with verack.
                    let _ = encoding::decode_from_read::<VersionMessage, _>(&mut stream_reader)
                        .unwrap();
                    let verack = V1NetworkMessage::new(magic, NetworkMessage::Verack);

                    encoding::encode_to_writer(&verack, &mut stream).unwrap();
                }
                "feefilter" => {
                    let _ = encoding::decode_from_read::<message::FeeFilter, _>(&mut stream_reader)
                        .unwrap();
                }
                _ => unimplemented!("{:?}", command.as_ref()),
            }
        }
    } else {
        eprintln!("failed to open connection");
    }
}

fn build_version_message(address: SocketAddr) -> message::NetworkMessage {
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
    message::NetworkMessage::Version(message_network::VersionMessage::new(
        protocol_version,
        services,
        timestamp as i64,
        addr_recv,
        addr_from,
        nonce,
        user_agent,
        start_height,
    ))
}
