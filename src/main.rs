use std::sync::Mutex;

use pnet::packet::icmp::MutableIcmpPacket;
use pnet::packet::ipv4::MutableIpv4Packet;
use socket2::{Domain, Protocol, Socket, Type};
use thiserror::Error;

fn main() {
    let socket = unwrap_result(get_socket());
    crossbeam::scope(|s| {
        s.spawn(|_| {
            // Calculate buffer size for packet
            const ICMP_PACKET_SIZE: usize = MutableIcmpPacket::minimum_packet_size();
            const IP_HDR_SIZE: usize = MutableIpv4Packet::minimum_packet_size();
            const BUF_SIZE: usize = ICMP_PACKET_SIZE + IP_HDR_SIZE;
            let mut buf = [0_u8; BUF_SIZE];

            // Send ICMP echo request packet in a loop
            loop {
                let icmp_packet = MutableIcmpPacket::new(&mut buf[IP_HDR_SIZE..]).unwrap();
                let ip_packet = MutableIpv4Packet::new(&mut buf).unwrap();
            }
        });
    })
    .unwrap();
}

fn get_socket() -> PingResult<Mutex<Socket>> {
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
    Ok(Mutex::new(socket))
}

#[derive(Error, Debug)]
enum PingError {
    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),
}

type PingResult<O> = Result<O, PingError>;

fn unwrap_result<O>(val: PingResult<O>) -> O {
    match val {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
