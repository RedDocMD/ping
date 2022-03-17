use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use pnet::packet::icmp::{self, IcmpType, MutableIcmpPacket};
use pnet::packet::ipv4::MutableIpv4Packet;
use socket2::{Domain, Protocol, Socket, Type};
use thiserror::Error;

const ICMP_ECHO_REQUEST: u8 = 8;
const IPV4_VERSION: u8 = 4;

fn main() {
    let socket = unwrap_result(get_socket());
    let start = Instant::now();

    // This scope is to spawn a thread which sends ICMP echo requests at regular intervals
    crossbeam::scope(|s| {
        s.spawn(|_| {
            // Calculate buffer size for packet
            const ICMP_HEADER_SIZE: usize = MutableIcmpPacket::minimum_packet_size();
            const ICMP_PAYLOAD_SIZE: usize = 64; // For timestamp
            const ICMP_PACKET_SIZE: usize = ICMP_HEADER_SIZE + ICMP_PAYLOAD_SIZE;
            const IP_HDR_SIZE: usize = MutableIpv4Packet::minimum_packet_size();
            const IP_PACKET_SIZE: usize = ICMP_PACKET_SIZE + IP_HDR_SIZE;

            let mut ip_buf = [0_u8; IP_PACKET_SIZE];
            let mut icmp_buf = [0_u8; ICMP_PACKET_SIZE];

            const SLEEP_TIME_SECS: u64 = 1;
            let sleep_time = Duration::from_secs(SLEEP_TIME_SECS);

            // Send ICMP echo request packet in a loop
            loop {
                let mut icmp_packet = MutableIcmpPacket::new(&mut icmp_buf).unwrap();
                // Set ICMP fields
                // Type
                icmp_packet.set_icmp_type(IcmpType(ICMP_ECHO_REQUEST));
                // Timestamp in header field
                let now = Instant::now();
                let diff = (now - start).as_millis();
                icmp_packet.set_payload(&diff.to_ne_bytes());
                // Checksum
                icmp_packet.set_checksum(icmp::checksum(&icmp_packet.to_immutable()));

                let mut ip_packet = MutableIpv4Packet::new(&mut ip_buf).unwrap();
                // Set IP fields
                // Version
                ip_packet.set_version(IPV4_VERSION);
                // Header len
                ip_packet.set_header_length((IP_HDR_SIZE / 4) as u8);
                // Total length
                ip_packet.set_total_length(IP_PACKET_SIZE as u16);

                // Sleep for 1 second
                thread::sleep(sleep_time);
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
