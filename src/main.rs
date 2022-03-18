use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::str::FromStr;
use std::time::{Duration, Instant};
use std::{env, mem, process, thread};

use pnet::packet::icmp::{self, IcmpType, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::{self, MutableIpv4Packet};
use pnet::packet::Packet;
use regex::Regex;
use socket2::{Domain, Protocol, Socket, Type};
use thiserror::Error;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;

const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;
const IPV4_VERSION: u8 = 4;
const TTL: u8 = 112;
const ICMP_PROTOCOL: u8 = 1;

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Expected: <hostname|ipv4>");
        process::exit(1);
    }
    let ping_arg = PingArg::new(&args[1]);
    let host_addr = unwrap_result(ping_arg.to_ipv4());

    let start = Instant::now();
    let identifier = rand::random::<u16>();

    // This scope is to spawn a thread which sends ICMP echo requests at regular intervals
    crossbeam::scope(|s| {
        s.spawn(|_| {
            let send_socket = unwrap_result(get_socket());

            // Calculate buffer size for packet
            const ICMP_HEADER_SIZE: usize = MutableIcmpPacket::minimum_packet_size();
            const ICMP_PACKET_SIZE: usize = ICMP_HEADER_SIZE + IcmpPayload::SIZE;
            const IP_HDR_SIZE: usize = MutableIpv4Packet::minimum_packet_size();
            const IP_PACKET_SIZE: usize = ICMP_PACKET_SIZE + IP_HDR_SIZE;

            let mut ip_buf = [0_u8; IP_PACKET_SIZE];
            let mut icmp_buf = [0_u8; ICMP_PACKET_SIZE];

            const SLEEP_TIME_SECS: u64 = 1;
            let sleep_time = Duration::from_secs(SLEEP_TIME_SECS);

            let mut icmp_packet = MutableIcmpPacket::new(&mut icmp_buf).unwrap();
            // Set ICMP fields
            icmp_packet.set_icmp_type(IcmpType(ICMP_ECHO_REQUEST));
            let now = Instant::now();
            let diff = (now - start).as_millis();
            let mut icmp_payload = IcmpPayload {
                identifier,
                seq_num: 0,
                timestamp: diff as u32,
            };

            let mut ip_packet = MutableIpv4Packet::new(&mut ip_buf).unwrap();
            // Set IP fields
            ip_packet.set_version(IPV4_VERSION);
            ip_packet.set_header_length((IP_HDR_SIZE / 4) as u8);
            ip_packet.set_total_length(IP_PACKET_SIZE as u16);
            ip_packet.set_ttl(TTL);
            ip_packet.set_next_level_protocol(IpNextHeaderProtocol(ICMP_PROTOCOL));
            ip_packet.set_destination(host_addr);

            println!(
                "PING ({}) {}({}) bytes of data",
                host_addr, ICMP_PACKET_SIZE, IP_PACKET_SIZE
            );

            // Send ICMP echo request packet in a loop
            loop {
                // Set payload and checksum (ICMP)
                let icmp_payload_bytes = icmp_payload.to_bytes();
                icmp_packet.set_payload(&icmp_payload_bytes);
                icmp_packet.set_checksum(icmp::checksum(&icmp_packet.to_immutable()));

                // Set payload and checksum (IP)
                ip_packet.set_payload(icmp_packet.packet());
                ip_packet.set_checksum(ipv4::checksum(&ip_packet.to_immutable()));

                if let Err(err) =
                    send_socket.send_to(ip_packet.packet(), &SocketAddrV4::new(host_addr, 0).into())
                {
                    eprintln!("Error while sending: {}", err);
                }

                // Sleep for 1 second
                thread::sleep(sleep_time);

                // For next packet
                icmp_payload.seq_num += 1;
                let now = Instant::now();
                let diff = (now - start).as_millis();
                icmp_payload.timestamp = diff as u32;
            }
        });
    })
    .unwrap();
}

fn get_socket() -> PingResult<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
    socket.set_header_included(true)?;
    Ok(socket)
}

#[derive(Error, Debug)]
enum PingError {
    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("Invalid IP addr: {0}")]
    InvalidIpv4(#[from] std::net::AddrParseError),

    #[error("Resolve error: {0}")]
    ResolveError(#[from] trust_dns_resolver::error::ResolveError),

    #[error("Failed to find IPv4 address")]
    NoIpv4Addr,
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

#[repr(C)]
#[derive(Debug)]
struct IcmpPayload {
    identifier: u16,
    seq_num: u16,
    timestamp: u32,
}

impl IcmpPayload {
    const SIZE: usize = mem::size_of::<IcmpPayload>();

    fn to_bytes(&self) -> [u8; IcmpPayload::SIZE] {
        unsafe { mem::transmute_copy(self) }
    }
}

#[derive(Debug)]
enum PingArg<'a> {
    Host(&'a str),
    Ip(&'a str),
}

impl<'a> PingArg<'a> {
    fn new(arg: &'a str) -> Self {
        let arg = arg.trim();
        let ip_re = Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").unwrap();
        if ip_re.is_match(arg) {
            PingArg::Ip(arg)
        } else {
            PingArg::Host(arg)
        }
    }

    fn to_ipv4(&self) -> PingResult<Ipv4Addr> {
        match self {
            PingArg::Host(host) => {
                let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())?;
                let response = resolver.lookup_ip(*host)?;
                for ip_addr in response.iter() {
                    if let IpAddr::V4(ipv4_addr) = ip_addr {
                        return Ok(ipv4_addr);
                    }
                }
                Err(PingError::NoIpv4Addr)
            }
            PingArg::Ip(ip) => Ok(Ipv4Addr::from_str(ip)?),
        }
    }
}
