extern crate libc;
extern crate rand;
extern crate pnet;
extern crate time;

use std::env;
use std::iter::repeat;
use std::mem;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use pnet::datalink::{self, NetworkInterface};
// use pnet::packet::{Packet, PacketSize, FromPacket};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket, EtherTypes};
use pnet::packet::ipv4::{self, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::icmp::{IcmpPacket, echo_reply, echo_request, icmp_types};
use pnet::packet::icmp::{self, MutableIcmpPacket, IcmpType, IcmpCode};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::util::MacAddr;


fn handle_icmp_echo_reply_packet(interface_name: &str,
                                 frame_size: usize,
                                 source: IpAddr,
                                 ttl: u8,
                                 packet: &[u8]) {
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        match icmp_packet.get_icmp_type() {
            icmp_types::EchoReply => {
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                // let payload = echo_reply_packet.payload();
                // let now = time::now();
                // let timestamp = payload[..8];
                let rtt = "";
                println!("{} bytes from {}: icmp_seq={} ttl={} time={}",
                         frame_size,
                         source,
                         echo_reply_packet.get_sequence_number(),
                         ttl,
                         rtt,
                );
            }
            icmp_types::EchoRequest => (),
            _ => (),
        }
    } else {
        println!("[{}]: Malformed ICMP Packet", interface_name);
    }
}

fn handle_transport_protocol(interface_name: &str,
                             frame_size: usize,
                             source: IpAddr,
                             ttl: u8,
                             protocol: IpNextHeaderProtocol,
                             packet: &[u8]) {
    match protocol {
        IpNextHeaderProtocols::Icmp => {
            handle_icmp_echo_reply_packet(interface_name, frame_size, source, ttl, packet)
        }
        _ => (),
    }
}

fn handle_ipv4_packet(interface_name: &str, ethernet: &EthernetPacket) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(interface_name,
                                  ethernet.packet().len(),
                                  IpAddr::V4(header.get_source()),
                                  header.get_ttl(),
                                  header.get_next_level_protocol(),
                                  header.payload());
    } else {
        println!("[{}]: Malformed IPv4 Packet", interface_name);
    }
}

fn handle_packet(interface_name: &str, ethernet: &EthernetPacket) {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(interface_name, ethernet),
        _ => (),
    }
}


fn main() {
    use pnet::datalink::Channel::Ethernet;

    // Create iface_name
    let iface_name = env::args().nth(1).unwrap();
    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;
    // Create destiantion ipaddr
    let args1 = env::args().nth(2).unwrap();
    let v4addr = Ipv4Addr::from_str(&args1).unwrap();
    // let addr = IpAddr::V4(v4addr);

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    // netmap could not support L3 layer now and treat L2 Layer.
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel type: {}"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    };

    let i = Some(interface.clone());

    // Initialize echo-request esquence number
    let mut echo_sequence = 0;

    loop {
        // Allocate enough space for a new packet
        // FixMe: packet length?
        let mut vec_icmp: Vec<u8> = repeat(0u8).take(22).collect();
        // L3: 24bytes
        let mut vec_l3: Vec<u8> = repeat(0u8).take(46).collect();
        // L2: 18bytes
        let mut vec_l2: Vec<u8> = repeat(0u8).take(64).collect();

        // Create icmp packet
        {
            let mut new_icmp_packet =
                echo_request::MutableEchoRequestPacket::new(&mut vec_icmp[..]).unwrap();
            new_icmp_packet.set_icmp_type(IcmpType(8));
            new_icmp_packet.set_icmp_code(IcmpCode(0));
            unsafe {
                let pid = libc::getpid();
                new_icmp_packet.set_identifier(pid as u16);
            }
            new_icmp_packet.set_sequence_number(echo_sequence);
            // Create icmp data
            let mut payload: [u8; 8] = [0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
            let now = time::now();
            // let secs: [u8; 4] = unsafe { mem::transmute::<u32, [u8;4]>(now.tm_sec as u32) };
            // let nsecs: [u8; 4] = unsafe { mem::transmute::<u32, [u8;4]>(now.tm_nsec as u32) };
            new_icmp_packet.set_payload(&payload);
        }
        {
            let mut new_icmp_packet = MutableIcmpPacket::new(&mut vec_icmp[..]).unwrap();
            // Calculate icmp checksum
            let checksum = icmp::checksum(&new_icmp_packet.to_immutable());
            new_icmp_packet.set_checksum(checksum);
        }
        // Create ipv4 packet
        {
            let mut new_l3_packet = MutableIpv4Packet::new(&mut vec_l3[..]).unwrap();
            let header_size = 5;
            let packet_size = header_size + vec_icmp.len() / 4;
            new_l3_packet.set_version(4);
            new_l3_packet.set_header_length(header_size as u8);
            new_l3_packet.set_dscp(0);
            new_l3_packet.set_ecn(0);
            new_l3_packet.set_total_length(packet_size as u16);
            new_l3_packet.set_identification(rand::random());
            new_l3_packet.set_flags(0);
            new_l3_packet.set_fragment_offset(0);
            new_l3_packet.set_ttl(64);
            new_l3_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
            // FixMe: source ip addr
            new_l3_packet.set_source(Ipv4Addr::from_str("172.17.0.2").unwrap());
            new_l3_packet.set_destination(v4addr);

            new_l3_packet.set_payload(&mut vec_icmp);
            // Calculate ipv4 checksumx
            let checksum = ipv4::checksum(&new_l3_packet.to_immutable());
            new_l3_packet.set_checksum(checksum);
        }

        let mut new_l2_packet = MutableEthernetPacket::new(&mut vec_l2[..]).unwrap();
        let destination = MacAddr::from_str("62:e2:57:f0:57:55").unwrap();
        new_l2_packet.set_destination(destination);
        let source = MacAddr::from_str("02:42:ac:11:00:02").unwrap();
        new_l2_packet.set_source(source);
        new_l2_packet.set_ethertype(EtherTypes::Ipv4);
        new_l2_packet.set_payload(&mut vec_l3);

        match tx.send_to(&new_l2_packet.to_immutable(), i.clone()).unwrap() {
            Ok(_) => (),
            Err(e) => panic!("failed to send packet: {}", e),
        }
        thread::sleep(Duration::from_secs(1));

        // FixMe: Implement receive echo-reply thread
        // FixMe: Handling when it not receive echo-reply
        let mut recv_iter = rx.iter();

        match recv_iter.next() {
            Ok(packet) => {
                // Allocate enough space for a new packet
                handle_packet(&interface.name[..], &packet);
            }
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("An error occurred while reading: {}", e);
            }
        }

        echo_sequence += 1;
    }
}
