// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// This example shows a basic packet logger using libpnet

extern crate pnet;

use std::env;
use std::net::IpAddr;

use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::icmp::{IcmpPacket, echo_reply, echo_request, icmp_types};

use pnet::datalink::{self, NetworkInterface};

fn handle_icmp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        match icmp_packet.get_icmp_type() {
            icmp_types::EchoReply => {
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                println!("[{}]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                         interface_name,
                         source,
                         destination,
                         echo_reply_packet.get_sequence_number(),
                         echo_reply_packet.get_identifier());
            }
            icmp_types::EchoRequest => {
                let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                println!("[{}]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
                         interface_name,
                         source,
                         destination,
                         echo_request_packet.get_sequence_number(),
                         echo_request_packet.get_identifier());
            }
            _ => {
                println!("[{}]: ICMP packet {} -> {} (type={:?})",
                         interface_name,
                         source,
                         destination,
                         icmp_packet.get_icmp_type())
            }
        }
    } else {
        println!("[{}]: Malformed ICMP Packet", interface_name);
    }
}

fn handle_transport_protocol(interface_name: &str,
                             source: IpAddr,
                             destination: IpAddr,
                             protocol: IpNextHeaderProtocol,
                             packet: &[u8]) {
    match protocol {
        IpNextHeaderProtocols::Icmp => {
            handle_icmp_packet(interface_name, source, destination, packet)
        }
        _ => {
            println!("[{}]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
                     interface_name,
                     match source {
                         IpAddr::V4(..) => "IPv4",
                         _ => "IPv6",
                     },
                     source,
                     destination,
                     protocol,
                     packet.len())
        }
    }
}

fn handle_ipv4_packet(interface_name: &str, ethernet: &EthernetPacket) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(interface_name,
                                  IpAddr::V4(header.get_source()),
                                  IpAddr::V4(header.get_destination()),
                                  header.get_next_level_protocol(),
                                  header.payload());
    } else {
        println!("[{}]: Malformed IPv4 Packet", interface_name);
    }
}

fn handle_packet(interface_name: &str, ethernet: &EthernetPacket) {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(interface_name, ethernet),
        _ => {
            println!("[{}]: Unknown packet: {} > {}; ethertype: {:?} length: {}",
                     interface_name,
                     ethernet.get_source(),
                     ethernet.get_destination(),
                     ethernet.get_ethertype(),
                     ethernet.packet().len())
        }
    }
}

fn main() {
    use pnet::datalink::Channel::Ethernet;

    let iface_name = env::args().nth(1).unwrap();
    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    // Create a channel to receive on
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel type: {}"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    };

    let mut iter = rx.iter();
    let i = Some(interface.clone());
    loop {
        match iter.next() {
            Ok(packet) => {
                handle_packet(&interface.name[..], &packet);

                // Create icmp echo-reply packet
                use std::iter::repeat;
                use pnet::packet::MutablePacket;
                use pnet::packet::icmp::{IcmpType, IcmpCode};

                let mut vec: Vec<u8> = repeat(0u8).take(packet.packet().len()).collect();
                let mut new_packet = MutableEthernetPacket::new(&mut vec[..]).unwrap();

                new_packet.clone_from(&packet);
                new_packet.set_destination(packet.get_source());
                new_packet.set_source(packet.get_destination());

                {
                    let l3_header = Ipv4Packet::new(packet.payload()).unwrap();
                    let mut new_l3_header = MutableIpv4Packet::new(new_packet.payload_mut())
                        .unwrap();
                    new_l3_header.set_destination(l3_header.get_source());
                    new_l3_header.set_source(l3_header.get_destination());

                    let icmp = echo_request::EchoRequestPacket::new(l3_header.payload()).unwrap();
                    let mut new_icmp =
                        echo_reply::MutableEchoReplyPacket::new(new_l3_header.payload_mut())
                            .unwrap();
                    new_icmp.set_identifier(icmp.get_identifier());
                    new_icmp.set_sequence_number(icmp.get_sequence_number());
                    new_icmp.set_icmp_type(IcmpType(0));
                    new_icmp.set_icmp_code(IcmpCode(0));
                }

                // Send packet
                match tx.send_to(&new_packet.to_immutable(), i.clone()).unwrap() {
                    Ok(_) => {
                        // println!("send pong");
                    }
                    Err(e) => panic!("failed to send packet: {}", e),
                }
                handle_packet(&interface.name[..], &new_packet.to_immutable());
            }
            Err(e) => panic!("packetdump: unable to receive packet: {}", e),
        }
    }
}
