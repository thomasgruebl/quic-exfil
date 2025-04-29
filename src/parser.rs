//! Copyright thomasgruebl 2025
//! License: GNU GPLv3
//! This module contains a custom QUIC packet parser.

use etherparse::{PacketHeaders, PayloadSlice};
use once_cell::sync::Lazy;
use std::{net::Ipv4Addr, sync::Mutex};

macro_rules! dbg {
    () => { ... };
    ($val:expr $(,)?) => { println!( $val );  };
    ($($val:expr),+ $(,)?) => { println!( $( $val ),* );  };
}

/// store unique handshake DCIDs
static GLOBAL_DCID_LIST: Lazy<Mutex<Vec<String>>> = Lazy::new(|| Mutex::new(Vec::new()));

#[derive(Debug, PartialEq)]
enum IpAddrKind {
    V4,
    V6,
}

/// Represents either an IPv4 or IPv6 address in one of three formats: bytes, hex string or decimal string representation
#[derive(Debug)]
pub struct IP {
    kind: IpAddrKind,
    bytes: Option<Vec<u8>>,
    hex: Option<String>,
    decimal: Option<String>,
}

impl IP {
    /// Convert an IP address to a hex string
    fn as_hex(&self) -> Result<String, &'static str> {
        let hex_string: String = <Option<Vec<u8>> as Clone>::clone(&self.bytes)
            .expect("IP byte array not valid.")
            .iter()
            .map(|byte| format!("{:02X}", byte))
            .collect();

        if hex_string.len() > 0 {
            Ok(hex_string)
        } else {
            Err("Conversion from byte array to hex string failed.")
        }
    }

    /// Convert to decimal
    fn as_decimal(&self, hex: bool) -> Result<String, &'static str> {
        // if hex bool true -> input is self.hex; else -> self.bytes
        if self.kind == IpAddrKind::V4 {
            let bytes: &Vec<u8> = &<Option<Vec<u8>> as Clone>::clone(&self.bytes).unwrap();
            if hex {
                let hex_value: u32 = match u32::from_str_radix(
                    &<Option<String> as Clone>::clone(&self.hex)
                        .unwrap()
                        .as_str(),
                    16,
                ) {
                    Ok(value) => value,
                    Err(_) => return Err("Invalid hexadecimal input string."),
                };
                let ipv4_addr: String = Ipv4Addr::from(hex_value.to_be_bytes()).to_string();
                return Ok(ipv4_addr);
            } else {
                if *(&<Option<Vec<u8>> as Clone>::clone(&self.bytes)
                    .unwrap()
                    .len())
                    != 4
                {
                    return Err("IPv4 address should be exactly 4 bytes long.");
                }
                let decimal_string: String =
                    format!("{}.{}.{}.{}", &bytes[0], &bytes[1], &bytes[2], &bytes[3]);
                return Ok(decimal_string);
            }
        }

        Err("Please supply an IPv4 address to use this method.")
    }
}

pub struct Packet {
    src_ip: IP,
    dst_ip: IP,
    src_port: u16,
    dst_port: u16,
    payload: QUICPacket,
}

impl Packet {
    pub fn new(src_ip: IP, dst_ip: IP, src_port: u16, dst_port: u16, payload: QUICPacket) -> Self {
        Packet {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            payload,
        }
    }

    /// Parse packet headers
    pub fn parse(data: &[u8]) -> Result<PacketHeaders, String> {
        // https://github.com/JulianSchmid/etherparse
        let packet = match PacketHeaders::from_ethernet_slice(data) {
            Ok(packet) => {
                /*println!("link: {:?}", packet.link);
                println!("vlan: {:?}", packet.vlan);
                println!("net: {:?}", packet.net); // contains ip
                println!("transport: {:?}", packet.transport);
                println!("payload: {:?}", packet.payload);*/
                //QUICPacket::parse_quic_header(packet.payload.clone());

                Ok(packet)
            }
            Err(err) => Err(format!("Error parsing packet: {:?}", err)),
        };
        //dbg!("Packet: {:?}", packet);

        //let mut src_ip_test = IP {kind: IpAddrKind::V6, bytes: Some(packet.net.clone().unwrap().ipv6_ref().unwrap().0.source.to_vec()), hex: None, decimal: None};
        //let mut dst_ip_test = IP {kind: IpAddrKind::V6, bytes: Some(packet.net.clone().unwrap().ipv6_ref().unwrap().0.destination.to_vec()), hex: None, decimal: None};
        //src_ip_test.hex = Some(src_ip_test.as_hex().unwrap());
        //src_ip_test.decimal = Some(src_ip_test.as_decimal(false).unwrap());

        //println!("Source IP and Destination IP: {:?} and {:?}", src_ip_test, dst_ip_test);
        return packet;
    }
}

#[derive(Default, Debug, PartialEq)]
pub enum QUICHeaderForm {
    #[default]
    ShortHeader,
    LongHeader,
}

impl std::fmt::Display for QUICHeaderForm {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Default, Debug, PartialEq)]
pub enum QUICPacketType {
    Initial = 0,
    ZeroRTT = 1,
    Handshake = 2,
    #[default]
    ProtectedPayload,
}

impl std::fmt::Display for QUICPacketType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Default, Debug)]
pub struct QUICPacket {
    pub len: u16,
    pub header_type: QUICHeaderForm,
    pub packet_type: QUICPacketType,
    pub first_byte: u8,
    version: Vec<u8>,
    pub dcid_len: u8,
    pub dcid: Vec<u8>,
    pub scid_len: u8,
    scid: Vec<u8>,
    pub remaining_payload: Vec<u8>,
    pub remaining_payload_len: u16,
}

impl std::fmt::Display for QUICPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "(Packet Length: {},
                    Header Type: {},
                    QUIC Type: {},
                    First Byte: {},
                    Version: {:?},
                    DCID_LEN: {},
                    DCID: {:?},
                    SCID_LEN: {},
                    SCID: {:?},
                    Remaining payload: {:?},
                    Remaining payload len: {:?}
                )",
            self.len,
            self.header_type,
            self.packet_type,
            self.first_byte,
            self.version,
            self.dcid_len,
            self.dcid,
            self.scid_len,
            self.scid,
            self.remaining_payload,
            self.remaining_payload_len
        )
    }
}

impl QUICPacket {
    /// Create new QUICPacket which includes len, header_type, packet_type, first_byte, version, dcid_len, dcid, scid_len, scid the remaining_payload and remaining_payload_len
    pub fn new(
        len: u16,
        header_type: QUICHeaderForm,
        packet_type: QUICPacketType,
        first_byte: u8,
        version: Vec<u8>,
        dcid_len: u8,
        dcid: Vec<u8>,
        scid_len: u8,
        scid: Vec<u8>,
        remaining_payload: Vec<u8>,
        remaining_payload_len: u16,
    ) -> Self {
        Self {
            len,
            header_type,
            packet_type,
            first_byte,
            version,
            dcid_len,
            dcid,
            scid_len,
            scid,
            remaining_payload,
            remaining_payload_len,
        }
    }

    /// Generates a byte array representation from a QUICPacket object. Differentiates between short and long header packets.
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut byte_array: Vec<u8> = Vec::new();

        // short header
        if (self.packet_type == QUICPacketType::ProtectedPayload)
            && (self.header_type == QUICHeaderForm::ShortHeader)
        {
            byte_array.push(self.first_byte);
            byte_array.extend_from_slice(&self.dcid.to_vec());
            byte_array.extend_from_slice(&self.remaining_payload.to_vec());
        } else {
            // change this
            //assert!(self.dcid_len <= 255 && self.dcid_len > 0);
            //assert!(self.scid_len <= 255 && self.scid_len > 0);
        }

        byte_array
    }

    /// Parses QUIC header as per RFC 8999 Version-Independent Properties of QUIC
    pub fn parse_quic_header(payload: PayloadSlice) -> Self {
        //dbg!("QUIC Payload: {:?}", payload);

        // create empty QUICPacket object
        let mut quic_packet: QUICPacket = QUICPacket::default();

        // QUIC packet length
        quic_packet.len = payload.slice().len() as u16;

        // differentiate between QUIC short and long header packets based on first byte of UDP payload
        let first_byte: &u8 = payload.slice().get(0).unwrap();

        // if high bit in the first byte is set to 1 -> long header, else -> short header (https://www.rfc-editor.org/rfc/rfc8999.html)
        if *first_byte >= 128 {
            // long header
            quic_packet.header_type = QUICHeaderForm::LongHeader;

            // bit 4 & 5 of first byte contain QUIC Packet Type: Initial (0), 0-RTT (1) Handshake (2)
            let first_byte_as_bits: String = format!("{:08b}", *first_byte);
            let packet_type: &str = &first_byte_as_bits[2..4];
            let packet_type_decimal: u8 = ((packet_type.chars().nth(0).unwrap() as u8 - 48) * 2)
                + (packet_type.chars().nth(1).unwrap() as u8 - 48); // 48 equals char '0'

            match packet_type_decimal {
                0 => quic_packet.packet_type = QUICPacketType::Initial,
                1 => quic_packet.packet_type = QUICPacketType::ZeroRTT,
                2 => quic_packet.packet_type = QUICPacketType::Handshake,
                _ => quic_packet.packet_type = QUICPacketType::default(),
            }

            // next 4 bytes -> Version
            let version: &[u8] = payload.slice().get(1..5).unwrap();

            // next 1 byte -> length in bytes of the Destination Connection ID field that follows
            let dcid_len: &u8 = payload.slice().get(5).unwrap();

            // next N bytes -> The Destination Connection ID field follows the Destination Connection ID Length field and is between 0 and 255 bytes in length.
            assert!(*dcid_len > 0);
            let dcid_end: usize = (*dcid_len + 5) as usize;
            let dcid: &[u8] = payload.slice().get(6..dcid_end + 1).unwrap();

            // next 1 byte -> length in bytes of the Source Connection ID field that follows
            let scid_len: &u8 = payload.slice().get(dcid_end + 1).unwrap();

            // next N bytes -> The Source Connection ID field follows the Source Connection ID Length field and is between 0 and 255 bytes in length.
            //assert!(*scid_len > 0);
            let scid_end: usize = dcid_end + 2 + *scid_len as usize;
            let scid: &[u8] = payload.slice().get((dcid_end + 2)..scid_end).unwrap();

            // lastly, the remaining payload follows the SCID
            let remaining_payload: &[u8] = payload.slice().get(scid_end..).unwrap();

            quic_packet.first_byte = *first_byte;
            quic_packet.version = version.to_vec();
            quic_packet.dcid = dcid.to_vec();
            quic_packet.dcid_len = *dcid_len;
            quic_packet.scid = scid.to_vec();
            quic_packet.scid_len = *scid_len;
            quic_packet.remaining_payload = remaining_payload.to_vec();
            quic_packet.remaining_payload_len = remaining_payload.len() as u16;

            // store unique handshake DCIDs in order to map protected payload packets to an existing connection later on
            if quic_packet.packet_type == QUICPacketType::Handshake {
                // && pcap::Direction::Out (true)
                Self::store_handshake_dcids(&quic_packet);
            }
        } else {
            // short header
            quic_packet.header_type = QUICHeaderForm::ShortHeader;

            // second byte onwards -> Destination Connection ID
            // match protected payload packet DCIDs on stored handshake DCIDs
            let mut dcid_list: std::sync::MutexGuard<'_, Vec<String>> =
                GLOBAL_DCID_LIST.lock().unwrap();
            let mut dcid: Vec<u8> = Vec::new();
            for d in dcid_list.iter() {
                let payload_slice: String =
                    Self::cid_as_hex_str(payload.slice().get(1..).unwrap().to_vec());

                if payload_slice.contains(d)
                    && (payload_slice.chars().next().unwrap() == d.chars().next().unwrap())
                {
                    dcid = d
                        .as_bytes()
                        .chunks(2)
                        .map(|chunk| {
                            u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap()
                        })
                        .collect::<Vec<u8>>();
                }
            }
            let dcid_len: &u8 = &(dcid.len() as u8);

            // lastly, the remaining payload follows the DCID
            let dcid_end: usize = (*dcid_len + 1) as usize;
            let remaining_payload: &[u8] = payload.slice().get(dcid_end..).unwrap();

            quic_packet.first_byte = *first_byte;
            quic_packet.dcid = dcid;
            quic_packet.dcid_len = *dcid_len;
            quic_packet.remaining_payload = remaining_payload.to_vec();
            quic_packet.remaining_payload_len = remaining_payload.len() as u16;
        }

        quic_packet
    }

    /// Takes a Vec<u8> connection ID and converts it to a hex string representation
    pub fn cid_as_hex_str(cid: Vec<u8>) -> String {
        let hex_string: String = cid.iter().map(|b| format!("{:02X}", b)).collect::<String>();
        hex_string
    }

    /// Stores handshake DCIDs in global list in hex string representation
    fn store_handshake_dcids(&self) {
        let dcid: String = QUICPacket::cid_as_hex_str(self.dcid.clone());
        let mut dcid_list: std::sync::MutexGuard<'_, Vec<String>> =
            GLOBAL_DCID_LIST.lock().unwrap();

        if !dcid_list.contains(&dcid) {
            dcid_list.push(dcid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_packet() {
        let data: Vec<u8> = vec![
            0x00, 0xc5, 0x85, 0x13, 0xf2, 0xa1, 0xb4, 0xee, 0xb4, 0xb7, 0xb1, 0x9e, 0x86, 0xdd,
            0x60, 0x00, 0x00, 0x00, 0x00, 0x22, 0x11, 0x39, 0x2a, 0x00, 0x14, 0x50, 0x40, 0x02,
            0x04, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x0e, 0x2a, 0x02, 0x21, 0xb4,
            0x92, 0x3d, 0x14, 0x00, 0x34, 0x3f, 0x6b, 0x44, 0x4e, 0xaf, 0x43, 0xa9, 0x01, 0xbb,
            0xcc, 0xb1, 0x00, 0x22, 0x67, 0x4f, 0x55, 0x29, 0x40, 0xb3, 0xf9, 0x44, 0x7d, 0xb4,
            0x9b, 0xe1, 0xd8, 0xa4, 0xc7, 0x53, 0x8a, 0xc7, 0x7c, 0x3f, 0x45, 0x41, 0x44, 0x8b,
            0xa7, 0xfa, 0x82, 0x2e,
        ];

        let result: Result<PacketHeaders<'_>, String> = Packet::parse(&data);
        assert!(result.is_ok());
        let parsed_packet: PacketHeaders<'_> = result.unwrap();
        assert!(parsed_packet.link.is_some());
        // assert!(parsed_packet.vlan.is_some());
        assert!(parsed_packet.net.is_some());
        assert!(parsed_packet.transport.is_some());
    }

    #[test]
    fn test_is_invalid_packet() {
        let invalid_data: Vec<u8> = vec![];
        assert!(Packet::parse(&invalid_data).is_err());
    }

    #[test]
    fn test_cid_bytes_to_hexstring_conversion() {
        let quick_packet: QUICPacket = QUICPacket::default();
        let cid: Vec<u8> = vec![
            1, 236, 199, 34, 47, 166, 55, 198, 90, 238, 221, 34, 83, 166, 1, 138, 134, 28, 40, 192,
        ];
        assert_eq!(
            QUICPacket::cid_as_hex_str(cid),
            "01ECC7222FA637C65AEEDD2253A6018A861C28C0"
        );
    }

    #[test]
    fn test_store_handshake_dcids() {
        let mut quick_packet: QUICPacket = QUICPacket::default();
        quick_packet.dcid = vec![
            1, 236, 199, 34, 47, 166, 55, 198, 90, 238, 221, 34, 83, 166, 1, 138, 134, 28, 40, 192,
        ];
        quick_packet.store_handshake_dcids();

        let dcid_list: std::sync::MutexGuard<'_, Vec<String>> = GLOBAL_DCID_LIST.lock().unwrap();
        assert_eq!(dcid_list.len(), 1);
        assert!(dcid_list.contains(&"01ECC7222FA637C65AEEDD2253A6018A861C28C0".to_string()));
    }
}
