//! Copyright thomasgruebl 2025
//! License: GNU GPLv3

use clap::Parser;

///
/// A simple prototypical program that mimics QUIC server-side connection migrations and exfiltrates data to a target server
///
#[derive(Parser, Clone)]
#[command(version, about, long_about = None)]
pub(crate) struct Cli {
    /// Network interface name
    #[arg(short = 'i', long, default_value_t = String::from("en1"))]
    pub(crate) interface: String,

    /// Target file to exfiltrate
    #[arg(short = 't', long, default_value_t = String::from("images/sample.jpg"))]
    pub(crate) target: String,

    /// Pcap capture filter
    #[arg(short = 'f', long, default_value_t = String::from("udp dst port 443"))]
    pub(crate) filter: String,

    /// Exfiltration server destination IP
    #[arg(short = 'd', long, default_value_t = String::from("192.0.2.100"))]
    pub(crate) dst: String,

    /// Exfiltration server destination port
    #[arg(short = 'p', long, default_value_t = String::from("443"))]
    pub(crate) port: String,

    /// Packet buffer. Specifies how many QUIC packets should be captured and analyzed before attempting to send the first exfiltration packet. Required to mimic payload lengths of previously seen traffic.
    #[arg(short = 'b', long, default_value_t = 1000)]
    pub(crate) buffer: usize,

    // Sleep time in milliseconds. Specifies a static time interval between two exfitration packets
    //#[arg(short = 's', long, default_value_t = 100)]
    //pub(crate) sleep: u64,
    /// Number of packets to be exfiltrated per simulated connection migration
    #[arg(short = 'n', long, default_value_t = 100)]
    pub(crate) number: u32,
}
