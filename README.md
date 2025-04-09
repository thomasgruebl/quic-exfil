# quic-exfil
Covert data exfiltration by mimicking QUIC server-side connection migrations.

![Crates.io](https://img.shields.io/crates/d/quic-exfil?style=plastic)
![Libraries.io dependency status for GitHub repo](https://img.shields.io/librariesio/github/thomasgruebl/quic-exfil?style=plastic)
![GitHub last commit](https://img.shields.io/github/last-commit/thomasgruebl/quic-exfil?style=plastic)
![GitHub](https://img.shields.io/github/license/thomasgruebl/quic-exfil?style=plastic)
<a style="text-decoration: none" href="https://github.com/thomasgruebl/quic-exfil/stargazers">
<img src="https://img.shields.io/github/stars/thomasgruebl/quic-exfil.svg?style=plastic" alt="Stars">
</a>
<a style="text-decoration: none" href="https://github.com/thomasgruebl/quic-exfil/fork">
<img src="https://img.shields.io/github/forks/thomasgruebl/quic-exfil.svg?style=plastic" alt="Forks">
</a>
<a style="text-decoration: none" href="https://github.com/thomasgruebl/quic-exfil/issues">
<img src="https://img.shields.io/github/issues/thomasgruebl/quic-exfil.svg?style=plastic" alt="Issues">
</a>



Add descr on how to install quiche on the base machine -> and start quiche server to listen for benign connection migrations 
./target/release/quiche-server --listen 192.168.100.63:4433 --root html --cert apps/src/bin/cert.crt --key apps/src/bin/cert.key --enable-active-migration


QUIC-exfiltration client-side Wireshark trace (without the required server-side acknowledgments)
* 2a05:d012:8ef:f66:12d3:23ac:6791:a11f is the exfiltration server IP
* Packet 54622 mimics the PATH_CHALLENGE packet

![Alt text](sample_pcap.png "pcap_sample")