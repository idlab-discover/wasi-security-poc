//! Network probe: exercises every `wasi:sockets` operation the policy polices.
//!
//! All traffic stays on loopback so the probe gives the same answer on any
//! machine. The addresses are fixed; the example policies in `policies/` grant
//! or deny exactly these.
//!
//! | step            | address          | policed by                          |
//! |-----------------|------------------|-------------------------------------|
//! | dns lookup      | `localhost`      | `network.allow_ip_name_lookup`      |
//! | tcp listen      | 127.0.0.1:7878   | `network.bind`                      |
//! | tcp connect     | 127.0.0.1:7878   | `network.connect`                   |
//! | tcp connect     | 127.0.0.1:9      | `network.connect`                   |
//! | udp bind        | 0.0.0.0:0        | `network.bind` / outbound UDP grant |
//! | udp send        | 127.0.0.1:7979   | `network.connect`                   |
//! | udp send        | 127.0.0.1:9      | `network.connect`                   |

use std::io::{self, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs, UdpSocket};

const LISTEN: &str = "127.0.0.1:7878";
const OTHER_TCP: &str = "127.0.0.1:9";
const UDP_PEER: &str = "127.0.0.1:7979";
const OTHER_UDP: &str = "127.0.0.1:9";

fn main() {
    println!("net-probe: what can this guest reach?");

    report("dns  lookup  localhost", lookup("localhost:0"));

    let listener = TcpListener::bind(LISTEN);
    report(
        &format!("tcp  listen  {LISTEN}"),
        listener
            .as_ref()
            .map(|l| format!("bound {}", l.local_addr().unwrap()))
            .map_err(clone_err),
    );

    report(
        &format!("tcp  connect {LISTEN}"),
        tcp_roundtrip(LISTEN, listener.as_ref().ok()),
    );
    report(&format!("tcp  connect {OTHER_TCP}"), tcp_connect(OTHER_TCP));

    let udp = UdpSocket::bind("0.0.0.0:0");
    report(
        "udp  bind    0.0.0.0:0",
        udp.as_ref()
            .map(|s| format!("bound {}", s.local_addr().unwrap()))
            .map_err(clone_err),
    );
    match &udp {
        Ok(socket) => {
            report(
                &format!("udp  send    {UDP_PEER}"),
                udp_send(socket, UDP_PEER),
            );
            report(
                &format!("udp  send    {OTHER_UDP}"),
                udp_send(socket, OTHER_UDP),
            );
        }
        Err(_) => {
            println!("  SKIPPED  udp  send    {UDP_PEER} -> no UDP socket");
            println!("  SKIPPED  udp  send    {OTHER_UDP} -> no UDP socket");
        }
    }
}

fn lookup(name: &str) -> io::Result<String> {
    let addrs: Vec<String> = name
        .to_socket_addrs()?
        .map(|a| a.ip().to_string())
        .collect();
    Ok(format!("[{}]", addrs.join(", ")))
}

/// Connect to our own listener and push a message through it, so a granted
/// connect is shown to carry real traffic.
fn tcp_roundtrip(addr: &str, listener: Option<&TcpListener>) -> io::Result<String> {
    let mut client = TcpStream::connect(addr)?;
    let Some(listener) = listener else {
        return Ok("connected (no local listener to echo through)".into());
    };

    let (mut server, peer) = listener.accept()?;
    client.write_all(b"ping")?;
    let mut buf = [0u8; 4];
    server.read_exact(&mut buf)?;

    Ok(format!(
        "accepted {peer}, server read {:?}",
        String::from_utf8_lossy(&buf)
    ))
}

fn tcp_connect(addr: &str) -> io::Result<String> {
    TcpStream::connect(addr).map(|s| format!("connected from {}", s.local_addr().unwrap()))
}

fn udp_send(socket: &UdpSocket, addr: &str) -> io::Result<String> {
    socket
        .send_to(b"ping", addr)
        .map(|n| format!("sent {n} bytes"))
}

fn clone_err(err: &io::Error) -> io::Error {
    io::Error::new(err.kind(), err.to_string())
}

fn report(label: &str, outcome: io::Result<String>) {
    match outcome {
        Ok(detail) => println!("  ALLOWED  {label} -> {detail}"),
        // The policy let the call through; the OS found nobody listening.
        Err(err) if err.kind() == ErrorKind::ConnectionRefused => {
            println!("  ALLOWED  {label} -> passed the policy, but {err}")
        }
        Err(err) => println!("  DENIED   {label} -> {:?}: {err}", err.kind()),
    }
}
