//! RoCE Sanity Check

#![deny(
    // The following are allowed by default lints according to
    // https://doc.rust-lang.org/rustc/lints/listing/allowed-by-default.html
    anonymous_parameters,
    bare_trait_objects,
    // box_pointers, // use box pointer to allocate on heap
    elided_lifetimes_in_paths, // allow anonymous lifetime
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs, // TODO: add documents
    single_use_lifetimes, // TODO: fix lifetime names only used once
    trivial_casts, // TODO: remove trivial casts in code
    trivial_numeric_casts,
    // unreachable_pub, allow clippy::redundant_pub_crate lint instead
    // unsafe_code,
    unstable_features,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    variant_size_differences,

    warnings, // treat all wanings as errors

    clippy::all,
    clippy::restriction,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo
)]
#![allow(
    // Some explicitly allowed Clippy lints, must have clear reason to allow
    clippy::blanket_clippy_restriction_lints, // allow denying clippy::restriction directly
    clippy::implicit_return, // actually omitting the return keyword is idiomatic Rust code
    clippy::module_name_repetitions, // repeation of module name in a struct name is not big deal
    clippy::multiple_crate_versions, // multi-version dependency crates is not able to fix
    clippy::panic, // allow debug_assert, panic in production code
    clippy::panic_in_result_fn, // allow debug_assert
)]

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io::prelude::*;
use std::net::{TcpListener, TcpStream, UdpSocket};
use utilities::Cast;

// ///
// const MSG: &str = "SEND operation";
// ///
// const RDMAMSGR: &str = "RDMA read operation";
// ///
// const RDMAMSGW: &str = "RDMA write operation";
// ///
// const MSG_SIZE: usize = 32;
// ///
// const MAX_POLL_CQ_TIMEOUT: i64 = 2000;
// ///
// const INVALID_SIZE: isize = -1;

/// The data needed to connect QP
#[derive(Deserialize, Serialize)]
struct CmConData {
    /// Buffer address
    addr: u64,
    /// Remote key
    rkey: u32,
    /// QP number
    qp_num: u32,
    /// LID of the IB port
    lid: u16,
    /// gid
    gid: u128,
}

impl CmConData {
    ///
    fn new() -> anyhow::Result<Self> {
        let s = Self {
            addr: u64::from_str_radix("55b4dec4d610", 16)?,
            rkey: u32::from_str_radix("245", 16)?,
            qp_num: u32::from_str_radix("11", 16)?,
            lid: u16::from_str_radix("0", 16)?,
            gid: u128::from_str_radix("fe80000000000000505400fffea7d042", 16)?,
        };
        Ok(s)
    }
    ///
    const fn into_be(self) -> Self {
        Self {
            addr: u64::to_be(self.addr),
            rkey: u32::to_be(self.rkey),
            qp_num: u32::to_be(self.qp_num),
            lid: u16::to_be(self.lid),
            gid: u128::to_be(self.gid),
        }
    }
    ///
    const fn into_le(self) -> Self {
        Self {
            addr: u64::from_be(self.addr),
            rkey: u32::from_be(self.rkey),
            qp_num: u32::from_be(self.qp_num),
            lid: u16::from_be(self.lid),
            gid: u128::from_be(self.gid),
        }
    }
}

impl std::fmt::Display for CmConData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        //unsafe {
        write!(
            f,
            "addr={:x}, rkey={:x}, qp_num={:x}, lid={:x}, gid={:x}",
            self.addr, self.rkey, self.qp_num, self.lid, self.gid,
        )
        //}
    }
}

///
#[derive(Debug, Deserialize, Serialize)]
enum State {
    ///
    ReceiveReady,
    ///
    SendSize(isize),
    ///
    ReadSize(isize),
    ///
    WriteSize(isize),
}

///
#[derive(Debug)]
pub enum TcpSock {
    ///
    Listener(TcpListener),
    ///
    Stream(TcpStream),
}

impl TcpSock {
    ///
    pub fn bind(port: u16) -> Self {
        let sock_addr = format!("0.0.0.0:{}", port);
        let tcp_listener = TcpListener::bind(&sock_addr)
            .unwrap_or_else(|err| panic!("failed to bind to {}, the error is: {}", sock_addr, err));
        Self::Listener(tcp_listener)
    }

    ///
    fn listener(&self) -> &TcpListener {
        match *self {
            Self::Listener(ref srv) => srv,
            Self::Stream(_) => panic!("cannot return TcpListener from TcpSock::CLIENT"),
        }
    }

    ///
    fn stream(&self) -> &TcpStream {
        match *self {
            Self::Listener(_) => panic!("cannot return TcpListener from TcpSock::CLIENT"),
            Self::Stream(ref clnt) => clnt,
        }
    }

    ///
    pub fn accept(&self) -> Self {
        match self.listener().accept() {
            Ok((tcp_stream, addr)) => {
                println!("new client: {:?}", addr);
                Self::Stream(tcp_stream)
            }
            Err(e) => panic!("couldn't get client: {:?}", e),
        }
    }

    ///
    pub fn connect(server_name: &str, port: u16) -> Self {
        let sock_addr = format!("{}:{}", server_name, port);
        let tcp_stream = TcpStream::connect(&sock_addr).unwrap_or_else(|err| {
            panic!("failed to connect to {}, the error is: {}", sock_addr, err)
        });
        Self::Stream(tcp_stream)
    }

    ///
    fn exchange_data<T: Serialize, U: DeserializeOwned>(&self, data: &T) -> U {
        let xfer_size = std::mem::size_of::<T>();
        let encoded: Vec<u8> = bincode::serialize(data)
            .unwrap_or_else(|err| panic!("failed to encode, the error is: {}", err));
        let send_size = self
            .stream()
            .write(&encoded)
            .unwrap_or_else(|err| panic!("failed to send data via socket, the error is: {}", err));
        debug_assert_eq!(send_size, encoded.len(), "socket send data size not match");
        let mut decode_buf = Vec::with_capacity(xfer_size);
        unsafe {
            decode_buf.set_len(xfer_size);
        }
        let recv_size = self.stream().read(&mut decode_buf).unwrap_or_else(|err| {
            panic!("failed to receive data via socket, the error is:{}", err)
        });
        unsafe {
            decode_buf.set_len(recv_size.cast());
        }
        debug_assert!(recv_size > 0, "failed to receive data from socket");

        bincode::deserialize(&decode_buf)
            .unwrap_or_else(|err| panic!("failed to decode, the error is: {}", err))
    }
}

fn main() -> anyhow::Result<()> {
    let handler = std::thread::spawn(move || {
        let socket = UdpSocket::bind("0.0.0.0:4791")
            .unwrap_or_else(|err| panic!("failed to bind, the error is:{}", err));
        let mut buf = [0; 64];
        loop {
            // Receives a single datagram message on the socket. If `buf` is too small to hold
            // the message, it will be cut off.
            let (amt, src) = socket
                .recv_from(&mut buf)
                .unwrap_or_else(|err| panic!("failed to recv_from, the error is:{}", err));
            println!("received {} bytes data from {}", amt, src);

            // Redeclare `buf` as slice of the received data and send reverse data back to origin.
            // let buf = &mut buf[..amt];
            // buf.reverse();
            // socket.send_to(buf, &src)?;
        }
    });

    let server_name = "192.168.122.190";
    let sock_port = 9527;
    let client_sock = TcpSock::connect(server_name, sock_port);
    let local_con_data = CmConData::new()?;

    println!("local connection data: {}", local_con_data);
    let local_con_data_be = local_con_data.into_be();
    let remote_con_data_be: CmConData = client_sock.exchange_data(&local_con_data_be);
    let remote_con_data = remote_con_data_be.into_le();
    println!("remote connection data: {}", remote_con_data);

    // Notify server to send
    let resp_recv_ready: State = client_sock.exchange_data(&State::ReceiveReady);
    if let State::ReceiveReady = resp_recv_ready {
        println!("receive ready: {:?}", resp_recv_ready);
    } else {
        panic!("failed to receive ready");
    }

    let join_res = handler.join();
    if let Err(err) = join_res {
        panic!("failed to join, the error is: {:?}", err);
    }

    Ok(())
}
