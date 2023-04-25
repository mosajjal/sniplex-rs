use clap::{App, Arg};
use serde::{Deserialize, Serialize};
use tls_parser::{parse_tls_extensions, parse_tls_plaintext};
use tokio::io;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::select;
use toml;
use std::fmt::format;
use std::sync::{Arc};
use dashmap::{DashMap};
use log::{info, warn, debug, error};
use stderrlog;
use rand::distributions::{Alphanumeric, DistString};

#[derive(Deserialize, Serialize, Debug)]
struct Config {
    bind: String,
    upstream: DashMap<String, String>,
}


fn get_sni_from_packet(packet: &[u8]) -> Option<String> {
    let res: Result<(&[u8], tls_parser::TlsPlaintext), tls_parser::Err<tls_parser::nom::error::Error<&[u8]>>> = parse_tls_plaintext(&packet);
    if res.is_err() {
        return None;
    }
    let tls_message: &tls_parser::TlsMessage = &res.unwrap().1.msg[0];
    if let tls_parser::TlsMessage::Handshake(handshake) = tls_message {
        if let tls_parser::TlsMessageHandshake::ClientHello(client_hello) = handshake {
            // get the extensions
            let extensions: &[u8] = client_hello.ext.unwrap();
            // parse the extensions
            let res: Result<(&[u8], Vec<tls_parser::TlsExtension>), tls_parser::Err<tls_parser::nom::error::Error<&[u8]>>> = parse_tls_extensions(extensions);
            // iterate over the extensions and find the SNI
            for extension in res.unwrap().1 {
                if let tls_parser::TlsExtension::SNI(sni) = extension {
                    // get the hostname
                    let hostname: &[u8] = sni[0].1;
                    let s: String = match String::from_utf8(hostname.to_vec()) {
                        Ok(v) => v,
                        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
                    };
                    return Some(s);
                }
            }
        }
    }
    None
}

async fn handle_client(client: TcpStream, up: Arc<DashMap<String,String>>) {
    let ray_id = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);
    let src_addr = client.peer_addr().unwrap();
    let metadata = format!("ray_id={} src_ip={}", ray_id, src_addr);

    let mut buf = [0; 1024];
    client.peek(&mut buf).await.expect("peek failed");
    let sni: Option<String> = get_sni_from_packet(&buf);
    if sni.is_none() {
        info!("{}: No SNI found", metadata);
        return;
    } else {
        let sni_string: String = sni.unwrap().to_string();
        info!("{} SNI: {}",metadata, &sni_string);
        let mut upstream: Option<dashmap::mapref::one::Ref<String, String>> = up.get(&sni_string);
        if upstream.is_none() {
            // check DEFAULT upstream
            upstream = up.get("DEFAULT");
            if upstream.is_none() {
                info!("{} No DEFAULT upstream found", metadata);
                return;
            }
        }
        let upstream_addr = upstream.unwrap().to_string();
        let server: Result<TcpStream, io::Error> = TcpStream::connect(upstream_addr.clone()).await;
        if server.is_err() {
            warn!("{} Failed to connect to upstream: {}",metadata, upstream_addr);
            return;
        }
        let server: TcpStream = server.unwrap();
        let (mut eread, mut ewrite) = client.into_split();
        let (mut oread, mut owrite) = server.into_split();
        info!("{} Connected to upstream: {}",metadata,upstream_addr);
        let e2o: tokio::task::JoinHandle<Result<u64, io::Error>> = tokio::spawn(async move { io::copy(&mut eread, &mut owrite).await });
        let o2e: tokio::task::JoinHandle<Result<u64, io::Error>> = tokio::spawn(async move { io::copy(&mut oread, &mut ewrite).await });
        select! {
                _ = e2o => debug!("{} c2s done",metadata),
                _ = o2e => debug!("{} s2c done",metadata),
        }
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let matches: clap::ArgMatches = App::new("sniplex")
        .version("0.1")
        .author("Ali <hi@n0p.me>")
        .about("A simple SNI multiplexer")
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("ADDRESS")
                .help("path to config.toml")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .multiple(true)
                .help("Sets the level of verbosity"),
        )
        .get_matches();

    let config: &str = matches.value_of("config").unwrap();
    // read the config file into a struct
    let config_content: String =
        std::fs::read_to_string(config).expect("Unable to read config file");
    let c: Config = toml::from_str(&config_content).unwrap();

    let log_level: u64 = matches.occurrences_of("verbose");
    stderrlog::new().module(module_path!())
        .verbosity(log_level as usize)
        .timestamp(stderrlog::Timestamp::Second)
        .init()
        .unwrap();


    let listener: TcpListener = TcpListener::bind(c.bind.clone()).await?;
    info!("Listening on {}", c.bind);
    let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    let upstreams: Arc<DashMap<String, String>> =Arc::new(c.upstream); 
    loop {
        let upstreams: Arc<DashMap<String, String>> = upstreams.clone();
        let (client, _) = listener.accept().await?;
        let handle: tokio::task::JoinHandle<()> = tokio::spawn(async move {
            handle_client(client, upstreams).await;
        });
        handles.push(handle);
    }
}

