//! A fake host for trying the SSH wizard: answers like a host with the forced inventory command.
//!
//! `cargo run --features fake-host --example fake_ssh_host -- <port> <client public key file> <output file>`
//!
//! The client key is the line the wizard shows (without `restrict,command=…`), the output file what the
//! script would print (e.g. `{ cat /etc/os-release; echo ---; dpkg-query -W -f='…'; } > out.txt`).

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, port, key_file, output_file] = args.as_slice() else {
        eprintln!("usage: fake_ssh_host <port> <client public key file> <output file>");
        std::process::exit(2);
    };
    let key = std::fs::read_to_string(key_file).expect("key file");
    let key = key
        .split_whitespace()
        .skip_while(|w| !w.starts_with("ssh-"))
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    let output = std::fs::read_to_string(output_file).expect("output file");
    let running = opensecmon::inventory::ssh::testserver::start_on(
        port.parse().expect("port"),
        &key,
        output,
        false,
    )
    .await;
    println!("listening on 127.0.0.1:{}", running.port);
    println!("host key: {}", running.host_key);
    tokio::signal::ctrl_c().await.expect("signal");
}
