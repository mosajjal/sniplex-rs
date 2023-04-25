# Sniplex

Sniplex is a simple SNI multiplexer that allows you to route TLS connections based on the server name indication (SNI) extension.

## Installation

To install Sniplex, you need to have Rust and Cargo installed on your system. You can download them from [here](https://www.rust-lang.org/tools/install).

Then, you can clone this repository and run `cargo build --release` to compile the binary. The binary will be located in `target/release/sniplex`.

## Usage

To use Sniplex, you need to create a `config.toml` file that specifies the address to listen on and the upstream servers to route the connections to. For example:

```toml
bind = "0.0.0.0:443"

[upstream]
"example.com" = "192.168.1.1:443"
"foo.com" = "192.168.1.2:443"
"bar.com" = "192.168.1.3:443"
```

This config file tells Sniplex to listen on port 443 and forward the connections to different servers based on the SNI value.

To run Sniplex, you can use the following command:

```bash
sniplex -c config.toml -v
```

The `-c` option specifies the path to the config file, and the `-v` option sets the level of verbosity (you can use multiple `-v` flags to increase the verbosity).

## License

Sniplex is licensed under the MIT license. See [LICENSE](LICENSE) for more details.
