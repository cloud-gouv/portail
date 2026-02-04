cargo build; systemd-socket-activate --now --fdname proxy:control -E RUST_LOG=debug --listen 127.0.0.1:8000 --listen $(pwd)/portail.sock ./target/debug/portail
