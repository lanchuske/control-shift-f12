# SeamlessInput

SeamlessInput is a free, open-source, peer-to-peer terminal application for
sharing keyboard and pointer control across macOS and Windows computers, with
text and PNG clipboard synchronization planned.

Every machine uses the same `seamless-input start` command. Peers can discover
one another on a local network or pair using a short-lived code; there are no
permanent server or client roles.

## Build

Install a recent stable Rust toolchain, then build and run the workspace:

```sh
cargo build --workspace
cargo run -p seamless-input -- --help
```

The current workspace establishes the CLI contract. Commands are scaffolds;
peer discovery, pairing, input capture, clipboard synchronization, and the
topology interface are implemented in subsequent project tasks.

## Commands

```text
seamless-input start
seamless-input pair new
seamless-input pair <six-word-code>
seamless-input peers
seamless-input unpair <peer>
seamless-input tui
seamless-input doctor
seamless-input config show
seamless-input config path
```

The project scope, security requirements, and acceptance evidence are in
[`docs/specs/seamless-input-mvp.md`](docs/specs/seamless-input-mvp.md).

## License

SeamlessInput is licensed under the MIT License. See [LICENSE](LICENSE).
