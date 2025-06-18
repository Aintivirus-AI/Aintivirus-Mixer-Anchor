# AINRIVIRUS MIXER program
## Environment version requirement

### `avm: 0.30.1`
### `anchor-cli: 0.29.0`
### `cargo: 1.79.0`
### `rust(command: rustup): 1.27.1`
### `rust(command: rustc): 1.79.0`
### `solana-cli: 1.18.15`
### `node: 20.10.0`

## Anchor dependency version requirement
### `anchor-lang: 0.29.0`
### `anchor-spl: 0.29.0`
### `solana-program: 1.16`

## NPM & Yarn dependency version requirement
### `@solana/web3.js: 1.95.0`
### `@solana/spl-token: 0.4.6`
### `bs58: ^5.0.0`
### `ts-node: ^10.9.2`
### `typescript: ^4.3.5`
### `mocha: ^9.0.3`
### `chai: ^4.3.4`

## Environment initialize step (Linux)
### Install Rust
`curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh`
### Install & Initialize Solana
#### Install Solana
`sh -c "$(curl -sSfL https://release.solana.com/v1.18.15/install)"`
#### Initialize Solana local environment
````
solana config set --url localhost
solana config get
````
`solana-test-validator`
#### Create local Solana wallet
`solana-keygen new`

`solana config set -k ~/.config/solana/id.json`
#### Airdrop test SOL
`solana airdrop 2`
`solana balance`
### Install `avm` & Anchor
#### Install `avm`
`cargo install --git https://github.com/coral-xyz/anchor avm --locked --force`
#### Install Anchor
`avm install 0.29.0`
`avm use 0.29.0`

## Deployed address (Devnet)
#### aintivirus_mixer : `2XzGonB3VWc7KnGdUdU5TM7sH9kSr5PueVLc6isXTSDD`

## Deployed address (Mainnet)
#### aintivirus_mixer : `GWNpsKtdNy9LEZ4P86VHXGB8d25voFYKQDyvVNMixPcP`