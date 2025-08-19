# 4Mica Core

[![Rust](https://github.com/4mica-Network/4mica-core/actions/workflows/rust.yml/badge.svg)](https://github.com/4mica-Network/4mica-core/actions/workflows/rust.yml)

## Getting Started

### Requirements

- [Docker](https://www.docker.com/)
- [Rust](https://www.rust-lang.org/) `1.85.0` 

### Running the Project

1. **Start the Database**

    Use Docker Compose to start the database:

    ```sh
    docker compose up
    ```

2. **Configure Environment Variables**

    Create a `.env` file in the `core/` directory with the following content:

    ```env
        DATABASE_URL=postgres://postgres:qwerty123456@localhost:5432/core

        BLS_PRIVATE_KEY=9f3eff11070f29192c5f2dde4d047f99fc7861fd82593d22859d5ca03d9e476b

        ETHEREUM_WS_RPC_URL=wss://holesky.4mica.xyz
        ETHEREUM_HTTP_RPC_URL=https://holesky.4mica.xyz
        ETHEREUM_CONTRACT_ADDRESS=0x5FbDB2315678afecb367f032d93F642f64180aa3

    ```

3. **Build and Run**

    Build and run the project using Cargo:

    ```sh
    cargo build
    cargo run --bin core-service
    ```

---

For more details, refer to the [documentation](https://github.com/4mica-Network/4mica-core).
