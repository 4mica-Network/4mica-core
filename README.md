# 4Mica Core

[![Rust](https://github.com/4mica-Network/4mica-core/actions/workflows/rust.yml/badge.svg)](https://github.com/4mica-Network/4mica-core/actions/workflows/rust.yml)

## Getting Started

### Requirements

- [Docker](https://www.docker.com/)
- [Rust](https://www.rust-lang.org/) `stable` 

### Running the Project

To run the project locally, execute the following script:

```bash
deployment/deploy_local.sh
```

This script prepares and launches all required development services. It is designed to:

- Stop execution immediately if any command fails, preventing silent errors.
- Fail when encountering undefined variables, ensuring all variables are explicitly set.
- Detect and handle errors in command pipelines, so no failures are missed.

For more details, refer to the [documentation](https://github.com/4mica-Network/4mica-core).
