# Namingo Domain Manager

[![StandWithUkraine](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/badges/StandWithUkraine.svg)](https://github.com/vshymanskyy/StandWithUkraine/blob/main/docs/README.md)

[![SWUbanner](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/banner2-direct.svg)](https://github.com/vshymanskyy/StandWithUkraine/blob/main/docs/README.md)

Namingo Domain Manager is a powerful and flexible tool for managing **DNS zones** across multiple providers. It provides seamless integration with various DNS services, allowing you to manage and streamline domain name system (DNS) configurations effectively.

## Features
✅ **Multi-provider support** – Manage DNS records across different DNS providers.

✅ **API-based automation** – Configure and update DNS zones using provider APIs.

✅ **Support for popular DNS providers** – Works with multiple DNS services.

✅ **Fast and secure** – Uses API keys for authentication and ensures secure communication.

## Supported Providers & Requirements
Namingo Domain Manager supports the following **DNS providers**, each requiring specific credentials:

| Provider    | Credentials in .env | Requirements  | Status | DNSSEC |
|------------|---------------------|------------|---------------------|---------------------|
| **AnycastDNS** | `API_KEY` | | ✅ | ❌ |
| **Bind9** | `API_KEY:BIND_IP` | [bind9-api-server](https://github.com/getnamingo/bind9-api-server)/[bind9-api-server-sqlite](https://github.com/getnamingo/bind9-api-server-sqlite) | ✅ | 🚧 |
| **Cloudflare** | `EMAIL:API_KEY` or `API_TOKEN` | | ✅ | ❌ |
| **ClouDNS** | `AUTH_ID:AUTH_PASSWORD` | | ✅ | 🚧 |
| **Desec** | `API_KEY` | | ✅ | ✅ |
| **DNSimple** | `API_KEY` | | ✅ | ❌ |
| **Hetzner** | `API_KEY` | | 🚧 | ❌ |
| **PowerDNS** | `API_KEY:POWERDNS_IP` | | ✅ | 🚧 |
| **Vultr** | `API_KEY` | | ✅ | ❌ |

## Documentation

### Installation

**Minimum requirement:** a VPS running Ubuntu 22.04/24.04 or Debian 12/13, with at least 1 CPU core, 2 GB RAM, and 10 GB hard drive space.

To get started, copy the command below and paste it into your server terminal:

```bash
bash <(wget -qO- https://raw.githubusercontent.com/getnamingo/dnspanel/refs/heads/main/docs/install.sh)
```

For detailed installation steps, see [install.md](docs/install.md)

### Update

To get started, copy the command below and paste it into your server terminal:

```bash
bash <(wget -qO- https://raw.githubusercontent.com/getnamingo/dnspanel/refs/heads/main/docs/update.sh)
```

## Contributing
Contributions are welcome! Feel free to submit a pull request or open an issue.

## License
This project is licensed under the **MIT License**.

## Contact
For any issues or feature requests, please open an issue on **[GitHub](https://github.com/getnamingo/dnspanel/issues)**.