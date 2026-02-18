# Cert Watch

TLS Certificate Monitor built with GTK4/Adwaita.

![License](https://img.shields.io/badge/license-GPL--3.0-blue)
![Python](https://img.shields.io/badge/python-3.10+-green)

## Features

- Add domains and monitor TLS certificate status
- View certificate details: issuer, expiry, SANs, serial number
- Connection info: cipher suite, protocol version, HSTS status
- Expiry warnings (< 14 days)
- Automatic polling (5-minute intervals)
- Export reports as JSON or CSV
- Dark/light theme toggle
- Keyboard shortcuts (Ctrl+Q to quit)

## Installation

```bash
pip install -e .
cert-watch
```

## Requirements

- Python 3.10+
- GTK4, libadwaita
- PyGObject

## License

GPL-3.0-or-later — Daniel Nylander
