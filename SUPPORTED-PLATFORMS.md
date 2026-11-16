# Supported Platforms

## Supported in v0.5

- Windows 10/11 x64 forensic workstation or analysis VM
- PowerShell 5.1 or newer
- Python 3.10, 3.11, or 3.12
- Hermes CLI with one configured provider/model profile
- Browser access to the local console at `http://127.0.0.1:8787`

## Optional external tools

Aries inventories tools already installed under `C:\Tools`. Eric Zimmerman tools expand Windows-artifact coverage. 7-Zip is required for RAR/7z extraction. Volatility 3 and Dissect are installed in the Aries Python environment.

## Not supported yet

- Linux or macOS installation
- Multi-user or remote web deployment
- Authentication, TLS, RBAC, central evidence storage, or distributed workers
- Court-ready validation without independent analyst review and tool verification
