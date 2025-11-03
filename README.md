# pass2keepassxc

A Python utility to convert password-store (pass) GPG-encrypted password files to KeePassXC CSV format for easy import.

## Installation

### From source

```bash
git clone https://github.com/IGeraGera/pass2keepassxc.git
cd pass2keepassxc
pip install -e .
```

### Requirements

- Python 3.13+
- python-gnupg >= 0.5.5
- [A compatible version of the GnuPG executable](https://gnupg.readthedocs.io/en/latest/)

## Usage

### Basic Usage

```bash
pass2keepassxc --pass-directory ~/.password-store \
               --output-directory ./output \
               --private-key ~/.gnupg/private-key.asc
```

### Command-line Options

```
Options:
  -p, --pass-directory PATH    Path to password-store directory containing .gpg files (required)
  -o, --output-directory PATH  Path to output directory for CSV file (required)
  -k, --private-key PATH       Path to GPG private key file (required)
  -v, --verbose                Enable verbose output (DEBUG level)
  --version                    Show version and exit
  -h, --help                   Show help message and exit
```

## Password File Format

The tool expects password files in the standard password-store format:

```
MySecretPassword123
user: john.doe@example.com
url: https://example.com
Some additional notes
More notes here
```

### Supported Field Names (case-insensitive)

- `user:` or `login:` - Username/login credentials
- `url:` - Associated URL
- First line without `:` - Treated as password
- Everything else - Stored as notes

## Output Format

The tool generates a CSV file named `keepass_export.csv` with the following columns:

- `password` - The password value
- `username` - Username or login
- `title` - Entry title (derived from filename)
- `url` - Associated URL
- `notes` - Additional notes and metadata

This CSV can be directly imported into KeePassXC using:
1. File → Import → Generic CSV Importer
2. Map the columns accordingly

## Troubleshooting

### "Private key file not found"

Ensure the path to your GPG private key is correct. Export your key if needed:

```bash
gpg --export-secret-keys -a your@email.com > private-key.asc
```

### "Failed to import GPG key"

The key file might be corrupted or in the wrong format. Try re-exporting it.

### "No GPG files found"

Check that you're pointing to the correct password-store directory and that it contains `.gpg` files.

### Permission Errors

Ensure you have read permissions for the password files and write permissions for the output directory.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [password-store](https://www.passwordstore.org/) - The standard Unix password manager
- [KeePassXC](https://keepassxc.org/) - The free, open source password manager
- [python-gnupg](https://github.com/vsajip/python-gnupg) - Python wrapper for GnuPG

## Changelog

### Version 0.1.0 (2025-11-03)

- Initial release
- Support for basic password-store format
- Case-insensitive field detection
- Comprehensive error handling and logging
- CSV export for KeePass import
