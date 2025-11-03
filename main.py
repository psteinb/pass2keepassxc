"""Pass to KeePass password converter.

This module provides functionality to convert password-store (pass) GPG-encrypted
password files to KeePass CSV format for easy import.
"""

import argparse
import csv
import logging
import sys
from pathlib import Path

import gnupg

# Constants
FIELD_NAMES = ["password", "username", "title", "url", "notes"]
DEFAULT_OUTPUT_FILENAME = "keypass_export.csv"

# Regex patterns as constants
PATTERN_USER = r"^(user|login):"
PATTERN_URL = r"^url:"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


class GpgDecryptionError(Exception):
    """Raised when GPG decryption fails."""

    pass


class Gnupg:
    """Wrapper class for GPG operations.

    This class provides a simplified interface for GPG decryption operations,
    specifically designed for decrypting password-store files.

    Attributes:
        gpg: The underlying gnupg.GPG instance.
    """

    def __init__(self, key_path: Path) -> None:
        """Initialize the GPG wrapper.

        Args:
            key_path: Path to the GPG private key file.

        Raises:
            FileNotFoundError: If the key file doesn't exist.
            IOError: If the key file cannot be read or imported.
        """
        if not key_path.exists():
            raise FileNotFoundError(f"Private key file not found: {key_path}")

        self.gpg = gnupg.GPG()
        self.gpg.encoding = "utf-8"

        import_result = self.gpg.import_keys_file(key_path=str(key_path))
        if not import_result.count:
            raise IOError(f"Failed to import GPG key from {key_path}")

        logger.info(f"Successfully imported {import_result.count} GPG key(s)")

    def decrypt(self, file_path: Path) -> str:
        """Decrypt a GPG-encrypted file.

        Args:
            file_path: Path to the encrypted file.

        Returns:
            The decrypted content as a string.

        Raises:
            FileNotFoundError: If the file doesn't exist.
            GpgDecryptionError: If decryption fails.
        """
        if not file_path.exists():
            raise FileNotFoundError(f"Encrypted file not found: {file_path}")

        try:
            with open(file_path, "rb") as file:
                decrypted_data = self.gpg.decrypt_file(file)

            if not decrypted_data.ok:
                raise GpgDecryptionError(
                    f"Decryption failed for {file_path}: {decrypted_data.status}"
                )

            if not decrypted_data.data:
                logger.warning(f"Decrypted file is empty: {file_path}")
                return ""

            return decrypted_data.data.decode("utf-8")
        except Exception as e:
            if isinstance(e, GpgDecryptionError):
                raise
            raise GpgDecryptionError(f"Error decrypting {file_path}: {e}") from e


class PasswordEntry:
    """Represents a single password entry.

    Attributes:
        password: The password value.
        username: The username or login.
        title: The entry title (usually the filename).
        url: The associated URL.
        notes: Additional notes or information.
    """

    def __init__(
        self,
        title: str,
        password: str = "",
        username: str = "",
        url: str = "",
        notes: str = "",
    ) -> None:
        """Initialize a password entry.

        Args:
            title: The entry title.
            password: The password value.
            username: The username or login.
            url: The associated URL.
            notes: Additional notes.
        """
        self.password = password
        self.username = username
        self.title = title
        self.url = url
        self.notes = notes

    def to_dict(self) -> dict[str, str]:
        """Convert the entry to a dictionary.

        Returns:
            A dictionary representation of the entry.
        """
        return {
            "password": self.password,
            "username": self.username,
            "title": self.title,
            "url": self.url,
            "notes": self.notes,
        }


def parse_line(line: str, entry: PasswordEntry) -> bool:
    """Parse a single line and update the password entry.

    Args:
        line: The line to parse.
        entry: The password entry to update.

    Returns:
        True if the line was parsed as a special field, False if it should
        be added to notes.
    """
    line = line.strip()
    if not line:
        return True

    line_lower = line.lower()

    # Check for username/login (case-insensitive)
    if line_lower.startswith(("user:", "login:")):
        if not entry.username:  # Only set if not already set
            entry.username = line.split(":", 1)[1].strip()
        return True

    # Check for URL (case-insensitive)
    if line_lower.startswith("url:"):
        if not entry.url:  # Only set if not already set
            entry.url = line.split(":", 1)[1].strip()
        return True

    return False


def parse_password_file(content: str, title: str) -> PasswordEntry:
    """Parse the content of a password file.

    The password-store format typically has:
    - First line: password (or a special field)
    - Subsequent lines: metadata fields (user:, login:, url:) or notes

    Args:
        content: The decrypted file content.
        title: The title for this entry (usually the filename).

    Returns:
        A PasswordEntry with parsed information.
    """
    entry = PasswordEntry(title=title)

    if not content:
        logger.warning(f"Empty content for entry: {title}")
        return entry

    lines = content.splitlines()
    if not lines:
        return entry

    # Parse first line
    first_line = lines[0].strip()

    if ":" not in first_line:
        # First line is the password
        entry.password = first_line
    else:
        # First line might be a special field
        if not parse_line(first_line, entry):
            # Not a special field, add to notes
            entry.notes = first_line

    # Parse remaining lines
    notes_lines = []
    for line in lines[1:]:
        if not parse_line(line, entry):
            notes_lines.append(line.strip())

    # Combine notes
    if notes_lines:
        if entry.notes:
            entry.notes += "\n" + "\n".join(notes_lines)
        else:
            entry.notes = "\n".join(notes_lines)

    # Clean up notes (remove trailing newlines)
    entry.notes = entry.notes.strip()

    return entry


def validate_paths(
    pass_directory: Path, output_directory: Path, private_key: Path
) -> tuple[Path, Path, Path]:
    """Validate and expand all provided paths.

    Args:
        pass_directory: Path to the password store directory.
        output_directory: Path to the output directory.
        private_key: Path to the GPG private key.

    Returns:
        A tuple of (expanded_pass_dir, expanded_output_dir, expanded_key_path).

    Raises:
        FileNotFoundError: If required paths don't exist.
        NotADirectoryError: If a directory path points to a file.
    """
    try:
        pass_directory = pass_directory.expanduser().resolve()
        output_directory = output_directory.expanduser().resolve()
        private_key = private_key.expanduser().resolve()
    except (AttributeError, RuntimeError) as e:
        logger.error(f"Error expanding paths: {e}")
        raise ValueError("Please use explicit paths (not relative or with ~)") from e

    # Validate password store directory
    if not pass_directory.exists():
        raise FileNotFoundError(f"Password store directory not found: {pass_directory}")
    if not pass_directory.is_dir():
        raise NotADirectoryError(f"Not a directory: {pass_directory}")

    # Create output directory if it doesn't exist
    if not output_directory.exists():
        logger.info(f"Creating output directory: {output_directory}")
        output_directory.mkdir(parents=True, exist_ok=True)
    elif not output_directory.is_dir():
        raise NotADirectoryError(f"Output path is not a directory: {output_directory}")

    # Validate private key
    if not private_key.exists():
        raise FileNotFoundError(f"Private key not found: {private_key}")
    if not private_key.is_file():
        raise ValueError(f"Private key path is not a file: {private_key}")

    return pass_directory, output_directory, private_key


def export_to_csv(entries: list[PasswordEntry], output_path: Path) -> None:
    """Export password entries to a CSV file.

    Args:
        entries: List of password entries to export.
        output_path: Path to the output CSV file.

    Raises:
        IOError: If the file cannot be written.
    """
    try:
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FIELD_NAMES)
            writer.writeheader()
            for entry in entries:
                writer.writerow(entry.to_dict())
        logger.info(f"Successfully exported {len(entries)} entries to {output_path}")
    except Exception as e:
        raise IOError(f"Failed to write CSV file: {e}") from e


def convert_passwords(
    pass_directory: Path, output_directory: Path, private_key: Path
) -> int:
    """Convert password-store files to KeePass CSV format.

    Args:
        pass_directory: Path to the password store directory.
        output_directory: Path to the output directory.
        private_key: Path to the GPG private key.

    Returns:
        The number of entries successfully converted.

    Raises:
        Various exceptions for validation and processing errors.
    """
    # Validate paths
    pass_directory, output_directory, private_key = validate_paths(
        pass_directory, output_directory, private_key
    )

    # Initialize GPG
    logger.info("Initializing GPG...")
    gpg = Gnupg(key_path=private_key)

    # Find all GPG files
    gpg_files = [f for f in pass_directory.rglob("*.gpg") if f.is_file()]
    logger.info(f"Found {len(gpg_files)} GPG files to process")

    if not gpg_files:
        logger.warning(f"No GPG files found in {pass_directory}")
        return 0

    # Process each file
    entries: list[PasswordEntry] = []
    failed_count = 0

    for file_path in gpg_files:
        try:
            logger.debug(f"Processing: {file_path}")
            content = gpg.decrypt(file_path=file_path)
            entry = parse_password_file(content=content, title=file_path.stem)
            entries.append(entry)
        except GpgDecryptionError as e:
            logger.error(f"Failed to decrypt {file_path}: {e}")
            failed_count += 1
        except Exception as e:
            logger.error(f"Error processing {file_path}: {e}")
            failed_count += 1

    if failed_count > 0:
        logger.warning(f"Failed to process {failed_count} file(s)")

    # Export to CSV
    csv_path = output_directory / DEFAULT_OUTPUT_FILENAME
    export_to_csv(entries, csv_path)

    return len(entries)


def main() -> int:
    """Main entry point for the CLI.

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    parser = argparse.ArgumentParser(
        prog="pass2keepassxc",
        description="Convert password-store (pass) GPG files to KeePass CSV format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --pass-directory ~/.password-store \\
           --output-directory ./output \\
           --private-key ~/.gnupg/private-key.asc

  %(prog)s -p ~/passwords -o . -k ~/gpg-key.asc
        """,
    )
    parser.add_argument(
        "-p",
        "--pass-directory",
        type=Path,
        required=True,
        help="Path to password-store directory containing .gpg files",
        metavar="PATH",
    )
    parser.add_argument(
        "-o",
        "--output-directory",
        type=Path,
        required=True,
        help="Path to output directory for CSV file",
        metavar="PATH",
    )
    parser.add_argument(
        "-k",
        "--private-key",
        type=Path,
        required=True,
        help="Path to GPG private key file",
        metavar="PATH",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output (DEBUG level)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0",
    )

    args = parser.parse_args()

    # Set logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        count = convert_passwords(
            pass_directory=args.pass_directory,
            output_directory=args.output_directory,
            private_key=args.private_key,
        )

        if count > 0:
            logger.info(f"Conversion completed successfully: {count} entries")
            return 0
        else:
            logger.warning("No entries were converted")
            return 1

    except KeyboardInterrupt:
        logger.info("\nOperation cancelled by user")
        return 130
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        return 2
    except ValueError as e:
        logger.error(f"Invalid value: {e}")
        return 3
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
