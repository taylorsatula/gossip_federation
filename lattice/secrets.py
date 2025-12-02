"""
Secrets management for Lattice.

Provides a fallback chain for loading secrets:
1. systemd credentials (CREDENTIALS_DIRECTORY) - best security, systemd 250+
2. File-based secrets at /etc/lattice/ - traditional approach

Works on systemd 250+ (with encryption), older systemd, Docker, macOS, etc.
"""

import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Default paths
DEFAULT_SECRETS_DIR = Path("/etc/lattice")
DEFAULT_PRIVATE_KEY_PATH = DEFAULT_SECRETS_DIR / "private_key.pem"
DEFAULT_CONFIG_PATH = DEFAULT_SECRETS_DIR / "config.env"


def _load_from_credentials(name: str) -> Optional[str]:
    """
    Load secret from systemd credentials directory.

    Args:
        name: Credential name (filename in CREDENTIALS_DIRECTORY)

    Returns:
        Secret value or None if not available
    """
    creds_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if not creds_dir:
        return None

    cred_path = Path(creds_dir) / name
    if not cred_path.exists():
        return None

    try:
        value = cred_path.read_text().strip()
        logger.debug(f"Loaded {name} from systemd credentials")
        return value
    except Exception as e:
        logger.warning(f"Failed to read credential {name}: {e}")
        return None


def _load_from_file(path: Path) -> Optional[str]:
    """Load secret from file."""
    if not path.exists():
        return None

    try:
        value = path.read_text().strip()
        logger.debug(f"Loaded secret from {path}")
        return value
    except Exception as e:
        logger.warning(f"Failed to read {path}: {e}")
        return None


def _parse_config_env(content: str) -> dict:
    """
    Parse config.env file format.

    Supports:
        KEY=value
        KEY="quoted value"
        # comments
    """
    config = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue

        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()

        # Remove surrounding quotes
        if (value.startswith('"') and value.endswith('"')) or \
           (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]

        config[key] = value

    return config


def load_private_key() -> str:
    """
    Load the Lattice private key.

    Fallback chain:
    1. systemd credentials (private_key)
    2. /etc/lattice/private_key.pem file

    Returns:
        Private key PEM string

    Raises:
        RuntimeError: If private key cannot be found
    """
    # 1. systemd credentials
    key = _load_from_credentials("private_key")
    if key:
        return key

    # 2. File on disk
    key = _load_from_file(DEFAULT_PRIVATE_KEY_PATH)
    if key:
        return key

    raise RuntimeError(
        f"Private key not found. Checked: "
        f"$CREDENTIALS_DIRECTORY/private_key, "
        f"{DEFAULT_PRIVATE_KEY_PATH}"
    )


def load_config(key: str) -> Optional[str]:
    """
    Load a configuration value.

    Fallback chain:
    1. systemd credentials (config_{key})
    2. /etc/lattice/config.env file

    Args:
        key: Configuration key (e.g., "APP_URL", "BOOTSTRAP_SERVERS")

    Returns:
        Configuration value or None if not found
    """
    # Normalize key for different sources
    key_upper = key.upper()
    key_lower = key.lower()

    # 1. systemd credentials
    value = _load_from_credentials(f"config_{key_lower}")
    if value:
        return value

    # 2. Config file
    config_content = _load_from_file(DEFAULT_CONFIG_PATH)
    if config_content:
        config = _parse_config_env(config_content)
        # Try both with and without LATTICE_ prefix
        if key_upper in config:
            return config[key_upper]
        if f"LATTICE_{key_upper}" in config:
            return config[f"LATTICE_{key_upper}"]

    return None


def save_private_key(private_key_pem: str, path: Path = None) -> Path:
    """
    Save private key to disk with secure permissions.

    Args:
        private_key_pem: Private key in PEM format
        path: Optional custom path (default: /etc/lattice/private_key.pem)

    Returns:
        Path where key was saved

    Raises:
        RuntimeError: If key cannot be saved
    """
    path = path or DEFAULT_PRIVATE_KEY_PATH

    try:
        # Create directory if needed
        if not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            os.chmod(path.parent, 0o700)

        # Write key with restricted permissions
        path.write_text(private_key_pem)
        os.chmod(path, 0o600)

        logger.info(f"Saved private key to {path}")
        return path

    except PermissionError:
        raise RuntimeError(
            f"Permission denied writing to {path}. "
            f"Run with appropriate privileges or use a different path."
        )
    except Exception as e:
        raise RuntimeError(f"Failed to save private key: {e}")


def get_private_key_path() -> Path:
    """
    Get the path where the private key is stored.

    Returns the first existing path from:
    1. $CREDENTIALS_DIRECTORY/private_key (systemd)
    2. /etc/lattice/private_key.pem (default)

    Returns:
        Path to private key file
    """
    creds_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if creds_dir:
        cred_path = Path(creds_dir) / "private_key"
        if cred_path.exists():
            return cred_path

    return DEFAULT_PRIVATE_KEY_PATH
