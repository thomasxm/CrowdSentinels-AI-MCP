"""Centralised data directory and binary resolution for installed and development modes.

When installed via pip/uv, data directories (rules, detection-rules) are
bundled inside the package via hatch force-include. In development mode they
live at the project root. External binaries and downloaded data (chainsaw,
sigma rules) go to ``~/.crowdsentinel/`` so they persist across upgrades.

This module provides the single source of truth for all path resolution so
that new tool modules (wireshark, chainsaw, future integrations) can reuse
the same logic.
"""

import os
import shutil
from pathlib import Path
from typing import Optional

# Package directory — the 'src/' folder
_PKG_DIR = Path(__file__).parent

# Project root in development mode — one level above 'src/'
_PROJECT_ROOT = _PKG_DIR.parent

# User data directory — writable location for downloaded data
_USER_DATA_DIR = Path.home() / ".crowdsentinel"


def _resolve_data_dir(
    name: str,
    env_var: Optional[str] = None,
) -> Optional[Path]:
    """Resolve a data directory by checking multiple candidate locations.

    Resolution order:
        1. Environment variable override (if set and path exists)
        2. Inside the installed package  (src/<name>)
        3. User data directory           (~/.crowdsentinel/<name>)
        4. Project root in dev mode      (<project_root>/<name>)

    Args:
        name: Directory name relative to the candidate roots
              (e.g. "rules", "detection-rules/hunting", "chainsaw")
        env_var: Optional environment variable that overrides the path

    Returns:
        The first existing Path, or None if nothing found.
    """
    # 1. Environment variable override
    if env_var:
        env_value = os.environ.get(env_var)
        if env_value:
            p = Path(env_value)
            if p.exists():
                return p

    # 2. Installed package location  (src/rules, src/detection-rules/hunting, …)
    pkg_path = _PKG_DIR / name
    if pkg_path.exists():
        return pkg_path

    # 3. User data directory  (~/.crowdsentinel/rules, ~/.crowdsentinel/chainsaw, …)
    user_path = _USER_DATA_DIR / name
    if user_path.exists():
        return user_path

    # 4. Development / editable-install project root
    project_path = _PROJECT_ROOT / name
    if project_path.exists():
        return project_path

    return None


def get_user_data_dir() -> Path:
    """Return the writable user data directory (~/.crowdsentinel/).

    Used by ``crowdsentinel setup`` and other commands that need to
    download or persist data outside the installed package.
    """
    _USER_DATA_DIR.mkdir(parents=True, exist_ok=True)
    return _USER_DATA_DIR


def get_rules_dir() -> Optional[Path]:
    """Resolve the detection rules directory (Lucene + EQL)."""
    return _resolve_data_dir("rules", env_var="CROWDSENTINEL_RULES_DIR")


def get_hunting_rules_dir() -> Optional[Path]:
    """Resolve the ES|QL hunting rules directory."""
    return _resolve_data_dir(
        str(Path("detection-rules") / "hunting"),
        env_var="CROWDSENTINEL_HUNTING_DIR",
    )


def get_toml_rules_dir() -> Optional[Path]:
    """Resolve the TOML detection rules directory (detection-rules/rules/)."""
    return _resolve_data_dir(
        str(Path("detection-rules") / "rules"),
        env_var="CROWDSENTINEL_TOML_RULES_DIR",
    )


def get_chainsaw_dir() -> Optional[Path]:
    """Resolve the chainsaw root directory."""
    return _resolve_data_dir("chainsaw", env_var="CHAINSAW_DIR")


def get_assets_dir() -> Path:
    """Resolve the assets directory, creating it if necessary."""
    result = _resolve_data_dir("assets", env_var="CROWDSENTINEL_ASSETS_DIR")
    if result is None:
        # Default to user home location, create if needed
        result = _USER_DATA_DIR / "assets"
        result.mkdir(parents=True, exist_ok=True)
    return result


def get_binary_path(
    name: str,
    env_var: Optional[str] = None,
    subdir: Optional[str] = None,
) -> Optional[Path]:
    """Resolve an external binary for tool integration (chainsaw, tshark, etc.).

    Resolution order:
        1. Environment variable override
        2. User data directory    (~/.crowdsentinel/<subdir>/<name>)
        3. Project tree           (<project_root>/<subdir>/<name>)
        4. System PATH via ``shutil.which``

    Args:
        name: Binary name (e.g. "chainsaw", "tshark")
        env_var: Optional environment variable that overrides the path
        subdir: Optional subdirectory where the binary might live
                (e.g. "chainsaw" for chainsaw/chainsaw)

    Returns:
        Path to the binary, or None if not found anywhere.
    """
    # 1. Environment variable override
    if env_var:
        env_value = os.environ.get(env_var)
        if env_value:
            p = Path(env_value)
            if p.exists():
                return p

    # 2. User data directory (crowdsentinel setup installs here)
    if subdir:
        user_binary = _USER_DATA_DIR / subdir / name
        if user_binary.exists():
            return user_binary

    # 3. Project tree (dev mode — setup.sh installs binaries here)
    if subdir:
        project_binary = _PROJECT_ROOT / subdir / name
        if project_binary.exists():
            return project_binary

    # 4. System PATH
    which_result = shutil.which(name)
    if which_result:
        return Path(which_result)

    return None
