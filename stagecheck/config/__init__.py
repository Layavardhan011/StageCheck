"""StageCheck Embedded Configuration Package."""

from pathlib import Path

CONFIG_DIR = Path(__file__).parent / "defaults"

def get_config_path(config_name: str) -> Path:
    """Return path to an embedded configuration asset."""
    path = CONFIG_DIR / config_name
    if not path.is_file():
        raise FileNotFoundError(f"Embedded configuration asset not found: {config_name}")
    return path

