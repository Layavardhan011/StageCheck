"""StageCheck Embedded Schemas Package."""

from pathlib import Path

SCHEMA_DIR = Path(__file__).parent / "assets"

def get_schema_path(schema_name: str) -> Path:
    """Return path to an embedded schema asset."""
    path = SCHEMA_DIR / schema_name
    if not path.is_file():
        raise FileNotFoundError(f"Embedded schema asset not found: {schema_name}")
    return path
