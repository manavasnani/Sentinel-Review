"""
Language detection from file paths.

Maps file extensions to Language enum values. Used by the diff parser to
tag each DiffFile with the correct language, which downstream routes to
the correct system prompt.
"""

from __future__ import annotations

from pathlib import Path

from sentinel.models import Language


# Reverse index built from the Language enum's file_extensions property.
# Built once at module import time so per-file detection is a cheap dict lookup.
_EXTENSION_TO_LANGUAGE: dict[str, Language] = {
    ext: lang
    for lang in Language
    for ext in lang.file_extensions
}


def detect_language(file_path: str | Path) -> Language | None:
    """
    Determine the programming language of a file based on its extension.

    Args:
        file_path: Path to the file. Can be a string or Path. Only the
                   extension is used; the file does not need to exist on disk.

    Returns:
        The Language enum value for supported extensions, or None if the
        extension is unrecognized.

    Examples:
        >>> detect_language("src/app.py")
        <Language.PYTHON: 'python'>
        >>> detect_language("components/Button.tsx")
        <Language.TYPESCRIPT: 'typescript'>
        >>> detect_language("README.md")
        None
    """
    ext = Path(file_path).suffix.lower()
    return _EXTENSION_TO_LANGUAGE.get(ext)


def is_supported(file_path: str | Path) -> bool:
    """
    Check if a file is a supported language.

    Convenience wrapper around detect_language(). Useful for filtering
    a list of files down to only those Sentinel can analyze.

    Args:
        file_path: Path to the file.

    Returns:
        True if the file's extension maps to a supported language.
    """
    return detect_language(file_path) is not None


def supported_extensions() -> set[str]:
    """
    Return the set of all supported file extensions.

    Useful for CLI help text and for the diff parser to skip files
    that aren't in a supported language.
    """
    return set(_EXTENSION_TO_LANGUAGE.keys())