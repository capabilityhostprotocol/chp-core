"""chp-adapter-filesystem — governed file read/write/list with path allowlist.

Four capabilities:

* ``read_file``      — read a file's content; content absent from evidence
* ``write_file``     — write or overwrite a file; content absent from evidence
* ``list_directory`` — list entries with optional glob pattern
* ``stat_path``      — check existence, type, and size

Usage::

    from chp_core import LocalCapabilityHost, register_adapter
    from chp_adapter_filesystem import FilesystemAdapter, FilesystemConfig
    import tempfile

    host = LocalCapabilityHost()
    with tempfile.TemporaryDirectory() as tmp:
        register_adapter(host, FilesystemAdapter(FilesystemConfig(allowed_roots=[tmp])))
"""

from __future__ import annotations

from .adapter import FilesystemAdapter, FilesystemConfig

__all__ = ["FilesystemAdapter", "FilesystemConfig"]
