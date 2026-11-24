import re
import html
import socket
import ipaddress

MAX_ZIP_ENTRIES = 2500
MAX_SINGLE_ENTRY_BYTES = 100 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 500 * 1024 * 1024
MAX_REGEX_SCAN_BYTES = 10 * 1024 * 1024
MAX_PYTHON_FILE_BYTES = 2 * 1024 * 1024


def is_safe_public_target(host):
    if not host or host.lower() in ("localhost", "0.0.0.0"):
        return False, "Blocked internal/loopback hostname"
    try:
        resolved_ip = socket.gethostbyname(host)
        ip_obj = ipaddress.ip_address(resolved_ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved:
            return False, f"Blocked non-public IP range ({resolved_ip})"
        return True, resolved_ip
    except Exception:
        return False, "DNS resolution failed"


def validate_zip_bomb(zf):
    infos = zf.infolist()
    if len(infos) > MAX_ZIP_ENTRIES:
        return False, f"Archive exceeds max entry limit ({len(infos)} > {MAX_ZIP_ENTRIES})"
    total_size = 0
    for info in infos:
        if info.file_size > MAX_SINGLE_ENTRY_BYTES:
            return False, f"Zip Bomb protection: '{info.filename}' exceeds 100 MB limit"
        total_size += info.file_size
        if total_size > MAX_TOTAL_UNCOMPRESSED_BYTES:
            return False, "Zip Bomb protection: Total uncompressed archive exceeds 500 MB limit"
    return True, "OK"


def sanitize_html(value):
    return html.escape(str(value), quote=True)


def sanitize_dot_label(value):
    return re.sub(r'[^a-zA-Z0-9._:/ -]', '_', str(value))[:45]


# --- NEW: Zip Slip, Symlink & Archive Extraction Guard ---
import os
import zipfile

MAX_EXTRACT_SIZE = 500 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100.0
MAX_FILES = 10_000


class ArchiveSecurityError(Exception):
    pass


def validate_and_extract_zip(zip_path: str, dest_dir: str) -> list[str]:
    dest_root = os.path.realpath(dest_dir)
    os.makedirs(dest_root, exist_ok=True)
    extracted_files: list[str] = []
    total_uncompressed = 0

    if not zipfile.is_zipfile(zip_path):
        raise ArchiveSecurityError("Invalid or corrupted ZIP/APK container.")

    with zipfile.ZipFile(zip_path, "r") as zf:
        infos = zf.infolist()
        if len(infos) > MAX_FILES:
            raise ArchiveSecurityError(f"Archive exceeds file count limit ({len(infos)} > {MAX_FILES}).")

        for info in infos:
            unix_mode = (info.external_attr >> 16) & 0o170000
            if unix_mode == 0o120000:
                raise ArchiveSecurityError(f"Blocked symlink entry in archive: {info.filename}")

            target_path = os.path.realpath(os.path.join(dest_root, info.filename))
            if not (target_path == dest_root or target_path.startswith(dest_root + os.sep)):
                raise ArchiveSecurityError(f"Zip Slip path traversal detected: {info.filename}")

            total_uncompressed += info.file_size
            if total_uncompressed > MAX_EXTRACT_SIZE:
                raise ArchiveSecurityError("Cumulative uncompressed size exceeds safety ceiling.")

            if info.compress_size > 0:
                ratio = info.file_size / info.compress_size
                if ratio > MAX_COMPRESSION_RATIO and info.file_size > 10 * 1024 * 1024:
                    raise ArchiveSecurityError(f"Suspicious compression ratio ({ratio:.1f}x) on {info.filename}")

            if info.is_dir():
                os.makedirs(target_path, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                with zf.open(info, "r") as src, open(target_path, "wb") as dst:
                    dst.write(src.read())
                extracted_files.append(target_path)

    return extracted_files
