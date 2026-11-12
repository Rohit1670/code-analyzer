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
