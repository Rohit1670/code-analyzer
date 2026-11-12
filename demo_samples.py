import os
import hashlib
import zipfile
import base64
import tempfile
from analyzer import scan_target_full


def create_demo_apk(path):
    b64_c2 = base64.b64encode(b"https://telegram.org").decode("ascii")
    hex_c2 = b"http://185.220.101".hex().encode("ascii")
    dex = (
        b"dex\n035\x00Ldalvik/system/DexClassLoader;"
        b"Landroid/telephony/SmsManager;->sendTextMessage"
        b"Lokhttp3/OkHttpClient;\x00http://198.51.100\x00"
        b"https://firebaseio.com\x00"
        + b64_c2.encode("ascii") + b"\x00" + hex_c2 + b"\x00"
    )
    native_so = b"\x7fELF\x02\x01\x01\x00ptrace\x00Java_com_trojan_NativeBridge_sendData\x00http://91.215.85\x00"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("classes.dex", dex)
        zf.writestr("assets/hidden_update.apk", b"PK\x03\x04FAKE_PAYLOAD")
        zf.writestr("assets/encrypted_config.dat", os.urandom(512))
        zf.writestr("META-INF/CERT.RSA", b"MOCK_CERT_CN=Android Debug_SELF_SIGNED")
        zf.writestr("lib/arm64-v8a/libnative_crypto.so", native_so)


def create_demo_py(path):
    code = (
        'import os, sqlite3\nAPI_SECRET_TOKEN = "live_9a82f3bcde8147d02"\nC2_SERVER_IP = "185.220.101.5"\n'
        'def run(cmd, uid):\n    sqlite3.connect("u.db").execute("SELECT * FROM users WHERE id=\'%s\'" % uid)\n'
        '    eval(cmd)\n    os.system("whoami")\n'
        'HIDDEN = "aHR0cDovL21hbGljaW91cy1jb21tYW5kLWNvbnRyb2wtc2VydmVyLmNvbQ=="\n'
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(code)


def execute_file_scan_job(target_name, uploaded_obj=None):
    with tempfile.TemporaryDirectory() as tmp_dir:
        temp_path = os.path.join(tmp_dir, target_name)
        if uploaded_obj is not None:
            uploaded_obj.seek(0)
            with open(temp_path, "wb") as f:
                while True:
                    chunk = uploaded_obj.read(1024 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)
        elif target_name.endswith(".apk"):
            create_demo_apk(temp_path)
        else:
            create_demo_py(temp_path)

        md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
        with open(temp_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk); sha1.update(chunk); sha256.update(chunk)

        results, exfil, certs, ftree, comps = scan_target_full(temp_path)
        return {
            "name": target_name, "size_kb": round(os.path.getsize(temp_path) / 1024, 2),
            "md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest(),
            "results": results, "exfil": exfil, "certs": certs, "ftree": ftree, "comps": comps
        }
