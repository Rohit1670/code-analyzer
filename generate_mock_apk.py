import zipfile
import base64

def build_mock_malicious_apk(output_filename="mock_bank_trojan.apk"):
    hidden_b64_c2 = base64.b64encode(b"https://hidden-b64-c2-panel.top").decode("ascii")
    hidden_hex_cmd = b"http://185.220.101".hex().encode("ascii")

    mock_dex_content = (
        b"dex\n035\x00"
        b"Ldalvik/system/DexClassLoader;"
        b"Landroid/telephony/SmsManager;->sendTextMessage"
        b"Ljava/lang/Runtime;->exec"
        b"Ljava/lang/reflect/Method;->invoke"
        b"/system/bin/su"
        b"http://198.51.100"
        b"https://c2-exfil-dropzone.xyz\x00"
        + hidden_b64_c2.encode("ascii") + b"\x00"
        + hidden_hex_cmd + b"\x00"
    )

    with zipfile.ZipFile(output_filename, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("classes.dex", mock_dex_content)
        zf.writestr("assets/hidden_update.apk", b"PK\x03\x04FAKE_NESTED_PAYLOAD")
        zf.writestr("lib/arm64-v8a/libnative_crypto.so", b"\x7fELF_MOCK_NATIVE_BINARY")
        zf.writestr("AndroidManifest.xml", b"<manifest package='com.fake.bankupdate'/>")

    print(f"[+] Safe mock APK generated successfully: {output_filename}")

if __name__ == "__main__":
    build_mock_malicious_apk()
