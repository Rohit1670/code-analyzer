import os
import sqlite3
import subprocess

# 1. High Risk: Hardcoded API Secret String
API_SECRET_TOKEN = "live_9a82f3bcde8147d02"

# 2. Network Indicators: Direct raw server callback destination
C2_SERVER_IP = "185.220.101.5"
EXTERNAL_URL = "http://untrusted-file-repository.net"

def verify_user_access(user_provided_id):
    db = sqlite3.connect("users.db")
    cursor = db.cursor()
    # 3. High Risk: SQL Injection indicator via dynamic formatting inside execute()
    cursor.execute("SELECT * FROM entries WHERE account = '%s'" % user_provided_id)
    return cursor.fetchall()

def fire_system_payload(user_command):
    # 4. Critical Risk: Arbitrary command execution wrapper
    eval(user_command)
    
    # 5. Medium Risk: Direct system/subshell level interaction
    os.system("echo 'Warning: Low-level system modification triggered...'")
    subprocess.Popen("whoami", shell=True)

# 6. Obfuscation Indicator containing hidden C2 URL: "http://malicious-command-control-server.com"
HIDDEN_CALLBACK = "aHR0cDovL21hbGljaW91cy1jb21tYW5kLWNvbnRyb2wtc2VydmVyLmNvbQ=="
