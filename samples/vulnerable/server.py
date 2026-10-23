# Synthetic vulnerable Python server sample for VibeCheck static analysis
import subprocess
import requests

def get_user_record(cursor, user_id):
    # SQL injection via f-string
    return cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")

def run_backup(folder_name):
    # Shell injection via shell=True
    subprocess.run(f"tar -czf backup.tar.gz {folder_name}", shell=True)

def fetch_remote_metrics():
    # Insecure TLS verification disabled
    return requests.get("https://internal.metrics.local/api", verify=False)

if __name__ == "__main__":
    from flask import Flask
    app = Flask(__name__)
    # Insecure debug mode in production code
    app.run(debug=True)
