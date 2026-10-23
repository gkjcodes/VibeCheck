# Corrected Python server sample conforming to secure patterns
import os
import subprocess
import requests

def get_user_record(cursor, user_id):
    # Parameterized SQL query
    return cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

def run_backup(folder_name):
    # Safe subprocess execution without shell=True
    subprocess.run(["tar", "-czf", "backup.tar.gz", folder_name], shell=False, check=True)

def fetch_remote_metrics():
    # Valid TLS verification enabled
    return requests.get("https://internal.metrics.local/api", verify=True)

if __name__ == "__main__":
    from flask import Flask
    app = Flask(__name__)
    # Debug mode controlled via environment variable
    app.run(debug=False)
