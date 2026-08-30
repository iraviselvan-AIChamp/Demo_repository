from flask import Flask, request, render_template_string, send_file
import sqlite3
import subprocess
import hashlib
import os

app = Flask(__name__)


def init_db():
    conn = sqlite3.connect("demo.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT
        )
    """)

    cursor.execute("DELETE FROM users")

    cursor.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        ("Alice", "alice123")
    )

    cursor.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        ("Bob", "bob123")
    )

    conn.commit()
    conn.close()


init_db()


@app.route("/")
def home():
    return """
    <h1>CodeQL Vulnerability Demo</h1>

    <p>Endpoints:</p>

    <ul>
        <li>/user?id=1</li>
        <li>/ping?host=localhost</li>
        <li>/hello?name=Alice</li>
        <li>/file?name=test.txt</li>
        <li>/hash?password=test123</li>
    </ul>
    """


# ---------------------------------------------------------
# Vulnerability 1: SQL Injection
# ---------------------------------------------------------

@app.route("/user")
def get_user():

    user_id = request.args.get("id")

    conn = sqlite3.connect("demo.db")
    cursor = conn.cursor()

    # INTENTIONALLY VULNERABLE
    query = f"SELECT username FROM users WHERE id = {user_id}"

    cursor.execute(query)

    user = cursor.fetchone()

    conn.close()

    if user:
        return f"User: {user[0]}"

    return "User not found", 404


# ---------------------------------------------------------
# Vulnerability 2: OS Command Injection
# ---------------------------------------------------------

@app.route("/ping")
def ping():

    host = request.args.get("host")

    # INTENTIONALLY VULNERABLE
    command = "ping -c 1 " + host

    result = subprocess.check_output(
        command,
        shell=True,
        text=True
    )

    return f"<pre>{result}</pre>"


# ---------------------------------------------------------
# Vulnerability 3: Reflected Cross-Site Scripting
# ---------------------------------------------------------

@app.route("/hello")
def hello():

    name = request.args.get("name")

    template = """
        <html>
            <body>
                <h1>Hello {{ name }}</h1>
            </body>
        </html>
    """

    return render_template_string(template, name=name)


# ---------------------------------------------------------
# Vulnerability 4: Path Traversal / Path Injection
# ---------------------------------------------------------

@app.route("/file")
def download_file():

    filename = request.args.get("name")

    # INTENTIONALLY VULNERABLE
    filepath = os.path.join("files", filename)

    return send_file(filepath)


# ---------------------------------------------------------
# Vulnerability 5: Weak Password Hashing
# ---------------------------------------------------------

@app.route("/hash")
def hash_password():

    password = request.args.get("password")

    # INTENTIONALLY VULNERABLE
    password_hash = hashlib.md5(
        password.encode()
    ).hexdigest()

    return password_hash


# ---------------------------------------------------------
# Vulnerability 6: Flask Debug Mode
# ---------------------------------------------------------

if __name__ == "__main__":

    # INTENTIONALLY VULNERABLE
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
