from flask import Flask, jsonify
from db import get_connection

app = Flask(__name__)

@app.route('/')
def hello():
    return 'Hello from Flask + MySQL!'

@app.route('/users')
def get_users():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(users)

if __name__ == '__main__':
    app.run(debug=True)
