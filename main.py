from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route("/")
def home():
    return jsonify({"status": "ok", "message": "Kiya backend running"})

@app.route("/health")
def health():
    return jsonify({"healthy": True})

if __name__ == "__main__":
    # Only used when running locally: python main.py
    app.run(host="0.0.0.0", port=10000)

    