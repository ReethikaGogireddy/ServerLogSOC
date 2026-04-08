from flask import Flask, request, jsonify
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "success",
        "message": "Server is running"
    }), 200

if __name__ == "__main__":
    app.run(debug=True)
