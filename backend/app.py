from flask import Flask, request, jsonify
from flask_cors import CORS
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = "uploaded_logs"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "success",
        "message": "Server is running"
    }), 200



@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"message": "No file provided"}), 400

    file = request.files["file"]
    
    if file.filename == "":
        return jsonify({"message": "Empty filename"}), 400

    filename = secure_filename(file.filename) 
    if not filename.lower().endswith(".log"):
        filename = filename + ".log"

    save_path = os.path.join(UPLOAD_FOLDER, filename)
    
    try:
        file.save(save_path)
        return jsonify({"message": f"{filename} uploaded successfully"}), 200
    except Exception as e:
        return jsonify({"message": f"Upload failed: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)