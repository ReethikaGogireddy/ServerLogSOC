from zipfile import Path
from flask import Flask, request, jsonify
from flask_cors import CORS
import os
from werkzeug.utils import secure_filename
from parser import parse_uploaded_logs
from analytics import analyze_logs

app = Flask(__name__)
CORS(app)

#creating uploaded_folder if that doesn't exist
UPLOAD_FOLDER = "uploaded_logs"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


ALLOWED_EXTENSIONS = {"log", "txt"}

# for health check
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "success",
        "message": "Server is running"
    }), 200


# Endpoint to handle file uploads
@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"message": "No file provided"}), 400

    file = request.files["file"]
    
    if file.filename == "":
        return jsonify({"message": "Empty filename"}), 400

    filename = secure_filename(file.filename) 
  
    # Check the actual file extension
    file_ext = filename.rsplit(".", 1)[1].lower() if "." in filename else ""
     
    if file_ext not in ALLOWED_EXTENSIONS:
        return jsonify({
            "message": "Only .log or .txt files are allowed"
        }), 400
    
    # Clear old files in the upload folder before saving the new one
    for old_file in Path(UPLOAD_FOLDER).iterdir():
            if old_file.is_file():
                old_file.unlink()

    save_path = os.path.join(UPLOAD_FOLDER, filename)
    
    try:
        file.save(save_path)
        return jsonify({"message": f"{filename} uploaded successfully"}), 200
    except Exception as e:
        return jsonify({"message": f"Upload failed: {str(e)}"}), 500

# Endpoint to parse uploaded logs and return structured data
@app.route("/parse", methods=["GET"])
def parse_logs():
    entries = parse_uploaded_logs("uploaded_logs")
    print(entries[:5])
    return jsonify({
        "status": "success",
        "count": len(entries),
        "data": entries
    }), 200

# Endpoint to analyze parsed logs and return insights
@app.route("/analyze", methods=["GET"])
def analyze():
    try:
        entries = parse_uploaded_logs("uploaded_logs")
        analysis = analyze_logs(entries)
        return jsonify({
            "status": "success",
            "analysis": analysis
        }), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Analysis failed: {str(e)}"
        }), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)