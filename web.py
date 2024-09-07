from flask import Flask, jsonify, request
from upload import Uploader
import json
import os
from dotenv import load_dotenv
from datetime import datetime
import base64

app = Flask(__name__)
load_dotenv()

# Initialize the Uploader with credentials from environment variables
credentials_info = json.loads(os.getenv("GCP_CREDS"))
uploader = Uploader(credentials_info)

@app.route("/")
def index():
    return jsonify({"Hello": "Migroot"})




@app.route('/upload', methods=['POST'])
def upload():
    try:
        # Get the data from the request
        data = request.get_json()
        base64file = data.get('base64file')
        mimetype = data.get('mimetype')
        username = data.get('username')
        file_name = data.get('filename')

        # Check for required fields
        if not base64file or not mimetype or not username or not file_name:
            return jsonify({"error": "Missing required fields."}), 400

        # Find or create the user folder
        folder_id = uploader.get_existing_folder_id(username)
        if not folder_id:
            folder_id = uploader.create_folder(username)
            if not folder_id:
                return jsonify({"error": "Failed to create or retrieve the user folder."}), 500

        # Check if a file with the same name exists in the folder
        existing_files = uploader.find_files_by_name(file_name, parent_folder_id=folder_id)
        if existing_files:
            # Append timestamp to the file name
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            file_name = f"{os.path.splitext(file_name)[0]}_{timestamp}{os.path.splitext(file_name)[1]}"

        # Upload the document
        file_id = uploader.upload_document(file_name, mimetype, base64file, parent_folder_id=folder_id)
        if not file_id:
            return jsonify({"error": "Failed to upload the file."}), 500

        return jsonify({
            "message": "File uploaded successfully.",
            "file_url": f"https://drive.google.com/file/d/{file_id}/view",
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)

