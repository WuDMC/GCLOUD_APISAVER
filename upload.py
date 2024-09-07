from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import json
from datetime import datetime
import base64
from googleapiclient.http import MediaIoBaseUpload
import io
import os
from dotenv import load_dotenv
import logging


logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# FOLDER MIGROOT DOCS
# https://drive.google.com/drive/folders/1dO-b78iCXCXbaI0hu7-gn_0ZhNIqfi_d
PARENT_FOLDER_ID = "1dO-b78iCXCXbaI0hu7-gn_0ZhNIqfi_d"


class Uploader:
    def __init__(self, credentials_info):
        self.credentials_info = credentials_info
        self.service = self.authorize()

    def authorize(self):
        credentials = service_account.Credentials.from_service_account_info(
            self.credentials_info
        )
        return build("drive", "v3", credentials=credentials)

    def get_existing_folder_id(self, folder_name, parent_folder_id=PARENT_FOLDER_ID):
        try:
            query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder'"
            if parent_folder_id:
                query += f" and '{parent_folder_id}' in parents"

            results = self.service.files().list(q=query, fields="files(id)").execute()
            existing_folders = results.get("files", [])
            if existing_folders:
                return existing_folders[0]["id"]
            else:
                return None
        except Exception as error:
            logging.error(f"An error occurred while checking for existing folder: {error}")
            return None

    def get_file_info(self, file_id):
        try:
            file_info = (
                self.service.files().get(fileId=file_id, fields="id, name").execute()
            )
            return file_info
        except Exception as e:
            logging.error(f"An error occurred while getting file info: {e}")
            return None

    def upload_file(
        self, file_name, mime_type, base64file, parent_folder_id=PARENT_FOLDER_ID
    ):
        try:
            file_data_decoded = base64.b64decode(base64file)
            media = MediaIoBaseUpload(io.BytesIO(file_data_decoded), mimetype=mime_type)
            file_metadata = {"name": file_name, "parents": [parent_folder_id]}
            file = (
                self.service.files()
                .create(body=file_metadata, media_body=media, fields="id")
                .execute()
            )

            logging.info(
                f'File "{file_name}" has been uploaded to Google Drive with ID: {file.get("id")}'
            )
            return file.get("id")

        except Exception as error:
            logging.error(f"An error occurred while uploading the file: {error}")
            return None

    def upload_document(self, file_name, mime_type, base64file, parent_folder_id=PARENT_FOLDER_ID):
        allowed_mime_types = [
            'application/pdf',  # PDF
            'image/jpeg',  # JPG
            'image/png',  # PNG
            'image/gif',  # GIF
            'image/bmp',  # BMP
            'image/tiff',  # TIFF
            'image/webp'  # WebP
        ]

        # Check if the MIME type is allowed
        if mime_type not in allowed_mime_types:
            logging.info(f"File type '{mime_type}' is not allowed. Only PDFs and images (JPG, PNG, etc.) are accepted.")
            return None

        # Decode base64 and check the size
        file_data_decoded = base64.b64decode(base64file)
        file_size = len(file_data_decoded)  # Size in bytes

        # Check if the file size exceeds 10 MB
        if file_size > 10 * 1024 * 1024:  # 10 MB in bytes
            logging.info(f"File size exceeds the 10 MB limit. The file is {file_size / (1024 * 1024):.2f} MB.")
            return None

        # Call the existing upload_file method
        return self.upload_file(file_name, mime_type, base64file, parent_folder_id)

    def find_files_by_name(self, file_name, parent_folder_id=PARENT_FOLDER_ID):
        try:
            query = f"name='{file_name}'"
            if parent_folder_id:
                query += f" and '{parent_folder_id}' in parents"

            results = self.service.files().list(q=query, fields="files(id)").execute()
            existing_files = results.get("files", [])
            return [file["id"] for file in existing_files]

        except Exception as error:
            logging.error(f"An error occurred while finding files: {error}")
            return []

    def delete_file(self, file_id):
        try:
            self.service.files().delete(fileId=file_id).execute()
            logging.info(f"File with ID '{file_id}' has been deleted")
        except Exception as error:
            logging.error(f"An error occurred while deleting the file: {error}")
            return False

    def check_folder_permissions(self, folder_id):
        try:
            permissions = self.service.permissions().list(fileId=folder_id).execute()
            for permission in permissions.get("permissions", []):
                if permission["type"] == "anyone" and permission["role"] == "reader":
                    return True
            return False
        except Exception as error:
            logging.info(f"An error occurred while checking permissions: {error}")
            return False

    def extend_permissions(self, folder_id, email=None):
        try:
            # Define the permission dictionary
            permission = {"type": type, "role": "reader"}

            # If an email is provided, modify the permission for the specific email
            if email:
                permission["type"] = "user"  # Set type to 'user' for specific email
                permission["emailAddress"] = email

            # Create the permission for the folder
            self.service.permissions().create(
                fileId=folder_id, body=permission, fields="id"
            ).execute()

            # Print confirmation message
            logging.info(f"Permissions extended for folder with ID '{folder_id}'")
            if email:
                logging.info(f"Access granted to email: {email}")

        except Exception as error:
            logging.error(f"An error occurred while extending permissions: {error}")

    def create_folder(self, folder_name, parent_folder_id=PARENT_FOLDER_ID):
        metadata = {
            "name": folder_name,
            "mimeType": "application/vnd.google-apps.folder",
            "parents": [parent_folder_id],
        }

        try:
            existing_folder_id = self.get_existing_folder_id(
                folder_name, parent_folder_id
            )
            if existing_folder_id:
                logging.info(
                    f'Folder already existing, url: "{self.get_folder_url(existing_folder_id)}".'
                )
                return existing_folder_id

            file = self.service.files().create(body=metadata, fields="id").execute()
            logging.info(f'Folder created, url: "{self.get_folder_url(file.get("id"))}".')
            return file.get("id")

        except Exception as error:
            logging.error(f"An error occurred: {error}")
            return None

    def get_folder_url(self, folder_id):
        return f"https://drive.google.com/drive/folders/{folder_id}"

if __name__ == "__main__":
    load_dotenv()
    uploader = Uploader(json.loads(os.getenv("GCP_CREDS")))
    # uploader.extend_permissions(folder_id=PARENT_FOLDER_ID, email='email')
    # root_folder_id = 'root'  # Special identifier for Google Drive root
    # folder_name = "migroot_docs"
    #
    # folder_id = uploader.create_folder(folder_name, parent_folder_id=root_folder_id)
    #
    # if folder_id:
    #     logging.info(f'Folder "{folder_name}" created successfully with ID: {folder_id}')
    # else:
    #     logging.info(f'Failed to create folder "{folder_name}".')
