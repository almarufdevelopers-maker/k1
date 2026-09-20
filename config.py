import os
from flask import Flask
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate



app = Flask(__name__)

CORS(app, supports_credentials=True)

app.config["SECRET_KEY"] = "abdimalik@254"
app.config["JWT_SECRET_KEY"] = "Abdimalik@254"
jwt = JWTManager(app)

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "untenaplatform@gmail.com"
app.config["MAIL_PASSWORD"] = "jbnq xuex sdfy ppyl"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["MAIL_DEFAULT_SENDER"] = "untenaplatform@gmail.com" 

mail = Mail(app)



app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://root:e6qmt4lXK7oaTxuHs0FDlFe9pVYbhyo3@dpg-danf18mgekts738ovqg0-a.singapore-postgres.render.com/backenddb_eng7'
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "connect_args": {
       "sslmode": "require"
    }
}



UPLOAD_FOLDER = "uploads"
IMAGE_UPLOAD_FOLDER = os.path.join(UPLOAD_FOLDER, "images")
VIDEO_FOLDER = os.path.join(UPLOAD_FOLDER, "videos")
PDF_FOLDER = os.path.join(UPLOAD_FOLDER, "pdfs")

os.makedirs(IMAGE_UPLOAD_FOLDER, exist_ok=True)
os.makedirs(VIDEO_FOLDER, exist_ok=True)
os.makedirs(PDF_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["IMAGE_UPLOAD_FOLDER"] = IMAGE_UPLOAD_FOLDER
app.config["VIDEO_FOLDER"] = VIDEO_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024

ALLOWED_IMAGE = {"png", "jpg", "jpeg", "webp"}
ALLOWED_VIDEO = {"mp4", "mov", "avi", "mkv", "webm"}
ALLOWED_PDF = {"pdf"}

db = SQLAlchemy(app)
migrate = Migrate(app, db)
