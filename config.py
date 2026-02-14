import os
from dotenv import load_dotenv

load_dotenv()

# Flask configuration
SECRET_KEY = 'dev-secret-key'  # For development only
SQLALCHEMY_DATABASE_URI = 'sqlite:///users.db'
SQLALCHEMY_TRACK_MODIFICATIONS = False

# Email configuration
EMAIL = 'bhukyadeva23@gmail.com'
PASSWORD = 'flit bcgw alcc zwcf'
HOST = 'smtp.gmail.com'
PORT = 587

# Razorpay configuration
RAZORPAY_KEY_ID = 'test-key-id'  # For development only
RAZORPAY_KEY_SECRET = 'test-key-secret'  # For development only

# Upload folder configuration
UPLOAD_FOLDER = os.path.join('static', 'websites')

# MongoDB Configuration
MONGO_URI = 'mongodb://localhost:27017/'
