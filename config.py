import os


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "breach-dev-2025")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///pentest.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = "reports"
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024
    SCAN_TIMEOUT = float(os.environ.get("SCAN_TIMEOUT", "1.0"))
    MAX_SCAN_WORKERS = int(os.environ.get("MAX_SCAN_WORKERS", "50"))
    MAX_CIDR_HOSTS = int(os.environ.get("MAX_CIDR_HOSTS", "254"))
