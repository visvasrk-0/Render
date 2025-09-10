import os

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")  # use Render env var
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URI","sqlite:///db.db")     # your Aiven DB URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False