import os

class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY')
    database_url = os.environ.get('DATABASE_URL')
    if database_url and database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    SQLALCHEMY_DATABASE_URI = database_url or os.environ.get('SQLALCHEMY_DATABASE_URI')
    SQLALCHEMY_TRACK_MODIFICATIONS = False if os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS') == 'False' else True