import os

class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-hard-to-guess-string'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql://postgres:Umwana11@localhost/usermgt'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
