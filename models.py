from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class App_Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    first_name = db.Column(db.String(120), nullable=False)
    last_name = db.Column(db.String(120), nullable=False)
    gender = db.Column(db.String(120), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    marital_status = db.Column(db.String(120), nullable=False)
    nationality = db.Column(db.String(120), nullable=False)
    profile_photo = db.Column(db.String(120), nullable=True)
    nid_or_passport = db.Column(db.String(120), nullable=True)
    document_image = db.Column(db.String(120), nullable=True)
    verification_status = db.Column(db.String(120), default='UNVERIFIED')
    user_role = db.Column(db.String(80), default='user')  # New field
    is_active = db.Column(db.Boolean, default=False)
    reset_token = db.Column(db.String, nullable=True)


    def __repr__(self):
        return '<User %r>' % self.username
