from flask import Flask, render_template, redirect, url_for
from models import db, App_Users
from routes import configure_routes
from config import Config

app = Flask(__name__, static_folder='static')
app.config.from_object(Config)
db.init_app(app)

with app.app_context():
    db.session.expire_all()
    db.create_all()

configure_routes(app)

@app.route('/')
def home():
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
