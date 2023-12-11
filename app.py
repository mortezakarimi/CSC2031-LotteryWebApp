# IMPORTS
import os

import werkzeug.exceptions
from flask import Flask, render_template, redirect, url_for, request
from flask_bcrypt import Bcrypt
from flask_login import LoginManager  # Add this line
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from dotenv import load_dotenv

load_dotenv()  # take environment variables from .env.
# CONFIG
app = Flask(__name__)
app.config.from_mapping(os.environ)
bcrypt = Bcrypt(app)
# initialise database
db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()  # Add this line
login_manager.init_app(app)  # Add this line
Talisman(app, content_security_policy={
    'default-src': [
        '\'self\'',
        'cdnjs.cloudflare.com',
        'www.google.com',
        'www.gstatic.com'
    ],
    'style-src': [
        '\'self\'',
        'cdnjs.cloudflare.com'
    ],
    'script-src': [
        '\'self\'',
        'www.google.com',
        'www.gstatic.com'
    ],
    'img-src': [
        '\'self\'',
        'data:',
    ]
}, content_security_policy_nonce_in=['script-src', 'style-src'])


# HOME PAGE VIEW
@app.route('/')
def index():
    return render_template('main/index.html')


@app.errorhandler(werkzeug.exceptions.BadRequest)
def handle_bad_request(e):
    return render_template('errors/400.html', e=e), 400


@app.errorhandler(werkzeug.exceptions.Forbidden)
def handle_bad_request(e):
    return render_template('errors/403.html', e=e), 403


@app.errorhandler(werkzeug.exceptions.NotFound)
def handle_bad_request(e):
    return render_template('errors/404.html', e=e), 404


@app.errorhandler(werkzeug.exceptions.InternalServerError)
def handle_bad_request(e):
    return render_template('errors/500.html', e=e), 500


@app.errorhandler(werkzeug.exceptions.ServiceUnavailable)
def handle_bad_request(e):
    return render_template('errors/503.html', e=e), 503


# BLUEPRINTS
# import blueprints
from users.views import users_blueprint
from admin.views import admin_blueprint
from lottery.views import lottery_blueprint
from models import User

#
# # register blueprints with app
app.register_blueprint(users_blueprint)
app.register_blueprint(admin_blueprint)
app.register_blueprint(lottery_blueprint)

login_manager.login_view = "users.login"
login_manager.login_message_category = "danger"


@login_manager.user_loader
def load_user(user_id):
    return User.query.filter(User.id == int(user_id)).first()


if __name__ == "__main__":
    app.run(ssl_context=(app.config.get('SSL_PUBLIC_KEY_PATH'), app.config.get('SSL_PRIVATE_KEY_PATH')))
