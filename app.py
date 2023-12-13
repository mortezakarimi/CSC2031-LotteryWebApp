# IMPORTS
import logging
import os
from functools import wraps

import flask
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, current_user
from flask_qrcode import QRcode
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from werkzeug.exceptions import BadRequest, InternalServerError, Forbidden, NotFound, ServiceUnavailable


class SecurityFilter(logging.Filter):
    def filter(self, record):
        return 'SECURITY' in record.getMessage()


load_dotenv()  # take environment variables from .env.
# CONFIG
app = Flask(__name__)
app.config.from_mapping(os.environ)
bcrypt = Bcrypt(app)
# initialise database
db = SQLAlchemy(app)
qrcode = QRcode(app)

logger = logging.getLogger()
file_handler = logging.FileHandler('lottery.log', 'a')
file_handler.setLevel(logging.WARNING)
file_handler.addFilter(SecurityFilter())
formatter = logging.Formatter('%(asctime)s : %(message)s', '%m/%d/%Y %I:%M:%S %p')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

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


def requires_roles(*roles):
    """
    see: https://flask.palletsprojects.com/en/2.1.x/patterns/viewdecorators/
    """

    if roles is None:
        roles = ['admin', 'user']

    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if current_user.is_anonymous:
                flash("You need to login to access this resource.", "danger")
                return redirect(url_for('users.login', next=request.url))

            elif current_user.is_authenticated and not current_user.can_action(roles):
                current_user.log_unauthorised_access()
                flask.abort(403)

            return fn(*args, **kwargs)

        return decorated_view

    return wrapper


# HOME PAGE VIEW
@app.route('/')
def index():
    return render_template('main/index.html')


@app.errorhandler(BadRequest)
def handle_bad_request(e):
    return render_template('errors/400.html', e=e), 400


@app.errorhandler(Forbidden)
def handle_bad_request(e):
    return render_template('errors/403.html', e=e), 403


@app.errorhandler(NotFound)
def handle_bad_request(e):
    return render_template('errors/404.html', e=e), 404


@app.errorhandler(InternalServerError)
def handle_bad_request(e):
    return render_template('errors/500.html', e=e), 500


@app.errorhandler(ServiceUnavailable)
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
    return User.query.get(int(user_id))


if __name__ == "__main__":
    app.run(ssl_context=(app.config.get('SSL_PUBLIC_KEY_PATH'), app.config.get('SSL_PRIVATE_KEY_PATH')))
