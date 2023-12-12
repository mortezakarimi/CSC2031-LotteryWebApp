# IMPORTS
import logging
import os
from functools import wraps
from logging.config import dictConfig

import werkzeug.exceptions
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash
from flask.logging import default_handler
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, current_user  # Add this line
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman

dictConfig({

    "version": 1,
    "formatters": {
        "activty": {
            "format": "[%(asctime)s] [RemoteAddress(%(remote_addr)s) | URL(%(request_url)s)] [%(levelname)s | %(module)s] %(message)s",
        },
    },
    "handlers": {
        "file": {
            "class": "logging.FileHandler",
            "filename": "lottery.log",
            "formatter": "activty",
        },
    },

    "loggers": {
        "activity-logger": {
            "level": "INFO",
            "handlers": ["file"],
            "propagate": False,
        }
    },

})

load_dotenv()  # take environment variables from .env.
# CONFIG
app = Flask(__name__)
app.config.from_mapping(os.environ)
bcrypt = Bcrypt(app)
# initialise database
db = SQLAlchemy(app)
migrate = Migrate(app, db)

activity_logger = logging.getLogger("activity-logger")

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


def access_required(role="any"):
    """
    see: https://flask.palletsprojects.com/en/2.1.x/patterns/viewdecorators/
    """

    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if current_user.is_anonymous:
                flash("You need to login to access this resource.", "danger")
                return redirect(url_for('users.login', next=request.url))

            elif current_user.is_authenticated and role.lower() == "admin" and not current_user.is_admin():
                current_user.log_unauthorised_access(role)
                flash("You need to login with \"Admin\" role to access this resource.", "danger")
                return redirect(url_for('users.login', next=request.url))

            elif current_user.is_authenticated and role.lower() == "user" and not current_user.is_user():
                current_user.log_unauthorised_access(role)
                flash("You need to login with \"User\" role to access this resource.", "danger")
                return redirect(url_for('users.login', next=request.url))

            elif current_user.is_authenticated and role.lower() == "any" and not current_user.is_user() and not current_user.is_admin():
                current_user.log_unauthorised_access(role)
                flash("You need to login with \"User\" or \"Admin\" role to access this resource.", "danger")
                return redirect(url_for('users.login', next=request.url))
            return fn(*args, **kwargs)

        return decorated_view

    return wrapper


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
