# IMPORTS
from flask import Flask, render_template
from flask_bcrypt import Bcrypt
from flask_login import LoginManager  # Add this line
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

# CONFIG
app = Flask(__name__)
app.config['SECRET_KEY'] = 'LongAndRandomSecretKey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lottery.db'
app.config['SQLALCHEMY_ECHO'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
bcrypt = Bcrypt(app)
# initialise database
db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()  # Add this line
login_manager.init_app(app)  # Add this line


# HOME PAGE VIEW
@app.route('/')
def index():
    return render_template('main/index.html')


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
    app.run()
