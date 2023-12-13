import logging
import pickle
from datetime import datetime

import pyotp
import rsa
from flask import request
from flask_login import UserMixin
from sqlalchemy import func
from sqlalchemy.orm import make_transient

from app import db, app, bcrypt


# symmetric encryption
# def encrypt(data, secret_key):
#     return Fernet(secret_key).encrypt(bytes(data, 'utf-8'))
#
# symmetric encryption
# def decrypt(data, secret_key):
#     return Fernet(secret_key).decrypt(data).decode('utf-8')
def encrypt(data, public_key):
    return rsa.encrypt(str(data).encode(), public_key)


def decrypt(encrypted_data: bytes, private_key):
    return rsa.decrypt(encrypted_data, private_key).decode()


class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)

    # User authentication information.
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)

    # User information
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(100), nullable=False, default='user')

    date_of_birth = db.Column(db.String(10), nullable=False)
    postcode = db.Column(db.String(7), nullable=False)
    # symmetric encryption
    # secret_key = db.Column(db.BLOB, nullable=False, default=Fernet.generate_key())
    publicKey, privateKey = rsa.newkeys(512)
    public_key = db.Column(db.BLOB, nullable=False, default=pickle.dumps(publicKey))
    private_key = db.Column(db.BLOB, nullable=False, default=pickle.dumps(privateKey))
    pin_key = db.Column(db.String(32), unique=True, nullable=False, default=pyotp.random_base32())
    register_date = db.Column(db.DateTime(), nullable=False, default=func.current_timestamp())
    previous_login = db.Column(db.DateTime(), nullable=True)
    current_login = db.Column(db.DateTime(), nullable=True)
    previous_login_ip = db.Column(db.String(100), nullable=True)
    current_login_ip = db.Column(db.String(100), nullable=True)
    total_login = db.Column(db.Integer, nullable=False, default=0)

    # Define the relationship to Draw
    draws = db.relationship('Draw', backref='user')

    def __init__(self, email, firstname, lastname, phone, password, role, date_of_birth, postcode):
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        self.password = bcrypt.generate_password_hash(password)
        self.role = role
        self.date_of_birth = date_of_birth
        self.postcode = postcode
        # symmetric encryption
        # self.secret_key = Fernet.generate_key()
        publicKey, privateKey = rsa.newkeys(512)
        self.public_key = pickle.dumps(publicKey)
        self.private_key = pickle.dumps(privateKey)
        self.pin_key = pyotp.random_base32()
        self.total_login = 0
        self.register_date = datetime.now()

    def get_authentication_setup_uri(self):
        return pyotp.totp.TOTP(self.pin_key).provisioning_uri(
            name=self.email, issuer_name="CSC2031 Lottery")

    def is_otp_valid(self, user_otp):
        totp = pyotp.parse_uri(self.get_authentication_setup_uri())
        return totp.verify(user_otp)

    def is_password_valid(self, user_password):
        return bcrypt.check_password_hash(self.password, user_password)

    def set_password(self, user_password):
        self.password = bcrypt.generate_password_hash(user_password)

    def is_postcode_valid(self, user_postcode):
        return self.postcode == user_postcode

    def is_admin(self):
        return self.role == 'admin'

    def is_user(self):
        return self.role == 'user'

    def can_action(self, roles=None):
        if roles is None:
            roles = ['admin', 'user']

        return self.role in roles

    def registration_log(self):
        logging.warning("SECURITY - User registration [%s, %s]", self.email, request.remote_addr)

    def update_login_log(self):
        logging.warning("SECURITY - Log in [%s, %s, %s, %s]", self.id, self.email, self.role,
                        request.remote_addr)
        self.total_login = self.total_login + 1
        self.previous_login_ip = self.current_login_ip
        self.previous_login = self.current_login
        self.current_login = datetime.now()
        self.current_login_ip = request.remote_addr

    def log_unauthorised_access(self):
        logging.warning(
            "SECURITY - Unauthorised Access: [%s, %s, %s, %s]", self.id,
            self.email, self.role, request.remote_addr)

    def get_encryption_keys(self):
        return pickle.loads(self.public_key), pickle.loads(self.public_key)

    def get_public_key(self):
        return pickle.loads(self.public_key)

    def get_private_key(self):
        return pickle.loads(self.private_key)

    def __repr__(self):
        return f"<user {self.email}>"


class Draw(db.Model):
    __tablename__ = 'draws'

    id = db.Column(db.Integer, primary_key=True)

    # ID of user who submitted draw
    user_id = db.Column(db.Integer, db.ForeignKey(User.id), nullable=False)

    # 6 draw numbers submitted
    numbers = db.Column(db.String(100), nullable=False)

    # Draw has already been played (can only play draw once)
    been_played = db.Column(db.BOOLEAN, nullable=False, default=False)

    # Draw matches with master draw created by admin (True = draw is a winner)
    matches_master = db.Column(db.BOOLEAN, nullable=False, default=False)

    # True = draw is master draw created by admin. User draws are matched to master draw
    master_draw = db.Column(db.BOOLEAN, nullable=False)

    # Lottery round that draw is used
    lottery_round = db.Column(db.Integer, nullable=False, default=0)

    def __init__(self, user_id, numbers, master_draw, lottery_round,
                 # symmetric encryption
                 # secret_key
                 public_key
                 ):
        self.user_id = user_id
        # symmetric encryption
        # self.numbers = encrypt(numbers, secret_key)
        self.numbers = encrypt(numbers, public_key)
        self.been_played = False
        self.matches_master = False
        self.master_draw = master_draw
        self.lottery_round = lottery_round

    # symmetric encryption
    # def view_draw(self):
    #     secret_key = self.user.secret_key
    #     make_transient(self)
    #     self.numbers = decrypt(self.numbers, secret_key)
    #     return self

    # symmetric encryption
    # def view_numbers(self):
    #     try:
    #       return decrypt(self.numbers, self.user.secret_key)
    #     except:
    #       return self.numbers
    
    def view_draw(self):
        private_key = self.user.get_private_key()
        make_transient(self)
        self.numbers = decrypt(self.numbers, private_key)
        return self

    def view_numbers(self):
        try:
            return decrypt(self.numbers, self.user.get_private_key())
        except:
            return self.numbers


def init_db():
    with app.app_context():
        db.drop_all()
        db.create_all()
        admin = User(email='admin@email.com',
                     password='Admin1!',
                     firstname='Alice',
                     lastname='Jones',
                     phone='0191-123-4567',
                     role='admin',
                     date_of_birth='01/01/1970',
                     postcode='A1 2BC')
        admin.pin_key = 'NLGSMW2FX7UOM26VVBKWREMIF2FFFURR'

        db.session.add(admin)

        # Add custom user
        user = User(email='xavuhire@mailinator.com',
                    password='User1!',
                    firstname='Althea',
                    lastname='Curtis',
                    phone='7646-184-2932',
                    role='user',
                    date_of_birth='13/04/1974',
                    postcode='A1 2BC')
        user.pin_key = 'JL34FERKBY72FYZELMBEL273GXYW4Q7V'
        db.session.add(user)

        db.session.commit()
