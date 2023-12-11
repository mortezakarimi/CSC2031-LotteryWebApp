# IMPORTS
from datetime import datetime, timedelta, timezone

from flask import Blueprint, render_template, flash, redirect, url_for, current_app, session
from flask_login import login_user, current_user, login_required, logout_user

from app import db
from models import User
from shared.utils import get_b64encoded_qr_image
from users.forms import RegisterForm, TwoFactorForm, LoginForm

# CONFIG
users_blueprint = Blueprint('users', __name__, template_folder='templates')


# VIEWS
# view registration
@users_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    # create signup form object
    form = RegisterForm()

    # if request method is POST or form is valid
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        # if this returns a user, then the email already exists in database

        # if email already exists redirect user back to signup page with error message so user can try again
        if user:
            flash('Email address already exists')
            return render_template('users/register.html', form=form)

        # create a new user with the form data
        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=form.password.data,
                        role='user',
                        date_of_birth=form.date_of_birth.data,
                        postcode=form.postcode.data
                        )

        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flash("You are registered. You have to enable 2-Factor Authentication first to login.", "success")

        return redirect(url_for('users.two_factor_setup'))

    # if request method is GET or form not valid re-render signup page
    return render_template('users/register.html', form=form)


def is_login_attempt_available():
    if 'login_attempts' not in session:
        session['login_attempts'] = {'remaining': int(current_app.config['LOGIN_ATTEMPTS_LIMIT']),
                                     'last_try': datetime.now(timezone.utc)}

    if session['login_attempts']['last_try'] - datetime.now(timezone.utc) >= timedelta(
            hours=int(current_app.config['LOGIN_ATTEMPTS_HOURS_LIMIT'])):
        session['login_attempts']['remaining'] = int(current_app.config['LOGIN_ATTEMPTS_LIMIT'])

    session['login_attempts']['last_try'] = datetime.now(timezone.utc)
    session['login_attempts']['remaining'] = session['login_attempts']['remaining'] - 1
    return session['login_attempts']['remaining'] > 0


# view user login
@users_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('users.account'))

    # create login form object
    form = LoginForm()

    # if request method is POST or form is valid
    if form.validate_on_submit():

        if is_login_attempt_available():
            user = User.query.filter_by(email=form.username.data).first()
            if user is None:
                form.username.errors.append(f"Cannot find user with this username")
            else:
                if not user.is_password_valid(form.password.data):
                    form.password.errors.append(f"Password is invalid")
                else:
                    if not user.is_otp_valid(form.time_base_pin.data):
                        form.time_base_pin.errors.append(f"Time-base PIN is invalid")
                    else:
                        if not user.is_postcode_valid(form.postcode.data):
                            form.postcode.errors.append(f"Postcode is invalid")
                        else:
                            session.pop('login_attempts', None)
                            login_user(user)
                            return redirect(url_for('users.account'))

            flash(f"You have {session['login_attempts']['remaining']} attempts remaining.", "info")
        else:
            flash(
                f"You have exhausted your login attempts. Please try again after {int(current_app.config['LOGIN_ATTEMPTS_HOURS_LIMIT'])} hours.",
                "danger")

    return render_template('users/login.html', form=form)


@users_blueprint.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


# view user account
@users_blueprint.route('/account')
def account():
    if not current_user.is_two_factor_authentication_enabled:
        return redirect(url_for('users.two_factor_setup'))
    return render_template('users/account.html',
                           acc_no="PLACEHOLDER FOR USER ID",
                           email="PLACEHOLDER FOR USER EMAIL",
                           firstname="PLACEHOLDER FOR USER FIRSTNAME",
                           lastname="PLACEHOLDER FOR USER LASTNAME",
                           phone="PLACEHOLDER FOR USER PHONE")


# 2fa setup page
@users_blueprint.route('/2fa-setup', methods=["GET", "POST"])
@login_required
def two_factor_setup():
    secret = current_user.secret_token
    uri = current_user.get_authentication_setup_uri()
    base64_qr_image = get_b64encoded_qr_image(uri)

    form = TwoFactorForm()
    # if request method is POST or form is valid
    if form.validate_on_submit():
        if current_user.is_otp_valid(form.otp.data):
            if current_user.is_two_factor_authentication_enabled:
                flash("2FA verification successful. You are logged in!", "success")
                # sends user to login page
                return redirect(url_for('users.login'))
            else:
                try:
                    current_user.is_two_factor_authentication_enabled = True
                    db.session.commit()
                    flash("2FA setup successful. You are logged in!", "success")
                    # sends user to login page
                    return redirect(url_for('users.login'))
                except Exception:
                    db.session.rollback()
                    flash("2FA setup failed. Please try again.", "danger")
                    return redirect(url_for('users.two_factor_setup'))
        else:
            flash("Invalid OTP. Please try again.", "danger")
            return redirect(url_for('users.two_factor_setup'))
    else:
        if not current_user.is_two_factor_authentication_enabled:
            flash(
                "You have not enabled 2-Factor Authentication. Please enable it first.", "info")
        return render_template("users/2fa-setup.html", secret=secret, qr_image=base64_qr_image, form=form)
