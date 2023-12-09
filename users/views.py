# IMPORTS
from flask import Blueprint, render_template, flash, redirect, url_for
from flask_login import login_required, login_user, current_user

from app import db
from models import User
from shared.utils import get_b64encoded_qr_image
from users.forms import RegisterForm, TwoFactorForm

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


# view user login
@users_blueprint.route('/login')
def login():
    return render_template('users/login.html')


# view user account
@users_blueprint.route('/account')
def account():
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
