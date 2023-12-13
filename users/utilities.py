from datetime import datetime, timezone, timedelta

from flask import session, current_app

from models import User


def process_authentication_attempts():
    if 'authentication_attempts' not in session:
        session['authentication_attempts'] = {'remaining': int(current_app.config['LOGIN_ATTEMPTS_LIMIT']),
                                              'last_try': datetime.now(timezone.utc)}

    if session['authentication_attempts']['last_try'] - datetime.now(timezone.utc) >= timedelta(
            hours=int(current_app.config['LOGIN_ATTEMPTS_HOURS_LIMIT'])):
        session['authentication_attempts']['remaining'] = int(current_app.config['LOGIN_ATTEMPTS_LIMIT'])

    session['authentication_attempts']['last_try'] = datetime.now(timezone.utc)
    session['authentication_attempts']['remaining'] = session['authentication_attempts']['remaining'] - 1


def is_login_attempt_available():
    return 'authentication_attempts' not in session or session['authentication_attempts']['remaining'] > 1


def is_login_ok(form):
    user: User = User.query.filter_by(email=form.username.data).first()
    user_error = user is None

    if user_error:
        form.username.errors.append(f"Cannot find user with this username")

    password_error = user is not None and not user.is_password_valid(form.password.data)
    if password_error:
        form.password.errors.append(f"Password is invalid")

    otp_error = user is not None and not user.is_otp_valid(form.time_base_pin.data)
    if otp_error:
        form.time_base_pin.errors.append(f"Time-base PIN is invalid")

    postcode_error = user is not None and not user.is_postcode_valid(form.postcode.data)
    if postcode_error:
        form.postcode.errors.append(f"Postcode is invalid")

    login_ok = not (user_error or password_error or otp_error or postcode_error)
    return login_ok, user
