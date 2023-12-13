# IMPORTS

from flask import Blueprint, render_template, flash, redirect, url_for, current_app, session, request
from flask_login import login_user, current_user, login_required, logout_user

from app import db, activity_logger, requires_roles
from models import User
from users.forms import RegisterForm, LoginForm, ChangePasswordForm
from users.utilities import is_login_attempt_available, is_login_ok, process_authentication_attempts

# CONFIG
users_blueprint = Blueprint('users', __name__, template_folder='templates')


# VIEWS
# view registration
@users_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('users.account'))
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

        new_user.registration_log()
        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()
        session['username'] = new_user.email

        flash("You are registered. You have to enable 2-Factor Authentication first to login.", "success")

        return redirect(url_for('users.setup_2fa'))

    # if request method is GET or form not valid re-render signup page
    return render_template('users/register.html', form=form)


# view user login
@users_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash('You are already logged in.', 'success')
        return redirect(url_for('users.account'))
    if not is_login_attempt_available():
        flash(
            "You have exhausted your login attempts. Please try again after {} hours.".format(
                int(current_app.config['LOGIN_ATTEMPTS_HOURS_LIMIT'])),
            "danger")

        return render_template('users/login.html')

    # create login form object
    form = LoginForm()

    # if request method is POST or form is valid
    if form.validate_on_submit():
        process_authentication_attempts()
        login_ok, user = is_login_ok(form)

        if login_ok:
            session.pop('authentication_attempts', None)
            user.update_login_log()
            db.session.commit()
            login_user(user)

            if user.is_admin():
                return redirect(url_for('admin.admin'))
            elif user.is_user():
                return redirect(url_for('lottery.lottery'))

            return redirect(url_for('users.account'))

        flash('Please check your login details and try again, {} login attempts remaining'.format(
            session['authentication_attempts']['remaining']), "danger")

        activity_logger.warn("Invalid log in attempts Username(%s) RemoteAddress(%s)", form.username.data,
                             request.remote_addr,
                             extra={"user": "", "request_url": request.url, "remote_addr": request.remote_addr})

    return render_template('users/login.html', form=form)


@users_blueprint.route("/logout")
@login_required
@requires_roles("user", "admin")
def logout():
    logout_user()
    return redirect(url_for('index'))


@users_blueprint.route("/change-password", methods=['GET', 'POST'])
@login_required
@requires_roles("user", "admin")
def change_password():
    # create login form object
    form = ChangePasswordForm()

    # if request method is POST or form is valid
    if form.validate_on_submit():
        if current_user.is_password_valid(form.current_password.data):
            current_user.set_password(form.new_password.data)
            db.session.commit()
            flash("Password changed successfully", "success")
            return redirect(url_for('users.account'))
        else:
            form.current_password.errors.append("Current password is incorrect.")

    return render_template('users/change-password.html', form=form)


# view user account
@users_blueprint.route('/account')
@requires_roles("user", "admin")
def account():
    return render_template('users/account.html',
                           acc_no=current_user.id,
                           email=current_user.email,
                           firstname=current_user.firstname,
                           lastname=current_user.lastname,
                           phone=current_user.phone,
                           role=current_user.role,
                           date_of_birth=current_user.date_of_birth,
                           postcode=current_user.postcode,
                           )


# 2fa setup page
@users_blueprint.route('/setup_2fa', methods=["GET", "POST"])
def setup_2fa():
    if 'username' not in session:
        return redirect(url_for('index'))

    user = User.query.filter_by(email=session['username']).first()
    if not user:
        return redirect(url_for('index'))

    del session['username']
    uri = user.get_authentication_setup_uri()

    return render_template("users/setup_2fa.html", username=user.email, uri=uri), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
    }
