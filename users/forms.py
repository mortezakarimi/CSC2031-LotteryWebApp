from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, SubmitField, PasswordField, validators
from shared.validators import PasswordValidator, NotEqualTo


class RegisterForm(FlaskForm):
    email = StringField(validators=[validators.Email(), validators.DataRequired()])
    firstname = StringField(
        validators=[validators.Regexp(regex=r"^[^*?!'^+%&\/()=}\]\[{\$#@<>]*$",
                                      message="Firstname must not contain the characters: * ? ! ' ^ + % & / ( ) = } ] "
                                              "[ { $ # @ < >"),
                    validators.DataRequired()])
    lastname = StringField(
        validators=[validators.Regexp(regex=r"^[^*?!'^+%&\/()=}\]\[{\$#@<>]*$",
                                      message="Lastname must not contain the characters: * ? ! ' ^ + % & / ( ) = } ] "
                                              "[ { $ # @ < >"),
                    validators.DataRequired()])
    phone = StringField(validators=[
        validators.regexp(regex=r'\d{4}\-\d{3}\-\d{4}', message="Phone should following format: XXXX-XXX-XXXX"),
        validators.DataRequired()])
    password = PasswordField(validators=[PasswordValidator(), validators.DataRequired()])
    confirm_password = PasswordField(
        validators=[PasswordValidator(), validators.EqualTo('password'), validators.DataRequired()])
    date_of_birth = StringField(
        validators=[validators.regexp(regex=r"^(0[1-9]|[12][0-9]|3[01])\/(0[1-9]|1[012])\/(19|20)\d\d$",
                                      message="Date of Birth should following format: MM/DD/YYYY"),
                    validators.DataRequired()])
    postcode = StringField(
        validators=[validators.regexp(regex=r"^([A-Z])([A-Z]|\d)(\d){0,1}\s\d([A-Z]{2})$",
                                      message="Postal Code should follow one of following formats: XY YXX, XYY YXX, "
                                              "XXY YXX uppercase letters (X) digits (Y)"),
                    validators.DataRequired()])
    submit = SubmitField()


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[validators.DataRequired()])
    password = PasswordField("Password", validators=[validators.DataRequired()])
    time_base_pin = StringField("Time-based PIN",
                                validators=[validators.DataRequired(), validators.Length(min=6, max=6)])
    postcode = StringField(
        validators=[validators.regexp(regex=r"^([A-Z])([A-Z]|\d)(\d){0,1}\s\d([A-Z]{2})$",
                                      message="Postal Code should follow one of following formats: XY YXX, XYY YXX, "
                                              "XXY YXX uppercase letters (X) digits (Y)"),
                    validators.DataRequired()])
    recaptcha = RecaptchaField()
    submit = SubmitField("Login")


class TwoFactorForm(FlaskForm):
    otp = StringField('Enter OTP', validators=[
        validators.InputRequired(), validators.Length(min=6, max=6)])
    submit = SubmitField()


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current Password",
                                     validators=[validators.DataRequired()])
    new_password = PasswordField("New Password", validators=[PasswordValidator(), validators.DataRequired(),
                                                             NotEqualTo('current_password')])
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            PasswordValidator(),
            validators.EqualTo('new_password'),
            validators.DataRequired()
        ]
    )
    submit = SubmitField('Change Password')
