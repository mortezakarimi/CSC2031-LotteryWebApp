import re

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField, validators, ValidationError, IntegerField


class PasswordValidator(object):
    """
    Verify the strength of 'password'
    Returns a dict indicating the wrong criteria
    A password is considered strong if:
        8 characters length or more
        1 digit or more
        1 symbol or more
        1 uppercase letter or more
        1 lowercase letter or more
    """

    def __init__(self, min=6, max=12, check_digit=True, check_lower=True, check_upper=True, check_symbol=True,
                 message=None):
        self.check_symbol = check_symbol
        self.check_upper = check_upper
        self.check_lower = check_lower
        self.check_digit = check_digit
        self.min = min
        self.max = max
        if not message:
            message = ('Password must be between {min} and {max} characters long{digit_message}{lower_message}{'
                       'upper_message}{symbol_message}.').format(
                min=min, max=max,
                digit_message=', at least 1 digit' if self.check_digit else '',
                lower_message=', at least 1 lowercase' if self.check_lower else '',
                upper_message=', at least 1 uppercase' if self.check_upper else '',
                symbol_message=', at least 1 special character' if self.check_symbol else '',
            )
        self.message = message

    @staticmethod
    def has_special_char(s):
        for c in s:
            if not (c.isalpha() or c.isdigit() or c == ' '):
                return True
        return False

    def __call__(self, form, field):
        # calculating the length
        length_error = len(field.data) < self.min or len(field.data) > self.max

        # searching for digits
        digit_error = self.check_digit and re.search(r"\d", field.data) is None

        # searching for uppercase
        uppercase_error = self.check_upper and re.search(r"[A-Z]", field.data) is None

        # searching for lowercase
        lowercase_error = self.check_lower and re.search(r"[a-z]", field.data) is None

        # searching for symbols
        symbol_error = self.check_symbol and self.has_special_char(field.data) is False

        # overall result
        password_ok = not (length_error or digit_error or uppercase_error or lowercase_error or symbol_error)
        if not password_ok:
            raise ValidationError(self.message)


passwordValidator = PasswordValidator


class RegisterForm(FlaskForm):
    email = EmailField(validators=[validators.Email(), validators.DataRequired()])
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
    password = PasswordField(validators=[passwordValidator(), validators.DataRequired()])
    confirm_password = PasswordField(
        validators=[passwordValidator(), validators.EqualTo('password'), validators.DataRequired()])
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
    submit = SubmitField()


class TwoFactorForm(FlaskForm):
    otp = StringField('Enter OTP', validators=[
        validators.InputRequired(), validators.Length(min=6, max=6)])
    submit = SubmitField()
