import re

from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, SubmitField, PasswordField, validators, ValidationError


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


class NotEqualTo:
    """
    Compares the values of two fields should not equal.

    :param fieldname:
        The name of the other field to compare to.
    :param message:
        Error message to raise in case of a validation error. Can be
        interpolated with `%(other_label)s` and `%(other_name)s` to provide a
        more helpful error.
    """

    def __init__(self, fieldname, message=None):
        self.fieldname = fieldname
        self.message = message

    def __call__(self, form, field):
        try:
            other = form[self.fieldname]
        except KeyError as exc:
            raise ValidationError(
                field.gettext("Invalid field name '%s'.") % self.fieldname
            ) from exc
        if field.data != other.data:
            return

        d = {
            "other_label": hasattr(other, "label")
                           and other.label.text
                           or self.fieldname,
            "other_name": self.fieldname,
        }
        message = self.message
        if message is None:
            message = field.gettext("Field must not be equal to %(other_label)s.")

        raise ValidationError(message % d)


notEqualTo = NotEqualTo


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
    new_password = PasswordField("New Password", validators=[passwordValidator(), validators.DataRequired(),
                                                             notEqualTo('current_password')])
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            passwordValidator(),
            validators.EqualTo('new_password'),
            validators.DataRequired()
        ]
    )
    submit = SubmitField('Change Password')
