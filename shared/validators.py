import re

from wtforms.validators import ValidationError


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
                       'upper_message}{symbol_message}.')
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
            raise ValidationError(self.message.format(
                min=self.min, max=self.max,
                digit_message=', at least 1 digit' if self.check_digit and digit_error else '',
                upper_message=', at least 1 uppercase' if self.check_upper and uppercase_error else '',
                lower_message=', at least 1 lowercase' if self.check_lower and lowercase_error else '',
                symbol_message=', at least 1 special character' if self.check_symbol and symbol_error else '',
            ))


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
