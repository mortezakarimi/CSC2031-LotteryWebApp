from flask_wtf import FlaskForm
from wtforms import IntegerField, SubmitField
from wtforms.validators import DataRequired, NumberRange


class DrawForm(FlaskForm):
    number1 = IntegerField(id='no1', validators=[DataRequired(), NumberRange(1, 60)])
    number2 = IntegerField(id='no2', validators=[DataRequired(), NumberRange(1, 60)])
    number3 = IntegerField(id='no3', validators=[DataRequired(), NumberRange(1, 60)])
    number4 = IntegerField(id='no4', validators=[DataRequired(), NumberRange(1, 60)])
    number5 = IntegerField(id='no5', validators=[DataRequired(), NumberRange(1, 60)])
    number6 = IntegerField(id='no6', validators=[DataRequired(), NumberRange(1, 60)])
    submit = SubmitField("Submit Draw")

    def validate(self, **kwargs):
        standard_validators = FlaskForm.validate(self)
        if standard_validators:
            numbers = [
                self.number1.data,
                self.number2.data,
                self.number3.data,
                self.number4.data,
                self.number5.data,
                self.number6.data
            ]

            unique_numbers = set()
            duplicate_fields = set()
            for idx, number in enumerate(numbers):
                if number in unique_numbers:
                    duplicate_fields.add(idx)
                else:
                    unique_numbers.add(number)

            if duplicate_fields:
                error_message = "Numbers must be unique."
                for field_index in duplicate_fields:
                    field_name = f"number{field_index + 1}"
                    getattr(self, field_name).errors.append(error_message)

                return False

            return True
