import re
from flask_wtf import FlaskForm, Form
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField , SelectField, DateTimeLocalField, DateField, IntegerField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional, InputRequired
from flask_wtf.file import FileField, FileAllowed
from tour_management.models import User

class SignupForm(FlaskForm):
    first_name = StringField('First Name', validators=[
        DataRequired(), Length(min=2, max=255)])
    last_name = StringField('Last Name', validators=[
        DataRequired(), Length(min=2, max=255)])
    phone_number = StringField('Phone number', validators=[
        DataRequired(), Length(min=10, max=10)])
    dob = DateField('Date Of Birth',
                                validators=[InputRequired()])
    sex = StringField('Gender', validators=[
        DataRequired(), Length(min=1, max=10)])
    username = StringField('Username', validators=[
                           DataRequired(), Length(min=2, max=255)])
    email = StringField('Email', validators=[Email()])
    
    password = PasswordField('Password', validators=[
                             DataRequired(), Length(min=6)])
    password_confirm = PasswordField('Password Confirmation', validators=[
                                     DataRequired(), EqualTo('password')])
    terms_and_conditions = BooleanField(
        'I agree to the Security terms and conditions', validators=[DataRequired()])

    submit = SubmitField('Signup')
    # def validate_username(self, username):
    #     if not re.match('^[A-Za-z]+(?:[-][A-Za-z0-9]+)*$', username.data.lower()):
    #         raise ValidationError('Please enter valid characters')

    #     org = User.query.filter_by(username=username.data.lower()).first()
    #     if org:
    #         raise ValidationError('Username is aleady in use.')

    # def validate_email(self, email):
    #     org = User.query.filter_by(email=email.data.lower()).first()
    #     if org:
    #         raise ValidationError('Email is aleady in use.')

    # def validate_phone_number(self, phone_number):
    #     if not phone_number.data.isdigit():
    #         raise ValidationError('Only numeric values are allowed')
    
    # def validate_aadhar_number(self, aadhar_number):
    #     if not aadhar_number.data.isdigit():
    #         raise ValidationError('Only numeric values are allowed')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
                           DataRequired(), Length(min=2, max=255)])
    password = PasswordField('Password', validators=[
                             DataRequired(), Length(min=6)])
    submit = SubmitField('Login')




class ResendEmailConfirmationForm(FlaskForm):
    email = StringField(
        'Enter Email Address', validators=[DataRequired()])
    submit = SubmitField('Resend Email Confirmation')


class ResetPasswordRequestForm(FlaskForm):
    email = StringField(
        'Enter Email Address', validators=[DataRequired()])
    submit = SubmitField('Reset Password')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[
                             DataRequired(), Length(min=6)])
    password_confirm = PasswordField('Password Confirmation', validators=[
                                     DataRequired(), EqualTo('password')])
    submit = SubmitField('Update new password')


class LoginWithEmailForm(FlaskForm):
    email = StringField(
        'Enter Email Address', validators=[DataRequired()])
    submit = SubmitField('Login')

class ValidateotpForm(FlaskForm):
    otp = StringField(
        'Enter OTP', validators=[DataRequired()])
    submit = SubmitField('Verify')


class ResendValidateotpForm(FlaskForm):
    phone = StringField(
        'Enter Phone Number', validators=[DataRequired()])
    submit = SubmitField('Submit')
    
    def validate_phone_number(self, phone_number):
        if not phone_number.data.isdigit():
            raise ValidationError('Only numeric values are allowed')


class DashboardForm(FlaskForm):
    source = StringField('Choose your source', [DataRequired()])
    destination = StringField('Choose your destination', [DataRequired()])
    no_of_rooms = SelectField('How many rooms?' , choices=[('1 Room'), ('2 Rooms'), ('3 Rooms'), ('4 Rooms'), ('5 Rooms')],validators=[InputRequired()],
    coerce=lambda x: x == 'True')
    adults = SelectField('Adults' , choices=[('1'), ('2'), ('3'), ('4'), ('5'), ('6'), ('7'), ('8'), ('9'), ('10')],validators=[InputRequired()],
    coerce=lambda x: x == 'True')
    children = SelectField('Children' , choices=[('1'), ('2'), ('3'), ('4'), ('5')],validators=[InputRequired()],
    coerce=lambda x: x == 'True')
    inputCheckIn = DateField('Check In Date', format='%m/%d/%y', validators=[InputRequired()])
    inputCheckOut = DateField('Check Out Date', format='%m/%d/%y', validators=[InputRequired()])
    submit = SubmitField('Submit')