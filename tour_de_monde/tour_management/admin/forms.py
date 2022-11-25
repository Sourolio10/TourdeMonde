import re
from flask_wtf import FlaskForm
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField,SelectField, RadioField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional, InputRequired
from flask_wtf.file import FileField, FileAllowed
from tour_management.models import Admin


class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[
        DataRequired(), Length(min=2, max=255)])
    username = StringField('Username', validators=[
                           DataRequired(), Length(min=2, max=255)])
    employee_id = StringField('EmployeeID', validators=[
                               DataRequired(), Length(min=3, max=10)])
    email = StringField('Email', validators=[Email()])
    phone_number = StringField('Phone number', validators=[
                               DataRequired(), Length(min=10, max=10)])
    password = PasswordField('Password', validators=[
                             DataRequired(), Length(min=6)])
    password_confirm = PasswordField('Password Confirmation', validators=[
                                     DataRequired(), EqualTo('password')])
    submit = SubmitField('Signup')
    def validate_username(self, username):
        if not re.match('^[A-Za-z]+(?:[-][A-Za-z0-9]+)*$', username.data.lower()):
            raise ValidationError('Please enter valid characters')

        org = Admin.query.filter_by(username=username.data).first()
        if org:
            raise ValidationError('Username is aleady in use.')

    def validate_employee_id(self, employee_id):
        org = Admin.query.filter_by(employee_id=employee_id.data).first()
        if org:
            raise ValidationError('EmployeeID aleady exists.')

    def validate_email(self, email):
        org = Admin.query.filter_by(email=email.data.lower()).first()
        if org:
            raise ValidationError('Email is aleady in use.')

    def validate_phone_number(self, phone_number):
        if not phone_number.data.isdigit():
            raise ValidationError('Only numeric values are allowed')

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


class UpdateUsernameForm(FlaskForm):
    old_username = StringField('Old Username', validators=[
                                DataRequired(), Length(min=1, max=10)])
    username = StringField('Username', validators=[
                                DataRequired(), Length(min=1, max=10)])
    submit = SubmitField('Register')


class UpdatePasswordForm(FlaskForm):
    old_password = PasswordField('Old Password', validators=[
                             DataRequired(), Length(min=6)])
    password = PasswordField('Password', validators=[
                             DataRequired(), Length(min=6)])
    submit = SubmitField('Register')


class UpdateEmailForm(FlaskForm):
    old_email = StringField('Old Email', validators=[Email()])
    email = StringField('Email', validators=[Email()])
    submit = SubmitField('Register')


class SuperUserRegister(FlaskForm):
    name = StringField('Name', validators=[
        DataRequired(), Length(min=2, max=255)])
    username = StringField('Username', validators=[
                           DataRequired(), Length(min=2, max=255)])
    employee_id = StringField('EmployeeID', validators=[
                               DataRequired(), Length(min=3, max=10)])
    email = StringField('Email', validators=[Email()])
    phone_number = StringField('Phone number', validators=[
                               DataRequired(), Length(min=10, max=10)])
    password = PasswordField('Password', validators=[
                             DataRequired(), Length(min=6)])
    password_confirm = PasswordField('Password Confirmation', validators=[
                                     DataRequired(), EqualTo('password')])
    submit = SubmitField('Signup')
    def validate_username(self, username):
        if username == 'admin':
            raise ValidationError('This username is not permitted. Please choose another username')
        
        if not re.match('^[A-Za-z]+(?:[-][A-Za-z0-9]+)*$', username.data.lower()):
            raise ValidationError('Please enter valid characters')

        org = Admin.query.filter_by(username=username.data).first()
        if org:
            raise ValidationError('Username is aleady in use.')

    def validate_employee_id(self, employee_id):
        org = Admin.query.filter_by(employee_id=employee_id.data).first()
        if org:
            raise ValidationError('EmployeeID aleady exists.')

    def validate_password(self, password):
        if password == 'admin':
            raise ValidationError('This password is not permitted. Please choose another')

    def validate_phone_number(self, phone_number):
        if not phone_number.data.isdigit():
            raise ValidationError('Only numeric values are allowed')


class AddAdminsForm(FlaskForm):
    employee_id = StringField('EmployeeID', validators=[
                               DataRequired(), Length(min=3, max=10)])
    email = StringField('Email', validators=[Email()])

    role = RadioField('Role', choices=[('super_user','Super User'),('admin','Admin')])
    
    submit = SubmitField('Submit')

    def validate_employee_id(self, employee_id):
        org = Admin.query.filter_by(employee_id=employee_id.data).first()
        if org:
            raise ValidationError('EmployeeID aleady exists.')

    def validate_email(self, email):
        org = Admin.query.filter_by(email=email.data.lower()).first()
        if org:
            raise ValidationError('Email is aleady in use.')


class NewAdminRegistrationForm(FlaskForm):
    name = StringField('Name', validators=[
        DataRequired(), Length(min=2, max=255)])
    username = StringField('Username', validators=[
                           DataRequired(), Length(min=2, max=255)])
    phone_number = StringField('Phone number', validators=[
                               DataRequired(), Length(min=10, max=10)])
    password = PasswordField('Password', validators=[
                             DataRequired(), Length(min=6)])
    password_confirm = PasswordField('Password Confirmation', validators=[
                                     DataRequired(), EqualTo('password')])
    submit = SubmitField('Signup')
    def validate_username(self, username):
        if username == 'admin':
            raise ValidationError('This username is not permitted. Please choose another username')
        
        if not re.match('^[A-Za-z]+(?:[-][A-Za-z0-9]+)*$', username.data.lower()):
            raise ValidationError('Please enter valid characters')

        org = Admin.query.filter_by(username=username.data).first()
        if org:
            raise ValidationError('Username is aleady in use.')

    def validate_password(self, password):
        if password == 'admin':
            raise ValidationError('This password is not permitted. Please choose another')

    def validate_phone_number(self, phone_number):
        if not phone_number.data.isdigit():
            raise ValidationError('Only numeric values are allowed')
