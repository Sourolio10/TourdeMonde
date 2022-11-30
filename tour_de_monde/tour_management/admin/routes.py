import email
from functools import wraps
from lib2to3.pgen2 import token
import re
from urllib import response
from flask import Blueprint, render_template, redirect, url_for, flash, jsonify, request
from flask_login import login_user, current_user, login_required, logout_user
from tour_management.admin.utils import admin_creation, no_admin, super_user
from tour_management.models import (Accomodation, 
                                    Accomodationdetails,
                                    Flightdetails,
                                    Flights,
                                    Location,
                                    Locationdetails,
                                    Place,
                                    Ticket,
                                    Admin,
                                    AdminToken)
from tour_management.models.utils import rand_pass
from tour_management import db, jwt
from tour_management.utilities.util_helpers import send_confirmation_mail
import json
from cerberus import Validator
from tour_management.schemas.admin_apis import admin_signup, admin_login
from flask_api import FlaskAPI, status, exceptions
from flask_jwt_extended import create_access_token,get_jwt,get_jwt_identity, \
                               unset_jwt_cookies, jwt_required, JWTManager
from tour_management.admin.forms import (RegistrationForm,
                                            LoginForm,
                                            ResendEmailConfirmationForm,
                                            ResetPasswordRequestForm,
                                            ResetPasswordForm,
                                            UpdateUsernameForm,
                                            UpdatePasswordForm,
                                            UpdateEmailForm,
                                            SuperUserRegister,
                                            AddAdminsForm,
                                            NewAdminRegistrationForm)

admin = Blueprint('admin', __name__)

@admin.route('/', methods=['GET', 'POST'])
@admin.route('/registration', methods=['GET', 'POST'])
@admin_creation
def registration():
        return redirect(url_for('admin.login'))


@admin.route('/login', methods=['GET', 'POST'])
@admin_creation
@no_admin
# create decorater to check if actually product is validated
def login():
    if current_user.is_authenticated:
        flash('You are aleady logged in.', 'info')
        return redirect(url_for('admin.dashboard'))
    login_form = LoginForm()
    if login_form.validate_on_submit():
        username = login_form.username.data.lower()
        password = login_form.password.data
        org = Admin.query.filter_by(username=username).first()
        if org is None or org.check_password(password) is False:
            flash('Incorrect Username or Password', 'danger')
        elif not org.email_verified:
            flash('Your email is not verified Please verify email first', 'danger')
        elif not org.is_active:
            flash('Your Account is disabled.')
        else:
            login_user(org)
            flash('You are logged in successfully', 'info')
            return redirect(url_for('admin.dashboard'))
    return render_template('admin/login.html', form=login_form)

@admin.route('/registration/admin/<string:token>' , methods=['GET','POST'])
@admin_creation
@no_admin
def register(token):
    token_info = AdminToken.query.filter_by(token=token).first()
    if token_info is None:
        flash('Invalid URL Token', 'danger')
        return redirect(url_for('admin.login'))
    else:
        if not token_info.is_valid():
            flash('Token is expired.', 'danger')
            return redirect(url_for('admin.login'))
        # Enter only if the token is valid.
        first_activation_status = Admin.query.filter_by(username='admin').first()
        if first_activation_status is not None:
            first_user = True
            activation_status = Admin.query.filter_by(id=token_info.id).first()
            if activation_status.first_login == False:
                if token_info.token_type == 'admin_activation':
                    form = SuperUserRegister()
                    if form.validate_on_submit():
                        org = Admin.query.filter_by(username='admin').first()
                        org.name = form.name.data
                        org.username = form.username.data.lower()
                        org.employee_id = form.employee_id.data
                        org.email = form.email.data.lower()
                        org.phone_number = form.phone_number.data
                        org.first_login = True
                        org.password = Admin.hash_password(form.password.data)
                        org.role = 'super_user'
                        # Change These Two once email api is working
                        org.email_verified = True
                        org.is_active = True
                        db.session.commit()
                        flash('Admin signed up successfully', 'success')
                        return redirect(url_for('admin.login'))
                    return render_template('admin/register.html', form = form, item = first_user)
                else:
                    flash ('Invalid Token Type', 'danger')
                    return redirect(url_for('admin.login'))
        else:
            first_user = False
            if token_info.token_type == 'admin_token':
                form = NewAdminRegistrationForm()
                if form.validate_on_submit():
                    admin_id = token_info.admin_id
                    org = Admin.query.filter_by(id = admin_id).first()
                    if org is None or org == []:
                        flash('You need to log in to add admins','danger')
                        return redirect(url_for('admin.login'))
                    else:
                        org.name = form.name.data
                        org.username = form.username.data.lower()
                        org.phone_number = form.phone_number.data
                        org.password = Admin.hash_password(form.password.data)
                        db.session.commit()
                        flash('User signed up successfully', 'success')
                        return redirect(url_for('admin.login'))
                return render_template('admin/register.html', form = form, item = first_user)
            else:
                flash ('Invalid Token Type', 'danger')
                return redirect(url_for('admin.login'))



@admin.route('/add/admins' , methods=['GET','POST'])
@login_required
@super_user
def add_admins():
    form = AddAdminsForm()
    if form.validate_on_submit():
        org = Admin()
        org.employee_id = form.employee_id.data
        org.email = form.email.data
        org.role = form.role.data
        db.session.add(org)
        db.session.commit()
        if org.role == 'super_user':
            super_user_conf_token = AdminToken.generate_token('admin_token', org.id, 1800)
            # send_registration_mail(org.email, url_for('.registration_confirmation',token=super_user_conf_token.token, _external=True))
            flash('Super User is successfully created', 'info')
        elif org.role == 'admin':
            admin_token = AdminToken.generate_token('admin_token', org.id, 1800)
            # send_registration_mail(org.email,url_for('.registration_confirmation',token=admin_token.token, _external=True))
            flash('Admin is successfully created', 'info')
        else:
            flash('error detected' , 'danger')
            return redirect(url_for('admin.dashboard'))
    return render_template('admin/add_admins.html', form=form)


@admin.route('/registration/confirmation/<string:token>')
@admin_creation
def registration_confirmation(token):
    if current_user.is_authenticated:
        return redirect(url_for('admin.dashboard'))
    token_info = AdminToken.query.filter_by(token=token).first()

    if not token_info:
        flash('Invalid registration confirmation token', 'danger')
        return redirect(url_for('admin.login'))
    
    if not token_info.is_valid():
        flash('Token is expired. Please get new registration confirmation link', 'danger')
        return redirect('admin.login')
    token_info.admin.email_verified = True
    token_info.admin.is_active = True
    db.session.commit()
    flash('Email has been verified', 'success')
    return redirect(url_for('admin.register',token=token, _external=True))

@admin.route('/reset-password-request', methods=['GET', 'POST'])
@admin_creation
@no_admin
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('admin.dashboard'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        email = form.email.data
        org = Admin.query.filter_by(email=email).first()
        if not org:
            flash('Email address is not registered with us. Please signup', 'info')
            return redirect(url_for('admin.registration'))
        if not org.email_verified:
            flash('Email is not verified. Please verify email first', 'danger')
            return redirect(url_for('admin.login'))
        if not org.is_active:
            flash('Your account has been deactivated Please contact admin', 'info')
            return redirect(url_for('admin.login'))
        reset_password_token = AdminToken.generate_token(
            'reset_password', org.id, 1800)
        # send_reset_password_mail(org.email,
        #                          url_for('admin.reset_password',
        #                                  token=reset_password_token.token, _external=True))
        flash('Reset password link has been sent to your email address', 'info')
        return redirect(url_for('admin.login'))
    return render_template('admin/reset_password_request.html', form=form)

#Password reset
@admin.route('/reset-password/<string:token>', methods=['GET', 'POST'])
@admin_creation
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('admin.dashboard'))

    token_info = AdminToken.query.filter_by(
        token=token, token_type='reset_password').first()

    if not token_info:
        flash('Invalid Reset password token', 'danger')
        return redirect(url_for('admin.login'))
    if not token_info.is_valid():
        flash('Token is expired. Please get new email confirmation link', 'danger')
        return redirect('admin.login')
    form = ResetPasswordForm()
    if form.validate_on_submit():
        password = form.password.data
        token_info.admin.password = Admin.hash_password(password)
        db.session.commit()
        flash('Your password has been updated. Please login with new password', 'success')
        return redirect(url_for('admin.login'))
    return render_template('admin/reset_password.html', form=form)

@admin.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    return render_template('admin/profile.html', org=current_user)

@admin.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    # user_data = User.query.count()
    # prop_data = Property.query.filter_by(is_active = True).count()
    # bill_data = Metertransactionlog.query.count()
    # server_data = Iotserver.query.filter_by(server_reg_confirm = True).count()
    # admin_data = Admin.query.filter_by(is_active = True).count()
    # device_data = Iotdevice.query.filter_by(device_reg_confirm = True).count()
    # data = [user_data,prop_data,bill_data,server_data,admin_data,device_data]
    # return render_template('admin/dashboard.html', data = data)
    return render_template('admin/dashboard.html')


@admin.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You are logged out successfully.', 'info')
    return redirect(url_for('admin.login'))
    
    
    
@admin.route('/add/accomodation' ,methods=['POST'])
def create_accomodation():
    
    request_body = request.get_json()
    place_name = request.json.get("place_name",None)
    place_obj = Place.query.filter_by(place=place_name).first()
    if place_obj is None or place_obj == []:
        return "Please register a Place", status.HTTP_400_BAD_REQUEST
    
    tempAccomodation = Accomodation()
    tempAccomodation.hotel_name = request.json.get("hotel_name",None)
    tempAccomodation.address = request.json.get("address",None)
    tempAccomodation.discount_code = request.json.get("discount_code")
    tempAccomodation.description = request.json.get("description",None)
    tempAccomodation.email = request.json.get("email",None)
    tempAccomodation.place_id = place_obj.id
    try:
        db.session.add(tempAccomodation)
        db.session.commit()
    except Exception as err:
        print('Error Logged : ', err)
        return "Could not register Accomodation", status.HTTP_400_BAD_REQUEST
    else:
        temp_Acc_Id = Accomodation.query.filter_by(email=tempAccomodation.email).first()
        print("asdsa",temp_Acc_Id.id)
        tempAccDetails = Accomodationdetails()
        tempAccDetails.accomodation_id = temp_Acc_Id.id
        tempAccDetails.description = request.json.get("description",None)
        tempAccDetails.room_capacity = request.json.get("room_capactiy",None)
        tempAccDetails.min_price = request.json.get("min_price",None)
        tempAccDetails.max_price = request.json.get("max_price",None)
        tempAccDetails.rooms_availble = request.json.get("rooms_availble",None)
        try:
            db.session.add(tempAccDetails)
            db.session.commit()
        except Exception as err:
            print('Error Logged : ', err)
            return "Could not register Accomodation", status.HTTP_400_BAD_REQUEST
        else:
            data = {
                    "message" : "Added Accomodation Data"
                    }
            return data, status.HTTP_200_OK



    #Take a hotel name, location, discount code and description 
    #Accomodation detial, will take room capacity, rooms availble, min and max prce and a description 

@admin.route('/add/flight' ,methods=['POST'])
def create_flight():
    request_body = request.get_json()
    tempFlights = Flights()
    tempFlights.flight_name = request.json.get("flight_name",None)
    tempFlights.international = bool(request.json.get("international",None))
    tempFlights.discount_code = request.json.get("discount_code", None)
    
    try:
        db.session.add(tempFlights)
        db.session.commit()
    except Exception as err:
        print('Error Logged : ', err)
        return "Could not register Flight Company", status.HTTP_400_BAD_REQUEST
    else:
        data = {
                "message" : "Added Flight Data"
                }
        return data, status.HTTP_200_OK
        

@admin.route('/add/ticket' ,methods=['POST'])
def create_flight_ticket():
    tempTicket = Ticket()
    tempTicket.type = request.json.get("type",None)
    tempTicket.min_cost = request.json.get("min_cost",None)
    tempTicket.max_cost = request.json.get("max_cost",None)

    try:
        db.session.add(tempTicket)
        db.session.commit()
    except Exception as err:
        print('Error Logged : ', err)
        return "Could not register Flight Ticket Data", status.HTTP_400_BAD_REQUEST
    else:
        data = {
                "message" : "Added Ticket Data"
                }
        return data, status.HTTP_200_OK


@admin.route('/add/flight/details' ,methods=['POST'])
def create_flight_details():
    flight_name_res = request.json.get("flight_name",None)
    flight_type = request.json.get("flight_type",None)
    temp_flights_id = Flights.query.filter_by(flight_name=flight_name_res).first()
    # Change ticket logic. Make a many-to-many table.
    temp_ticket_id = Ticket.query.filter_by(type=flight_type).first()
    if temp_flights_id is None or temp_flights_id == [] or temp_ticket_id is None or temp_ticket_id == []:
        return "Please register a Flight Company or Register a Ticket", status.HTTP_400_BAD_REQUEST
    temp_flights_details_id = Flightdetails()
    temp_flights_details_id.flight_number = request.json.get("flight_number",None)
    temp_flights_details_id.arrival_time = request.json.get("arrival_time",None)
    temp_flights_details_id.depart_tim = request.json.get("depart_tim",None)
    temp_flights_details_id.number_of_seats = request.json.get("number_of_seats",None)
    
    # Add check for source and destination. As they should be a part of the place table.
    
    temp_flights_details_id.source = request.json.get("source",None)
    temp_flights_details_id.destination = request.json.get("destination",None)
    temp_flights_details_id.vacant_seats = request.json.get("vacant_seats",None)
    temp_flights_details_id.flights_id = temp_flights_id.id
    temp_flights_details_id.ticket_id = temp_ticket_id.id
    try:
        db.session.add(temp_flights_details_id)
        db.session.commit()
    except Exception as err:
        print('Error Logged : ', err)
        return "Could not register Flight Details", status.HTTP_400_BAD_REQUEST
    else:
        data = {
                "message" : "Added Flight Details"
                }
        return data, status.HTTP_200_OK


@admin.route('/add/place' ,methods=['POST'])
def create_place():
    request_body = request.get_json()
    tempPlace = Place()
    tempPlace.place = request.json.get("place",None)
    tempPlace.code = request.json.get("code",None)
    
    try:
        db.session.add(tempPlace)
        db.session.commit()
    except Exception as err:
        print('Error Logged : ', err)
        return "Could not register Place", status.HTTP_400_BAD_REQUEST
    else:
        data = {
                "message" : "Added Place Data"
                }
        return data, status.HTTP_200_OK

@admin.route('/add/location' ,methods=['POST'])
def create_location():
    place_name = request.json.get("place_name",None)
    place_obj = Place.query.filter_by(place=place_name).first()
    if place_obj is None or place_obj == []:
        return "Please register a Place", status.HTTP_400_BAD_REQUEST
    
    tempLocation = Location()
    tempLocation.name = request.json.get("name",None)
    tempLocation.season_visit = request.json.get("season_visit",None)
    tempLocation.place_id = place_obj.id
    try:
        db.session.add(tempLocation)
        db.session.commit()
    except Exception as err:
        print('Error Logged : ', err)
        return "Could not register Location", status.HTTP_400_BAD_REQUEST
    else:
        # Need to add unique constraint here
        location_obj = Location.query.filter_by(name=tempLocation.name).first()
        if location_obj is None or location_obj == []:
            return "Please register a Location", status.HTTP_400_BAD_REQUEST
        
        tempLocationDetails = Locationdetails()
        tempLocationDetails.location_id = location_obj.id
        tempLocationDetails.address = request.json.get("address",None)
        tempLocationDetails.average_review = request.json.get("average_review",None)
        tempLocationDetails.average_time = request.json.get("average_time",None)
        tempLocationDetails.contact_email = request.json.get("contact_email",None)
        tempLocationDetails.contact_phone = request.json.get("contact_phone",None)
        tempLocationDetails.owner_name = request.json.get("owner_name",None)
        # tempLocationDetails.image = request.json.get("image",None)
        tempLocationDetails.description = request.json.get("description",None)
        try:
            db.session.add(tempLocationDetails)
            db.session.commit()
        except Exception as err:
            print('Error Logged : ', err)
            return "Could not register Location Details", status.HTTP_400_BAD_REQUEST
        else:
            
        
            data = {
                    "message" : "Added Location/Location Details Data"
                    }
            return data, status.HTTP_200_OK