import email
from functools import wraps
from lib2to3.pgen2 import token
import re
from urllib import response
from flask import Blueprint, render_template, redirect, url_for, flash, jsonify, request
from flask_login import login_user, current_user, login_required, logout_user
from tour_management.models.Accomodation import Accomodation
from tour_management.models.Accomodationdetails import Accomodationdetails
from tour_management.models.Flightdetails import Flightdetails
from tour_management.models.Flights import Flights
from tour_management.models.Location import Location
from tour_management.models.Locationdetails import Locationdetails
from tour_management.models.Place import Place
from tour_management.models.Ticket import Ticket
# from tour_management.models.Admin import Admin
from tour_management.models.utils import rand_pass
from tour_management import db, jwt
from tour_management.utilities.util_helpers import send_confirmation_mail
import json
from cerberus import Validator
from tour_management.schemas.admin_apis import admin_signup, admin_login
from flask_api import FlaskAPI, status, exceptions
from flask_jwt_extended import create_access_token,get_jwt,get_jwt_identity, \
                               unset_jwt_cookies, jwt_required, JWTManager

admin = Blueprint('admin', __name__)


# @admin.route('/signup', methods=["POST"])
# def create_account():
#     request_body = request.get_json()
#     validate_signup_req = Validator(admin_signup)
#     if not validate_signup_req.validate(request_body):
#         print(validate_signup_req.errors)
#         return 'Bad Request', status.HTTP_400_BAD_REQUEST
#     org = Admin()
#     org.first_name = request.json.get("first_name", None)
#     org.last_name = request.json.get("last_name", None)
#     org.phone_number = request.json.get("phone_number", None)
#     org.dob = request.json.get("date_of_birth", None)
#     org.sex = request.json.get("gender", None)
#     org.username = request.json.get("username", None)
#     org.email = request.json.get("email", None)
#     org.password = User.hash_password(request.json.get("password", None))
#     org.role = request.json.get('role',None)
#     # Remove These 2 Once email confirmation starts working
#     org.email_verified = True
#     org.is_active = True

#     try:
#         db.session.add(org)
#         db.session.commit()
#     except Exception as err:
#         print('Error Logged : ', err)
#         return "Could not register admin", status.HTTP_400_BAD_REQUEST
#     else:
#         email_conf_token = UserToken.generate_token(
#             'email_confirmation', org.id, 1800)
#         User.generate_smcode(org.id, 180)
#         # try:
#         #     send_confirmation_mail(org.email,
#         #                             url_for('user.email_confirmation',
#         #                                     token=email_conf_token.token, _external=True))
#         # except Exception as err:
#         #     print('Error Logged : ', err)
#         #     return "User Created - Email Sending Failure", status.HTTP_400_BAD_REQUEST
#         # else:
#         return "Admin Created", status.HTTP_201_CREATED

# @admin.route('/confirmation/<string:token>')
# def email_confirmation(token):
#     # if current_user.is_authenticated:
#     #     return redirect(url_for('.dashboard'))

#     token_info = UserToken.query.filter_by(
#         token=token, token_type='email_confirmation').first()

#     if not token_info:
#         return "Token Not Found", status.HTTP_401_UNAUTHORIZED
#     if not token_info.is_valid():
#         return "Token Expired", status.HTTP_401_UNAUTHORIZED
#     token_info.user.email_verified = True
#     token_info.user.is_active = True
    
#     db.session.commit()
#     return "Mail Confirmation Successfull" ,status.HTTP_200_OK


# @admin.route('/login', methods=['POST'])
# def login():
#     request_body = request.get_json()
#     validate_signup_req = Validator(admin_login)
#     if not validate_signup_req.validate(request_body):
#         print(validate_signup_req.errors)
#         return 'Bad Request', status.HTTP_400_BAD_REQUEST
#     username = request.json.get("username", None)
#     password = request.json.get("password", None)
#     org = User.query.filter_by(username=username).first()
#     if org is None or org.check_password(password) is False:
#         return "Either User does not Exist or Incorrect Credentials", status.HTTP_401_UNAUTHORIZED        
#     elif not org.email_verified:
#         return "Email is not verified", status.HTTP_401_UNAUTHORIZED
#     elif not org.valid_sm_code:
#         return "Validate SMS code", status.HTTP_401_UNAUTHORIZED
#     elif not org.is_active:
#         return "Your Account is disabled. Please contact admin", status.HTTP_401_UNAUTHORIZED
#     else:
#         access_token = create_access_token(identity=org.email)
#         data = {
#             "access_token" : access_token,
#             "message" : "Login Successful"
#             }
#         return data, status.HTTP_200_OK

# @admin.route('/dashboard', methods=['GET'])
# @jwt_required()
# def dashboard():
#     data = {
#             "message" : "Welcome To The Dashboard"
#             }
#     return data, status.HTTP_200_OK

    # if request.is_json:
    #     email = request.json['email']
    #     password = request.json['password']
    # else:
    #     email = request.form['email']
    #     password = request.form['password']

    # test = User.query.filter_by(email=email, password=password).first()
    # if test:
    #     access_token = create_access_token(identity=email)
    #     return jsonify(message='Login Successful', access_token=access_token)
    # else:
    #     return jsonify('Bad email or Password'), 401
    
    
    
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