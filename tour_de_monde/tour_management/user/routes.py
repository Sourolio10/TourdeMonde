from functools import wraps
from lib2to3.pgen2 import token
from urllib import response
from flask import Blueprint, render_template, redirect, url_for, flash, jsonify, request
from flask_login import login_user, current_user, login_required, logout_user
from tour_management.models import User, UserToken
from tour_management.models.utils import rand_pass
from tour_management import db, jwt
from tour_management.utilities.util_helpers import send_confirmation_mail
import json
from cerberus import Validator
from tour_management.schemas.user_apis import user_signup, user_login
from flask_api import FlaskAPI, status, exceptions
from flask_jwt_extended import create_access_token,get_jwt,get_jwt_identity, \
                               unset_jwt_cookies, jwt_required, JWTManager

user = Blueprint('user', __name__)


@user.route('/signup', methods=["POST"])
def create_account():
    request_body = request.get_json()
    validate_signup_req = Validator(user_signup)
    if not validate_signup_req.validate(request_body):
        print(validate_signup_req.errors)
        return 'Bad Request', status.HTTP_400_BAD_REQUEST
    org = User()
    org.first_name = request.json.get("first_name", None)
    org.last_name = request.json.get("last_name", None)
    org.phone_number = request.json.get("phone_number", None)
    org.dob = request.json.get("date_of_birth", None)
    org.sex = request.json.get("gender", None)
    org.username = request.json.get("username", None)
    org.email = request.json.get("email", None)
    org.password = User.hash_password(request.json.get("password", None))
    # Remove These 2 Once email confirmation starts working
    org.email_verified = True
    org.is_active = True

    try:
        db.session.add(org)
        db.session.commit()
    except Exception as err:
        print('Error Logged : ', err)
        return "Could not register user", status.HTTP_400_BAD_REQUEST
    else:
        email_conf_token = UserToken.generate_token(
            'email_confirmation', org.id, 1800)
        User.generate_smcode(org.id, 180)
        # try:
        #     send_confirmation_mail(org.email,
        #                             url_for('user.email_confirmation',
        #                                     token=email_conf_token.token, _external=True))
        # except Exception as err:
        #     print('Error Logged : ', err)
        #     return "User Created - Email Sending Failure", status.HTTP_400_BAD_REQUEST
        # else:
        return "User Created", status.HTTP_201_CREATED

@user.route('/confirmation/<string:token>')
def email_confirmation(token):
    # if current_user.is_authenticated:
    #     return redirect(url_for('.dashboard'))

    token_info = UserToken.query.filter_by(
        token=token, token_type='email_confirmation').first()

    if not token_info:
        return "Token Not Found", status.HTTP_401_UNAUTHORIZED
    if not token_info.is_valid():
        return "Token Expired", status.HTTP_401_UNAUTHORIZED
    token_info.user.email_verified = True
    token_info.user.is_active = True
    
    db.session.commit()
    return "Mail Confirmation Successfull" ,status.HTTP_200_OK


@user.route('/login', methods=['POST'])
def login():
    request_body = request.get_json()
    validate_signup_req = Validator(user_login)
    if not validate_signup_req.validate(request_body):
        print(validate_signup_req.errors)
        return 'Bad Request', status.HTTP_400_BAD_REQUEST
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    org = User.query.filter_by(username=username).first()
    if org is None or org.check_password(password) is False:
        return "Either User does not Exist or Incorrect Credentials", status.HTTP_401_UNAUTHORIZED        
    elif not org.email_verified:
        return "Email is not verified", status.HTTP_401_UNAUTHORIZED
    elif not org.valid_sm_code:
        return "Validate SMS code", status.HTTP_401_UNAUTHORIZED
    elif not org.is_active:
        return "Your Account is disabled. Please contact admin", status.HTTP_401_UNAUTHORIZED
    else:
        access_token = create_access_token(identity=org.email)
        data = {
            "access_token" : access_token,
            "message" : "Login Successful"
            }
        return data, status.HTTP_200_OK

@user.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    data = {
            "message" : "Welcome To The Dashboard"
            }
    return data, status.HTTP_200_OK

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
    


@user.route('/search/<location>/<travel_start_date>/<travel_end_date>/<people>', methods=['GET'])
@jwt_required()
def search():
    
    
    data = {
            "message" : "Welcome To The Search Board"
            }
    return data, status.HTTP_200_OK


@user.route('/check/flights/<current_location>/<travel_start_date>/<travel_end_date>/<people>', methods=['GET'])
@jwt_required()
def check_flights():
    
    
    data = {
            "message" : "Welcome To The Search Board"
            }
    return data, status.HTTP_200_OK


@user.route('/check/accomodation/<location>/<accomodation_name>/<travel_start_date>/<travel_end_date>/<people>', methods=['GET'])
@jwt_required()
def check_accomodation():
    
    
    data = {
            "message" : "Welcome To The Search Board"
            }
    return data, status.HTTP_200_OK


# GET : /search/<location>/<travel_start_date>/<travel_end_date>/<people>
# parameters :
                # location : Pick from Location Details Table
                # Travel Start, Travel End, People : USed to check for avalability of bookings
# operations :
                # First check if location present in our db
                # If yes, accordingly check for flight availability along with no of people - add to json object
                # If returns json object with flight data check for hotels availability for the no of people and add to json object
                # If that returns data then, send to the UI


# GET : /view/locations/<number : 5>
# parameters :
                # Number : To show number of places on the dashboard
# operations :
                # First check if locations present in our db
                # Query all of them
                # Randomly select 2 of them and 3 highly rated ones and send to the user interface


# GET : /view/activities/<number : 5>
# parameters :
                # Number : To show number of places on the dashboard
# operations :
                # First check if activities present in our db
                # Query all of them
                # Randomly select 2 of them and 3 highly rated ones and send to the user interface

# GET : /Dashboard
# @JWT_REQ
# operations :
                # This will be a redirect from login
                # Retrieve user trips and user data
                # Create a split between upcoming trips and completed trips
                # Jsonify it and send to the UI

# GET : /myorders/<order_id>
# GET : /myorders/
# @JWT_REQ
# Parameters :
                # If query is related to a specific order_id
# operations :
                # Query my_orders table along with users primary key
                # In case of order_id along with primamry key pass the order_id too
                # if found add all the available data to json object and send to UI

# POST : /create/order
# @jwt_required (Optional should work without it too - Concept of guest accounts)
# Parameters :
                # location
                # flights
                # hotel
                # activities
                # no of people
                # people object 
                # payment_made == True or payment_made == False (In this case hold the booking for 3 days)
                # * NEED TO DISCUSS THE JSON OBJECT FOR THIS *
# Operations : 
                # Will check all parameters if each of them exist in the data_base or not.
                # Add user booking in the my_orders table and create the itinerary.
                # If payment made then booking_confirmation = True else False in the my_orders Table.
                # Once all bookings are made in the tables and all confirmations done.
                # return True or else send error message.
                # * For NOW IF BOOKING FAILS THEN START ALL OVER AGAIN *