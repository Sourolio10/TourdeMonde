import email
from functools import wraps
from lib2to3.pgen2 import token
import re
from urllib import response
from flask import Blueprint, render_template, redirect, url_for, flash, jsonify, request
from flask_login import login_user, current_user, login_required, logout_user
from tour_management.models.Accomodation import Accomodation
from tour_management.models.AccomodationDetails import AccomodationDetails
from tour_management.models.Admin import Admin
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
    
    
    
@admin.route('/create/accomodation' ,methods=['POST'])
def create_accomodation():
    request_body = request.get_json()
    tempAccomodation = Accomodation()
    tempAccomodation.hotel_name = request.json.get("hotel_name",None)
    tempAccomodation.location = request.json.get("location",None)
    tempAccomodation.discount_code = request.json.get("discount_code")
    tempAccomodation.description = request.json.get("description",None)
    tempAccomodation.email = request.json.get("email",None)
    
    db.session.add(tempAccomodation)
    db.session.commit()

    temp_Acc_Id = Accomodation.query.filter_by(email=tempAccomodation.email).first().get(id)
    
    tempAccDetails = AccomodationDetails()
    tempAccDetails.accomodation_id = temp_Acc_Id
    tempAccDetails.description = request.json.get("description",None)
    tempAccDetails.room_capacity = request.json.get("room_capactiy",None)
    tempAccDetails.min_price = request.json.get("min_price",None)
    tempAccDetails.max_price = request.json.get("max_price",None)
    tempAccDetails.rooms_availble = request.json.get("rooms_availble",None)
    
    data = {
            "message" : "Added Accomodation Data"
            }
    return data, status.HTTP_200_OK


    db.session.add(tempAccDetails)
    db.session.commit()
    


    #Take a hotel name, location, discount code and description 
    #Accomodation detial, will take room capacity, rooms availble, min and max prce and a description 