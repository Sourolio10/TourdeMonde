from functools import wraps
from lib2to3.pgen2 import token
from urllib import response
from flask import Blueprint, render_template, redirect, url_for, flash, jsonify, request
from flask_login import login_user, current_user, login_required, logout_user
from tour_management.models import User, UserToken
from tour_management.models.Accomodation import Accomodation
from tour_management.models.utils import rand_pass
from tour_management import db, jwt
from tour_management.utilities.util_helpers import send_confirmation_mail
import json
from cerberus import Validator
from tour_management.schemas.user_apis import user_signup, user_login
from flask_api import FlaskAPI, status, exceptions
from flask_jwt_extended import create_access_token,get_jwt,get_jwt_identity, \
                               unset_jwt_cookies, jwt_required, JWTManager

accomodation = Blueprint('accomodation', __name__)


@accomodation.route('/signup', methods=["POST"])
def create_account():
    request_body = request.get_json()
    validate_signup_req = Validator(user_signup)
    if not validate_signup_req.validate(request_body):
        print(validate_signup_req.errors)
        return 'Bad Request', status.HTTP_400_BAD_REQUEST
    org = Accomodation()
    org.id = request.json.get("id", None)
    org.hotel_name = request.json.get("hotel_name", None)
    org.location = request.json.get("location", None)
    org.discount_code = request.json.get("discount_code", None)
    org.description = request.json.get("description", None)
    org.created_at = request.json.get("created_at", None)
    org.updated_at = request.json.get("updated_at", None)


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




@accomodation.route('/dashboard', methods=['GET'])
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