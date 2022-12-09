from functools import wraps
from lib2to3.pgen2 import token
from urllib import response
from flask import Blueprint, render_template, redirect, url_for, flash, jsonify, request
from flask_login import login_user, current_user, login_required, logout_user
from tour_management.models import (User, 
                                    UserToken,
                                    Myorders, 
                                    Location, 
                                    Place, 
                                    Myorderstemp,
                                    Accomodation,
                                    Flights,
                                    Flightdetails,
                                    Locationdetails,
                                    Accomodationdetails,
                                    Ticket,
                                    Flightbookingtemp)

from tour_management.models.utils import rand_pass
from tour_management import db, jwt
from tour_management.utilities.util_helpers import send_confirmation_mail
import json
import random
from cerberus import Validator
from tour_management.schemas.user_apis import user_signup, user_login
from flask_api import FlaskAPI, status, exceptions
from tour_management.user.forms import (SignupForm,
                                        LoginForm,
                                        ValidateotpForm,
                                        ResendValidateotpForm,
                                        ResendEmailConfirmationForm,
                                        ResetPasswordRequestForm,
                                        ResetPasswordForm,
                                        DashboardForm,
                                        HotelBookingForm,
                                        FlightBookingForm,
                                        MyordersForm)

user = Blueprint('user', __name__)



@user.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        flash('You are aleady logged in.', 'info')
        return redirect(url_for('.dashboard'))
    signup_form = SignupForm()
    print("Entered Signup")
    if signup_form.validate_on_submit():
        print("Entered Signup Now")
        org = User()
        print("User Object Created")
        org.first_name = signup_form.first_name.data
        org.last_name = signup_form.last_name.data
        org.phone_number = signup_form.phone_number.data
        org.dob = signup_form.dob.data
        org.sex = signup_form.sex.data
        org.username = signup_form.username.data.lower()
        org.email = signup_form.email.data
        org.password = User.hash_password(signup_form.password.data)
        # Remove These 2 Once email confirmation starts working
        org.email_verified = True
        org.is_active = True
        print("Accepted Data")
        try :
            db.session.add(org)
            db.session.commit()
        except Exception as err:
            print ('Error Logged : ', err)
            flash('Signup Failed', 'danger')
            return redirect(url_for('user.signup'))
        else:
            email_conf_token = UserToken.generate_token(
                'email_confirmation', org.id, 1800)
            User.generate_smcode(org.id, 180)
            # try:
            #     send_confirmation_mail(org.email,
            #                        url_for('user.email_confirmation',
            #                                token=email_conf_token.token, _external=True))
            # except Exception as err:
            #     print ('Error Logged : ', err)
            #     flash('Email sending failed', 'danger')
            #     return redirect(url_for('user.signup'))
            # else:
            return redirect(url_for('user.validate_OTP'))

    return render_template('user/signup.html', form=signup_form)


@user.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash('You are aleady logged in.', 'info')
        return redirect(url_for('.dashboard'))
    login_form = LoginForm()
    if login_form.validate_on_submit():
        username = login_form.username.data.lower()
        password = login_form.password.data
        org = User.query.filter_by(username=username).first()
        if org is None or org.check_password(password) is False:
            flash('Incorrect Username or Password', 'danger')
        elif not org.email_verified:
            flash('Your email is not verified Please verify email first', 'danger')
            return redirect(url_for('user.send_email_confirmation'))
        elif not org.valid_sm_code:
            flash('Your OTP is not verified Please verify OTP first', 'danger')
            return redirect(url_for('user.resend_validate_OTP'))
        elif not org.is_active:
            flash('Your Account is disabled. Please contact admin')
        else:
            login_user(org, remember=True)
            flash('You have logged in successfully', 'info')
            
            return redirect(url_for('user.dashboard'))
    return render_template('user/login.html', form=login_form)


# Validate users OTP
@user.route('/validate_otp', methods=['GET', 'POST'])
def validate_OTP():
    if current_user.is_authenticated:
        flash('You are aleady logged in.', 'info')
        return redirect(url_for('user.dashboard'))
    otp_form = ValidateotpForm()
    if otp_form.validate_on_submit():
        valid_sm = User.query.filter_by(sm_code=otp_form.otp.data).first()

        if valid_sm is None:
            flash('Invalid OTP', 'danger')
            return redirect(url_for('user.login'))

        if not valid_sm.is_valid():
            flash('OTP is expired. Please get new OTP', 'danger')
            return redirect('.login')
        else:
            valid_sm.valid_sm_code = True
            db.session.commit()
            flash('OTP verified', 'success')
            flash('User signed up successfully', 'success')
            return redirect(url_for('user.login'))
    return render_template('user/validate_otp.html', form=otp_form)



# Resend OTP incase of expiry
@user.route('/resend_validate_otp', methods=['GET', 'POST'])
def resend_validate_OTP():
    if current_user.is_authenticated:
        flash('You are aleady logged in.', 'info')
        return redirect(url_for('.dashboard'))
    otp_form = ResendValidateotpForm()
    if otp_form.validate_on_submit():
        valid_smcode = User.query.filter_by(phone_number=otp_form.phone.data).first()
    
        if valid_smcode is None:
            flash('Mobile Number Not Registered', 'danger')
            return redirect(url_for('.signup'))
        elif valid_smcode.valid_sm_code:
            flash('OTP Already Validated', 'danger')
            return redirect(url_for('.login'))
        else:
            User.generate_smcode(valid_smcode.id, 1800)
            flash('OTP Sent', 'success')
            return redirect(url_for('.validate_OTP'))
    return render_template('user/resend_validate_otp.html', form=otp_form)
    

@user.route('/' , methods=['GET', 'POST'])
def index():
    # dashboard_form = DashboardForm()
    return render_template('user/index.html')


@user.route('/dashboard' , methods=['GET', 'POST'])
@login_required
def dashboard():
    form = DashboardForm()
    if form.validate_on_submit():
        source = form.source.data.lower()
        destination = form.destination.data.lower()
        no_of_rooms = form.no_of_rooms.data
        adults = form.adults.data
        children = form.children.data
        inputCheckIn = form.inputCheckIn.data
        inputCheckOut = form.inputCheckOut.data
        international = form.international.data
        booking_type = False
        my_orders_temp = Myorderstemp()
        print(current_user.id)
        my_orders_temp.user_id = current_user.id
        my_orders_temp.international = international
        my_orders_temp.start_date = inputCheckIn
        my_orders_temp.end_date = inputCheckOut
        my_orders_temp.source = source
        my_orders_temp.destination = destination
        my_orders_temp.individual = booking_type
        db.session.commit()
        total_no_people = adults + children
        # Add booking Id, No of People, No of rooms to every request              
        flash('Please Select your FLight info', 'info')
        
        print(source, destination, no_of_rooms, adults, children, inputCheckIn, inputCheckOut, international)
        return redirect(url_for('user.dashboard'))
    return render_template('user/dashboard.html', form=form)

@user.route('/booking/flights/start/<string:booking_id>/<string:no_of_people>/<string:no_of_rooms>' , methods=['GET', 'POST'])
@login_required
def book_flights(booking_id, no_of_people, no_of_rooms):
    my_orders_temp = Myorderstemp.query.filter_by(id=booking_id).first()
    if my_orders_temp is None or my_orders_temp == []:
        flash('Booking Failed. Please start again', 'danger')
        return redirect(url_for('user.dashboard'))
    # Invoice.query.filter(Invoice.invoicedate >= date.today())
    source = my_orders_temp.source
    destination = my_orders_temp.destination
    start_date = my_orders_temp.start_date

    # flights_data = Flightdetails.query.filter_by(source=source, destination=destination, departure_date_time=start_date, ).all()
    # if flights_data is None or flights_data == []:
        
    #     Myorderstemp.query.filter_by(id = booking_id).delete()
    return "Wait. Work in Progress"

@user.route('/hotel_booking' , methods=['GET', 'POST'])
@login_required
def hotel_booking():
    hotel_booking_form = HotelBookingForm()
    return render_template('user/hotel_booking.html', form=hotel_booking_form)

@user.route('/my_orders' , methods=['GET', 'POST'])
@login_required
def my_orders():
    my_orders_form = MyordersForm()
    return render_template('user/my_orders.html', form=my_orders_form)

@user.route('/flight_booking' , methods=['GET', 'POST'])
@login_required
def flight_booking():

    items = None
    form = FlightBookingForm()
    if form.validate_on_submit():
        print("E")
        no_of_rooms = form.no_of_rooms.data

        source = form.source.data.lower()
        destination = form.destination.data.lower()
        number_of_people = form.adults.data + form.children.data
        departure_date = form.inputCheckIn.data
        arrival_date = form.inputCheckOut.data
        cabin_class = form.cabin_class.data
        print("\n\n\n\n\n\n\n\n\n\n",cabin_class)
        flight_details = (db.session.query(Flightdetails, Ticket)
                .join(Flightdetails, Flightdetails.id == Ticket.flights_id)
                .filter(Flightdetails.source == source,
                            Flightdetails.destination == destination,
                            Flightdetails.departure_date == departure_date,
                            Ticket.type == "economy")
                .all())
        
        print('\n\n\n\n\n\n\n\n\n', flight_details)
        items = []
        for flight_det, tickets in flight_details:
            if flight_det.vacant_seats < number_of_people:
                continue
            temp_dict = {}
            temp_dict['flight_number'] = flight_det.flight_number
            temp_dict['source'] = flight_det.source
            temp_dict['destination'] = flight_det.destination
            temp_dict['no_of_people'] = str(number_of_people)
            temp_dict['departure_date'] = str(flight_det.departure_date)
            temp_dict['departure_time'] = str(flight_det.departure_time)
            temp_dict['arrival_date'] = str(flight_det.arrival_date)
            temp_dict['arrival_time'] = str(flight_det.arrival_time)
            temp_dict['cost'] = str(random.randrange(tickets.min_cost,tickets.max_cost))
            # temp_dict = json.dumps(temp_dict)
            print(temp_dict)
            items.append(temp_dict)
        print(items)
        # items = json.dumps(items)
        # items = json.loads(items)
        print("ASD",items)
        return render_template('user/flight_booking.html', form=form, items = items)
    return render_template('user/flight_booking.html', form=form, items = items)

@user.route('/flight_booking/confim/<string:flight_number>/<string:source>/<string:destination>/<string:no_of_people>/<string:departure_date>/<string:departure_time>/<string:arrival_date>/<string:arrival_time>/<string:cost>' , methods=['GET', 'POST'])
@login_required
def flight_booking_confirm(flight_number, source, destination, no_of_people, departure_date, departure_time, arrival_date, arrival_time, cost):
    flight_number = flight_number
    source = source
    destination = destination
    no_of_people = no_of_people
    departure_date = departure_date
    departure_time = departure_time
    arrival_date = arrival_date
    arrival_time = arrival_time
    cost = cost
    user_id = current_user.id
    # Booking Temp Orders
    temp_orders = Myorderstemp()
    temp_orders.user_id = user_id
    #change later
    temp_orders.international = True
    temp_orders.cost = cost
    temp_orders.start_date = departure_date
    temp_orders.end_date = arrival_date
    temp_orders.source = source
    temp_orders.destination = destination
    temp_orders.individual = True
    temp_orders.booking_complete = False
    db.session.commit()
    temp_orders = Myorderstemp.query.filter_by(user_id = user_id, international = True, cost = cost, start_date = departure_date, end_date=arrival_date, source=source, destination=destination, booking_complete=False).first()
    flight_details = Flightdetails.query.filter_by(flight_number=flight_number).first()
    flight_booking_temp = Flightbookingtemp()
    flight_booking_temp.flight_details_id = flight_details.id
    flight_booking_temp.cost = cost
    flight_booking_temp.no_of_people = no_of_people
    flight_booking_temp.my_orders_id = temp_orders.id
    db.session.commit()
    return redirect(url_for('user.flightpassengerinfo', booking_id=temp_orders.id, _external=True))

@user.route('/flight_booking/passenger/<string:booking_id>' , methods=['GET', 'POST'])
@login_required
def flightpassengerinfo(booking_id):

    return 'Taking Flight Passenger Info'

@user.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    return render_template('user/profile.html', org=current_user)

# @user.route('/flight-booking' , methods=['GET', 'POST'])
# @login_required
# def flight_booking():
#     flight_booking_form = DashboardForm()
#     return render_template('user/flight_booking.html', form=flight_booking_form)

# @user.route('/hotel-booking' , methods=['GET', 'POST'])
# @login_required
# def hotel_booking():
#     hotel_booking_form = DashboardForm()
#     return render_template('user/hotel_booking.html', form=hotel_booking_form)


@user.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You are logged out successfully.', 'info')
    return redirect(url_for('user.login'))

# Confirm whether users email is verified or not
@user.route('/confirmation/<string:token>')
def email_confirmation(token):
    if current_user.is_authenticated:
        return redirect(url_for('.dashboard'))

    token_info = UserToken.query.filter_by(
        token=token, token_type='email_confirmation').first()

    if not token_info:
        flash('Invalid email confirmation token', 'danger')
        return redirect(url_for('.login'))
    if not token_info.is_valid():
        flash('Token is expired. Please get new email confirmation link', 'danger')
        return redirect('.login')
    token_info.user.email_verified = True
    token_info.user.is_active = True
    
    db.session.commit()
    flash('Email has been verified', 'success')
    return redirect(url_for('.login'))


# Send email to user for verification
@user.route('/resend-confirmation', methods=['GET', 'POST'])
def send_email_confirmation():
    if current_user.is_authenticated:
        return redirect(url_for('.dashboard'))

    form = ResendEmailConfirmationForm()
    if form.validate_on_submit():
        email = form.email.data
        org = User.query.filter_by(email=email).first()
        if not org:
            flash('Email address is not registered with us. Please signup', 'info')
            return redirect(url_for('.signup'))

        if org.email_verified:
            flash('Email address is already verified Please login', 'info')
            return redirect(url_for('.login'))

        email_conf_token = UserToken.generate_token(
            'email_confirmation', org.id, 1800)
        send_confirmation_mail(org.email,
                               url_for('.email_confirmation',
                                       token=email_conf_token.token, _external=True))
        flash('The email confirmation link has been sent to your email. Please check your email', 'info')
        return redirect(url_for('.login'))
    return render_template('user/resend_email_confirmation.html', form=form)


# Reset password incase forgotten
@user.route('/reset-password-request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('.dashboard'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        email = form.email.data
        org = User.query.filter_by(email=email).first()
        if not org:
            flash('Email address is not registered with us. Please signup', 'info')
            return redirect(url_for('.signup'))
        if not org.email_verified:
            flash('Email is not verified. Please verify email first', 'danger')
            return redirect(url_for('.login'))
        if not org.is_active:
            flash('Your account has been deactivated Please contact admin', 'info')
            return redirect(url_for('.login'))
        reset_password_token = UserToken.generate_token(
            'reset_password', org.id, 1800)
        # try:
        #     send_reset_password_mail(org.email,
        #                          url_for('.reset_password',
        #                                  token=reset_password_token.token, _external=True))
        # except Exception as err:
        #     print ('Error Logged : ', err)
        #     flash('Email sending failed', 'danger')
        #     return redirect(url_for('user.login')) 
        # else:
        flash('Reset password link has been sent to your email address', 'info')
        return redirect(url_for('.login'))
    return render_template('user/reset_password_request.html', form=form)


# Reset password
@user.route('/reset-password/<string:token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('.dashboard'))

    token_info = UserToken.query.filter_by(
        token=token, token_type='reset_password').first()

    if not token_info:
        flash('Invalid Reset password token', 'danger')
        return redirect(url_for('.login'))
    if not token_info.is_valid():
        flash('Token is expired. Please get new email confirmation link', 'danger')
        return redirect('.login')
    form = ResetPasswordForm()
    if form.validate_on_submit():
        password = form.password.data
        token_info.user.password = User.hash_password(password)
        db.session.commit()
        flash('Your password has been updated. Please login with new password', 'success')
        return redirect(url_for('.login'))
    return render_template('user/reset_password.html', form=form)


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