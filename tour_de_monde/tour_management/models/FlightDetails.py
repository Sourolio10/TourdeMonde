from datetime import datetime, timedelta
import math,random
from werkzeug.security import generate_password_hash, check_password_hash
from tour_management.models.utils import rand_pass
from flask_login import UserMixin
from tour_management import db
from tour_management import login_manager


class FlightDetails(db.Model, UserMixin):

    id = db.Column(db.Integer, primary_key= True)
    flight_number = db.Column(db.Integer,nullable=False)
    arrival_time = db.Column(db.Integer,nullable=False)
    depart_tim = db.Column(db.Integer,nullable=False)
    number_of_seats = db.Column(db.Integer,default=0)
    source = db.Column(db.String(255),nullable=False)
    destination = db.Column(db.String(255),nullable=False)
    vacant_seats = db.Column(db.Integer,default=0)
    
    flights_id = db.Column(db.Integer, db.ForeignKey('flights.id'), nullable=False)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=True)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def __str__(self):
        return 'Flight Details:{}'.format(self.id)