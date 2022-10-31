from datetime import datetime, timedelta
import math,random
from werkzeug.security import generate_password_hash, check_password_hash
from tour_management.models.utils import rand_pass
from flask_login import UserMixin
from tour_management import db
from tour_management import login_manager


class Flights(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    flight_name = db.Column(db.String(255),nullable=False)
    international = db.Column(db.Boolean, nullable = True, default=True)
    # Add discount code as new table eventually
    discount_code = db.Column(db.String(255),nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=True)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

    flight_details_id = db.relationship('FlightDetails',backref='flights',lazy=True)

    def __str__(self):
        return 'Flights:{}'.format(self.id)