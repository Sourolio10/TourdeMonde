from datetime import datetime, timedelta
import math,random
from werkzeug.security import generate_password_hash, check_password_hash
from tour_management.models.utils import rand_pass
from flask_login import UserMixin
from tour_management import db
from tour_management import login_manager


class Accomodation(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    hotel_name = db.Column(db.String(255), nullable=False)
    location = db.Column(db.String(255), nullable=False)
    discount_code = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable = True)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def __str__(self):
        return 'Accomodation :{}'.format(self.id)

    # hotel_name = db.column(db.String(255),nullable=False)
    # location = db.Column(db.String(255), nullable=False)
    # discount_code = db.column(db.String(255),nullable=False)
    # description = db.column(db.String(255),nullable=False)
    # created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=True)
    # updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

    # def __str__(self):
    #     return 'Accomodation :{}'.format(self.hotel_name)