from datetime import datetime, timedelta
import math,random
from werkzeug.security import generate_password_hash, check_password_hash
from tour_management.models.utils import rand_pass
from flask_login import UserMixin
from tour_management import db
from tour_management import login_manager

class AccomodationDetails(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key= True)
    accomodation_id = db.Column(db.Integer, db.ForeignKey('accomodation.id'), nullable=False)
    
    # Need to add default Arguement
    room_capacity = db.Column(db.Integer, default=0)
    
    rooms_availble = db.Column(db.Integer, default=0)
    min_price = db.Column(db.Integer, default=0)
    max_price = db.Column(db.Integer, default=0)
    description = db.Column(db.String(255), nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=True)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def __str__(self):
        return 'Accomodation Details :{}'.format(self.id)