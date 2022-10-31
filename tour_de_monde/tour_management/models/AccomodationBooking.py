from datetime import datetime, timedelta
import math,random
from werkzeug.security import generate_password_hash, check_password_hash
from tour_management.models.utils import rand_pass
from flask_login import UserMixin
from tour_management import db
from tour_management import login_manager

class AccomodationBooking(db.model,UserMixin):
    id = db.Column(db.Integer,primary_key = true)
    accomodation_id = db.Column(db.Integer, db.ForeignKey('accomodation.id'), nullable=False)
    booked_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=True)
    
       
    def __str__(self):
    return 'Accomodation Booking :{}'.format(self.id)


    
    
    
