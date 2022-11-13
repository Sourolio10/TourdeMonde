from datetime import datetime, timedelta
from email.policy import default
import math,random
from werkzeug.security import generate_password_hash, check_password_hash
from tour_management.models.utils import rand_pass
from flask_login import UserMixin
from tour_management import db
# from tour_management import login_manager

class Guest(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    phone_number = db.Column(db.String(255), nullable=False)
    sex = db.Column(db.String(255),nullable = True)
    is_active = db.Column(db.Boolean, default=False, nullable=False)
    current_location = db.Column(db.String(255),nullable = False)
    status = db.Column(db.Boolean,default = False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    
    # -- Backrefrences for other tables
    
    def __str__(self):
        return 'Guest : {}'.format(self.name)
    
    # Check validity of password
    def is_valid(self):
        valid_till = self.sm_code_sent_at + timedelta(seconds=self.valid_sm_sec)
        return valid_till > datetime.utcnow()
