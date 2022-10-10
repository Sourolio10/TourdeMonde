from datetime import datetime, timedelta
from email.policy import default
from werkzeug.security import generate_password_hash, check_password_hash
from tour_management.models.utils import rand_pass
from flask_login import UserMixin
from tour_management import db


class Place(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    location = db.Column(db.String(255), nullable = False)
    average_review = db.Column(db.Integer,nullable = True)
    activity_types = db.Column(db.String(255),nullable = True)
    season_visit = db.Column(db.String(255),nullable = True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=True)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def __str__(self):
        return 'Place:{}'.format(self.name)