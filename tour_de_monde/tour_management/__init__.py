from flask import Flask
# from flask_api import FlaskAPI, status, exceptions
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_mail import Mail
from tour_management.config import DevelopmentConfig
# from flask_limiter import Limiter
# from flask_limiter.util import get_remote_address
from flask_jwt_extended import JWTManager

db = SQLAlchemy()
migrate = Migrate()
mail = Mail()
jwt = JWTManager()
login_manager = LoginManager()
login_manager.login_message = 'Please login to continue'
login_manager.login_view = 'user.login'
login_manager.login_message_category = 'info'
# limiter = Limiter(key_func=get_remote_address)

def create_app(config=DevelopmentConfig):
    app = Flask(__name__)
    app.config.from_object(config)
    jwt.init_app(app)
    db.init_app(app)
    # limiter.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.session_protection = "strong"
    mail.init_app(app)
    from tour_management.models import Accomodation
    from tour_management.models import AccomodationDetails
    from tour_management.models import User
    from tour_management.models import UserToken
    from tour_management.models import FlightDetails
    from tour_management.models import Flights
    from tour_management.models import Guest
    from tour_management.models import Itinerary
    from tour_management.models import ItineraryType
    from tour_management.models import LocationDetails
    # from tour_management.models.MyOrders import MyOrders
    from tour_management.models import Place
    from tour_management.models import Ticket
    # from iot_security.auth import utils
    # from tour_management.main.routes import main
    # from tour_management.error_handler.routes import handle_error_404, handle_error_500, handle_error_429
    from tour_management.user.routes  import user
    # from iot_security.admin.routes import admin
    # from iot_security.api.routes import api
    # app.register_error_handler(404, handle_error_404)
    # app.register_error_handler(500, handle_error_500)
    # app.register_error_handler(429, handle_error_429)
    # app.register_blueprint(user)
    # login_manager.blueprint_login_views = {
    #     'admin' : '/admin/login',
    #     'user' : '/user/login'
    # }
    # app.register_blueprint(admin,url_prefix='/admin')
    # app.register_blueprint(user, url_prefix='/user')
    app.register_blueprint(user,url_prefix='/api/user')
    
    with app.app_context():
        db.create_all()
        db.session.commit()
    return app