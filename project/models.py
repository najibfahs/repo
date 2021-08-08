# project/models.py

# standard libraries 
from datetime import datetime

# third party libraries
from flask_login import UserMixin
from itsdangerous import TimedJSONWebSignatureSerializer

# local application/library specific imports
from project import db #imports db variable from __init__.py file
from project import login_manager, app





# This class defines user registration information
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    email_confirmed = db.Column(db.Boolean, nullable=False, default=False)
    password = db.Column(db.String(60), unique=False, nullable=False)
    global_logon = db.Column(db.String(46), unique=False, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow) #note that now is without the ()

    # add the column owner to Account class (account table) and point it to the User class (user object)
    accounts = db.relationship('Account', backref='owner', lazy='dynamic')

    def __repr__(self):
        return f'User({self.username}, {self.email}, {self.password}, {self.date_created})'

    # generating the token based on user id for password reset feature
    def get_token(self, expiry_sec=1800):
        s = TimedJSONWebSignatureSerializer(secret_key=app.config['SECRET_KEY'], expires_in=expiry_sec)
        return s.dumps({'user_id':self.id}).decode('utf-8')
    
    # verify the user token for password reset feature
    @staticmethod
    def verify_token(token):
        s = TimedJSONWebSignatureSerializer(secret_key=app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
            return User.query.get(user_id)
        except:
            return None






#This class defines the structure of the accounts table
class Account(db.Model):
    id = db.Column(name="id", type_=db.Integer, primary_key=True)
    resourcename = db.Column(db.String(50), unique=False, nullable=False)
    username = db.Column(db.String(50), unique=False, nullable=False)
    password = db.Column(db.String(30), nullable=False)
    global_logon = db.Column(db.Boolean, nullable=True, default=False)
    link = db.Column(db.String(100), nullable=True)
    additional_info = db.Column(db.String(1000), nullable=True)
    add_date = db.Column(db.DateTime, default=datetime.now) #note that the method now is without the ()
    lastupdate = db.Column(db.DateTime, default=datetime.now)

    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'Account({self.resourcename}, {self.username}, {self.link}, {self.password}, {self.add_date})'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))