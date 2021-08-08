# project/__init__.py

# standard libraries

# third party libraries 
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
#from flask_migrate import Migrate
from flask_mail import Mail
from flask_wtf.csrf import CSRFProtect
import pymysql

# local application/library specific imports

app = Flask(__name__, instance_relative_config=True)


app.config.from_object('config')
app.config.from_pyfile('config.py')


db = SQLAlchemy(app) #instance of the database

#migrate = Migrate(app, db)

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = ''
login_manager.login_message_category = 'info'
mail = Mail(app)
csrf = CSRFProtect(app)

pymysql.install_as_MySQLdb()

@app.before_first_request
def create_user():
    db.create_all()

#this is added below the app=Flask(__name__) to avoid circular import since routes.py also imports the app variable
from project import routes 