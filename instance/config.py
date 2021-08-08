import os

SECRET_KEY = os.getenv('SECRET_KEY')

# wtforms recapcha keys
RECAPTCHA_PUBLIC_KEY = os.getenv('RECAPTCHA_PUBLIC_KEY') # SITE KEY
RECAPTCHA_PRIVATE_KEY = os.getenv('RECAPTCHA_PRIVATE_KEY') # SECRET KEY

# sqlalchemy uri
#DB_URI = f'mysql://{os.getenv("DB_USERNAME")}:{os.getenv("DB_PASSWORD")}@{os.getenv("DB_HOST")}/{os.getenv("DB_DBNAME")}'
#SQLALCHEMY_DATABASE_URI = DB_URI
SQLALCHEMY_DATABASE_URI = 'sqlite:///sql/repo_db.db'

# email configuration for gmail (outgoing server)
# EMAIL CONFIGURATION (OUTGOING SERVER)
MAIL_SERVER = os.getenv('MAIL_SERVER')
MAIL_PORT = os.getenv('MAIL_PORT')
MAIL_USE_TLS = False
MAIL_USE_SSL = True
MAIL_USERNAME = os.getenv('MAIL_USERNAME')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER')

# configuration for itsdangerous package
SECURITY_PASSWORD_SALT = os.getenv('SECURITY_PASSWORD_SALT')

