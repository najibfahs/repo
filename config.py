
TESTING = False # set to True to bypass the Recaptcha validation field

SQLALCHEMY_TRACK_MODIFICATIONS = False

# When serving files, set the cache control max age to this number of seconds.
SEND_FILE_MAX_AGE_DEFAULT = 0


######################### CUSTOM SETTINGS #########################
EMAIL_TOKEN_EXPIRATION = 1800 # in seconds
CONFIRMATION_LINK_INVALID_MSG = 'The confirmation link is invalid or has expired.'

# password settings
PASSWORD_NUM_LOWERS_MIN = 2 # minimum # of lowercase letter in the password: 'abcdefghijklmnopqrstuvwxyz'
PASSWORD_NUM_UPPERS_MIN = 2 # minimum # of uppercase letter in the password: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
PASSWORD_NUM_DIGITS_MIN = 2 # minimum # of digits in the password: '0123456789'
PASSWORD_NUM_SYMBOLS_MIN = 1 # minimum # of special symbols in password: !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
PASSWORD_SPECIAL_SYMBOLS = '!#$%&()*+,-./:;<=>?@[\]^_{|}~'
PASSWORD_LENGTH_MIN = 8
PASSWORD_LENGTH_MAX = 30