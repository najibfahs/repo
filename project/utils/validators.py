# flask_practice/util/validators.py

from wtforms.validators import ValidationError
from project import app


# custom validator
'''
This class implements a RequiredIf validator.
if the global_logon is checked, then there is no need to fill out the password field.
if the global_logon is not checked, then the password field must be filled out and its
length must be between the min and max
'''
class RequiredIf(object):
    def __init__(self, min=0, max=0, message=None, condition_field=None):
        self.condition_field = condition_field
        self.min = min
        self.max = max
        if not message:
            message = u'Please provide a password for the resource if Global Logon is not used.'
        self.message = message

    def __call__(self, form, field):
        if self.condition_field not in form.data:
            pass
        else:
            checked = form.data.get(self.condition_field) # value of checkbox
            current_value = field.data # value field to which the custom filter is applied to
            if checked:
                print("checked", current_value, checked)
            else:
                print("not checked", current_value, checked, self.min, self.max)
                if not len(current_value) >= self.min or not len(current_value) <= self.max:
                    print('not met')
                    raise ValidationError(self.message)
                else:
                    print('met')

def password_validator(field):
    '''
    enforce password to contain certain characters:
    at least PASSWORD_NUM_LOWERS_MIN uppercase letters
    at least PASSWORD_NUM_UPPERS_MIN lowercase letters
    at least PASSWORD_NUM_DIGITS_MIN digits
    at least PASSWORD_NUM_SYMBOLS_MIN of the following: !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
    
    '''
    # Count lowercase, uppercase, digits and special symbols
    lowers = uppers = digits = symbols = 0
    password = field.data
    password_chars = list(password)
    password_length = len(password)

    for char in password_chars:
        if char.islower(): lowers += 1
        if char.isupper(): uppers += 1
        if char.isdigit(): digits += 1
        if char in app.config['PASSWORD_SPECIAL_SYMBOLS']: symbols += 1

    is_valid = lowers >= app.config['PASSWORD_NUM_LOWERS_MIN'] and \
                uppers >= app.config['PASSWORD_NUM_UPPERS_MIN'] and \
                digits >= app.config['PASSWORD_NUM_DIGITS_MIN'] and \
                symbols >= app.config['PASSWORD_NUM_SYMBOLS_MIN'] and \
                (lowers + uppers + digits + symbols) == password_length

    if not is_valid:
        raise ValidationError('Your password is not compliant with the rules.')