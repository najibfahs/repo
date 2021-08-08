# project/forms.py

# standard libraries 
import string

# third party libraries 
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, SubmitField, BooleanField, HiddenField, PasswordField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, InputRequired, Email, EqualTo, ValidationError, Regexp 
from flask_login import current_user

# local application/library specific imports
from project.models import User, Account
from project import bcrypt, app
from project.utils.validators import RequiredIf, password_validator      


# this is the class for the registration form
class RegistrationForm (FlaskForm):
    # this class will inherit from FlaskForm class
    username = StringField(
                    label='User name', 
                    description='Enter your user name',
                    validators=[DataRequired(message='Enter a valid username.'), 
                                Length(min=2, max=20), 
                                Regexp('^[a-zA-Z0-9]{2,20}$', message='user name must be alphanumerical.')
                    ]
                )
    email = StringField(label='Email', 
                        description='Enter your email',
                        validators=[DataRequired(message='Enter a valid email.'), Email()])
    password = PasswordField(label='Password', 
                            description = 'Enter your password',  
                            validators = [DataRequired(message='Please provide a password!'), Length(min=app.config['PASSWORD_LENGTH_MIN'], max=app.config['PASSWORD_LENGTH_MAX'])])
    confirm_password = PasswordField(label='Confirm Password', 
                            description = 'Enter your password again', 
                            validators = [DataRequired(message='Please enter the correct password!'), EqualTo('password', message='The passwords do not match.'), Length(min=8, max=30)])
    global_logon = PasswordField(label='AT&T Global Logon', 
                            description = 'Enter your AT&T Global Logon password or paraphrase (8-46 characters)',  
                            validators = [DataRequired(message='Please provide your AT&T Global Logon!'), Length(min=8, max=46)])
    
    recaptcha = RecaptchaField()
    submit = SubmitField(label='Sign Up')

    # inline custom validator
    def validate_username(self, username):  # the argument username is the field name
        user = User.query.filter_by(username=username.data).first()
        if user:
            # if a user exist with this username, then throw an exception with a custom message
            # msg sent to the form in case username is already in use.
            raise ValidationError('This username is already taken. Please try another username.') 

    # inline custom validator
    def validate_email(self, email):  # the argument username is the field name
        user = User.query.filter_by(email=email.data).first()
        if user:
            # if a user exist with this email, then throw an exception with a custom message
            # msg sent to the form in case the email is already in use.
            raise ValidationError('This email is already taken. Please try another email.')

    def validate_password(self, password):
        password_validator(password)

            

# this is the class for the login form
class LoginForm (FlaskForm):
    # this class will inherit from FlaskForm class
    email = StringField(label='Email', 
                        description='Enter your email',
                        validators=[DataRequired(message='Please enter your email!'), Email()])
    password = PasswordField(label='Password', 
                            description = 'Enter your password',  
                            validators = [DataRequired(message='Please enter your password!'), Length(min=app.config['PASSWORD_LENGTH_MIN'], max=app.config['PASSWORD_LENGTH_MAX'])])
    remember = BooleanField(label='Remember me', )
    submit = SubmitField(label='Login')


# this is the class for adding an account to the repository
class AddForm (FlaskForm):
    # this class will inherit from FlaskForm class
    resourcename = StringField(label='Resource Name', 
                        description='Enter the resource name',
                        validators=[DataRequired(), Length(min=1, max=50)])
    username = StringField(label='User Name', 
                        description='Enter your username',
                        validators=[DataRequired(), Length(min=3, max=50)])
    
    global_logon = BooleanField(label='Use Global Logon password?', default=None)
    password = PasswordField(label='Password', 
                        description='Enter your password',
                        validators=[RequiredIf(min=5, max=30, condition_field='global_logon')])

    resourcelink = TextAreaField(label='Resource Link', 
                        description='Enter 1 or more links for the resource',
                        validators=[Length(min=0, max=100)])
    additionalinfo = TextAreaField(label='Additional Info', 
                        description='Additional info pertaining to the resource',
                        validators=[Length(min=0, max=1000)])
    submit = SubmitField(label='Add new account')

    # inline custom validator
    def validate_resourcename(self, resourcename):  # the argument resourcename is the field name
        resourcename = Account.query.filter_by(owner_id=current_user.id).filter_by(resourcename=resourcename.data).first()
        if resourcename:
            # if the resourcename exist for this owner, then throw an exception with a custom message
            # msg sent to the form in case resourcename is already in use for the current user.
            raise ValidationError('This resourcename is already in your repo. Please try another resourcename.')


class UpdateForm (FlaskForm):
    # this class will inherit from FlaskForm class
    resourcename = StringField(label='Resource Name', 
                        description='Enter the resource name',
                        validators=[DataRequired(), Length(min=1, max=50)])
    username = StringField(label='User Name', 
                        description='Enter your username',
                        validators=[DataRequired(), Length(min=3, max=50)])
    
                        
    global_logon = BooleanField(label='Use Global Logon password?', default=None)
    password = PasswordField(label='Password',  
                        description='Enter your password',
                        validators=[RequiredIf(min=5, max=30, condition_field='global_logon')])

    resourcelink = TextAreaField(label='Resource Link', 
                        description='Enter 1 or more links for the resource',
                        validators=[Length(min=0, max=100)])
    additionalinfo = TextAreaField(label='Additional Info', 
                        description='Additional info pertaining to the resource',
                        validators=[Length(min=0, max=1000)])
    submit = SubmitField(label='Update user info')


class Delete1Form (FlaskForm):
    # this class will inherit from FlaskForm class
    resourcename = StringField(label='Resource Name', 
                        description='Enter the resource name',
                        validators=[DataRequired(), Length(min=1, max=50)])
    submit = SubmitField(label='Delete record')

class Delete2Form (FlaskForm):
    # this class will inherit from FlaskForm class
    resourcelist = SelectField(label='Select a resource for deletion', 
                        choices=[])
    submit = SubmitField(label='Delete record')

class GetForm (FlaskForm):
    # this class will inherit from FlaskForm class
    resourcename = StringField(label='Resource Name', 
                        description='Enter the resource name',
                        validators=[DataRequired(), Length(min=1, max=50)])
    update_option = BooleanField(label='Update option')
    submit = SubmitField(label='Get user record')


class UpdatePassword (FlaskForm):
    # this class will inherit from FlaskForm class
    current_password = PasswordField(label='Current Password', 
                            description = 'Enter your current password',  
                            validators = [DataRequired(message='Please enter your current password!'), Length(min=8, max=30)])
    new_password = PasswordField(label='New Password', 
                            description = 'Enter your new password',  
                            validators = [DataRequired(message='Please enter your new password!'), Length(min=8, max=30)])
    confirm_new_password = PasswordField(label='Confirm New Password', 
                            description = 'Enter your new password again', 
                            validators = [DataRequired(message='Please re-enter your new password!'), EqualTo('new_password', message='The passwords do not match.'), Length(min=8, max=30)])
    
    submit = SubmitField(label='Save New Password')

    # inline custom validator
    def validate_current_password(self, current_password):  # the argument current_password is the field name 
        if not bcrypt.check_password_hash(current_user.password, current_password.data):
            # if the current password does not match that of the active user, throw an exception
            # msg sent to the form in case current password is not correct.
            raise ValidationError('Your current password is incorrect. Please provide your current password.') 

             
    def validate_new_password(self, new_password):
        if bcrypt.check_password_hash(current_user.password, new_password.data):
            # if the new password matches the current one, then invalidate the form
            raise ValidationError('Your new password cannot be the same as the current one.')
        else:
            password_validator(new_password)



class UpdateGlobalLogon (FlaskForm):
    # this class will inherit from FlaskForm class
    new_global_logon = PasswordField(label='New Global Logon', 
                        description = 'Enter your new Global Logon',  
                        validators = [DataRequired(message='Please enter your new Global Logon!'), Length(min=8, max=46)])
    
    submit = SubmitField(label='Save New Global Logon')

    # inline custom validator
    def validate_new_global_logon(self, new_global_logon):  # the argument new_global_logon is the field name 
        if current_user.global_logon == new_global_logon.data:
            # if the current global logon matches the new one, throw an exception
            # msg sent to the form in case there is a match.
            raise ValidationError('Your new Global Logon matches the current one. Please provide a new Global Logon.') 

class UpdateEmail (FlaskForm):
    # this class will inherit from FlaskForm class
    new_email = StringField(label='New Email', 
                        description = 'Enter your new Email',  
                        validators = [DataRequired(message='Please enter your new email!'), Email()])
    
    submit = SubmitField(label='Update email')

    # inline custom validator
    def validate_new_email(self, new_email):  # the argument new_email is the field name 
        if current_user.email == new_email.data:
            # if the current email matches the new one, throw an exception
            # msg sent to the form in case there is a match.
            raise ValidationError('Your new email matches the current one. Please provide a new email.')

class RequestResetForm (FlaskForm):
    email = StringField(label='Email', 
                        description='Enter your email',
                        validators=[DataRequired(message='Enter a valid email.'), Email()])

    submit = SubmitField(label='Request Password Reset')

    # validation of user email using inline custom validator
    def validate_email(self, email):  # the argument email is the field name
        user = User.query.filter_by(email=email.data).first()
        print(user)
        if not user:
            # if a user does not exist with this email, then throw an exception with a custom message
            # msg sent to the form in case the email is already in use.
            raise ValidationError('There is no account with that email. You must register first.')

class ResetPasswordForm (FlaskForm):
    password = PasswordField(label='Password', 
                            description = 'Enter your new password',  
                            validators = [DataRequired(message='Please provide a password!'), 
                                            Length(min=8, max=60),
                                        ])
    confirm_password = PasswordField(label='Confirm Password', 
                            description = 'Enter your password again', 
                            validators = [DataRequired(message='Please enter the correct password!'), EqualTo('password', message='The passwords do not match.')])
    submit = SubmitField(label='Reset Password')

    def validate_password(self, password):
        password_validator(password)
