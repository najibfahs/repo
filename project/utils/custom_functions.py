# project/custom_functions.py

# standard libraries 
import sys
import os
import re
from datetime import datetime
from functools import wraps

# third party libraries 
from flask import request, session, redirect, url_for
from flask import flash
from sqlalchemy import exc
from werkzeug.utils import secure_filename
import pandas as pd, numpy as np
from flask_login import current_user
from flask_mail import Message
from itsdangerous.url_safe import URLSafeTimedSerializer, URLSafeSerializer

# local application/library specific imports
from project.models import Account
from project import db
from project import app
from project import mail

ALLOWED_EXTENSIONS = {'csv'}
UPLOAD_FOLDER = os.path.join(app.root_path, 'static')
DOWNLOAD_FOLDER = os.path.join(app.root_path, 'static\download')
delim = ";" # delimiter for the link and additional info fields in the account table
regex = r';*[\n\r]+'




# decorator to return user to the unconfirmed page when email is not confirmed
def check_confirmed(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.email_confirmed is False:
            #flash('Please confirm your account!', 'warning')
            return redirect(url_for('unconfirmed'))
        return func(*args, **kwargs)
    
    return decorated_function

def generate_email_confirmation_token(email):
    ts = URLSafeTimedSerializer(secret_key=app.config["SECRET_KEY"])
    return ts.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_email_token(token):
    ts = URLSafeTimedSerializer(secret_key=app.config["SECRET_KEY"])
    try:
        email = ts.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=app.config['EMAIL_TOKEN_EXPIRATION'])
    except:
        return False
    
    return email

def tokenize_username(username):
    ts = URLSafeSerializer(secret_key=app.config["SECRET_KEY"])
    return ts.dumps(username, salt=app.config['SECURITY_PASSWORD_SALT'])


def getResources(ownerId):
    '''
    function is used to retrieve all resource names (just that field) from database 
    to pre-populate the WTForms SelectField object. 
    A message is flashed if no data was found...this option is now disabled
    '''
    #message = "No resources were found"
    resources = []
    try:
        records = Account.query.filter_by(owner_id=ownerId).with_entities(Account.resourcename)
        for record in records:
            resources.append(record.resourcename)

        #if not resources:
            #flash(f'{message}', category='warning')

    except exc.OperationalError as e:
        flash(f'{e}', category='danger')            
    except:
        flash(f'{sys.exc_info()[0]} {sys.exc_info()[1]}', category='danger')   

    finally:
        return resources 

def getUserResources(ownerId):
    '''
    function is used to retrieve all resource records (objects) from database 
    A message is flashed if no data was found...this option is now disabled
    '''
    try:
        resources = Account.query.filter_by(owner_id=ownerId).all()
        

    except exc.OperationalError as e:
        flash(f'{e}', category='danger')            
    except:
        flash(f'{sys.exc_info()[0]} {sys.exc_info()[1]}', category='danger')   

    finally:
        return resources 


def getNumberOfRecords(ownerId):
    '''
    function is used to retrieve all resource names (just that field) from database 
    to pre-populate the WTForms SelectField object. 
    A message is flashed if no data was found...this option is now disabled
    '''
    
    return Account.query.filter_by(owner_id=ownerId).count()

    

def deleteAccount(dataDict=None):
    '''
    example of dataDict:
    {'resourcename':'some-resource-name'}
    {'id':'some-id'}
    delete the resources based on specified field (id or resourcename mostly)
    then returns the deleted records
    '''
    records = []
    try:
        if dataDict:
            accounts = Account.query.filter_by(**dataDict).all()
            if accounts:
                for account in accounts:
                    db.session.delete(account)
                    records.append((account.resourcename, account.username, account.add_date.strftime('%b %d, %Y %H:%M')))

                # commit all deletions
                db.session.commit()
        
    except exc.OperationalError as e:
        flash(f'{e}', category='danger')
        db.session.rollback()
        records = []

    except:
        flash(f'{sys.exc_info()[0]} {sys.exc_info()[1]}', category='danger')
        db.session.rollback()
        records = []

    finally:
        return records

def getAccount(dataDict=None, list_format="list"):
    '''
    example of dataDict:
    {'resourcename':'some-resource-name'}
    {'id':'some-id'}
    get a specific account based on specified field (id or resourcename mostly)
    or get all accounts (dataDict=None or not passed)
    then return all records

    list_format = "list" means the link and info fields are stored as a list
    list_format = "string" means the link and info are each a semi-colon delimited string

    '''
    records = []
    try:
        
        if dataDict:
            accounts = Account.query.filter_by(**dataDict).all()
        else:
            accounts = Account.query.filter_by(owner_id=current_user.id).order_by(Account.resourcename).all()

        if accounts:
            for account in accounts:
                if list_format == "list":
                    records.append(
                        {
                        'id': account.id,
                        'resourcename':account.resourcename, 
                        'username':account.username, 
                        'password': account.password,
                        'global_logon': account.global_logon, 
                        'link': [link.strip() for link in account.link.split(sep=delim) if account.link and link],
                        'additional_info': [info.strip() for info in account.additional_info.split(sep=delim) if account.additional_info and info],
                        'add_date':account.add_date.strftime('%b %d, %Y %H:%M'), 
                        'lastupdate':account.lastupdate.strftime('%b %d, %Y %H:%M'), 
                        }
                    )
                else:
                    records.append(
                        {
                        'id': account.id,
                        'resourcename':account.resourcename, 
                        'username':account.username, 
                        'password': account.password,
                        'global_logon': account.global_logon, 
                        'link': account.link,
                        'additional_info': account.additional_info,
                        'add_date':account.add_date.strftime('%b %d, %Y %H:%M'), 
                        'lastupdate':account.lastupdate.strftime('%b %d, %Y %H:%M'), 
                        }
                    )
                    

    except exc.OperationalError as e:
        flash(f'{e}', category='danger')
    except:
        flash(f'{sys.exc_info()[0]} {sys.exc_info()[1]}', category='danger')    
    finally:
        return records




def allowed_file(filename):
    '''
    validates the filename submitted by the user for upload
    '''
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def uploadFile(req):
    # the function returns a dictionary named upload
    upload_dict = {
        'file': None,
        'error': None
    }

    # check if the post request has the 'upload' field name
    if 'upload' not in req:
        upload_dict['error'] = 'Unexpected error occured while submitting the form. No upload part.'
      
    # if user does not select file, browser also submit an empty part without filename
    file = request.files['upload']
    if file.filename == '':
        upload_dict['error'] = 'No file selected for upload.'
    elif not allowed_file(file.filename):
        upload_dict['error'] = 'The uploaded file is not a CSV file.'
    elif file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        if filename:
            file.save(os.path.join(UPLOAD_FOLDER, filename))
            upload_dict['file'] = os.path.join(UPLOAD_FOLDER, filename)
        else:
            upload_dict['error'] = 'The name of the uploaded file is not acceptable. Please change the name and try again.'

    print(upload_dict)

    return upload_dict

def sanitize_df_data (df=None):
    '''
    this function sanitizes the data in the dataframe, read from a CSV file
    1- removes all rows where all fields have NA values
    2- removes all duplicate rows, keeping one only
    3- replaces all NA with ""
    4- replaces all strings true, false with Python True/False
    '''
    skipped_rows = [] # records skipped from the uploaded file, by row #
    added_rows = []   # records to be added to db from the uploaded file, by row #
    resources_in_db = getResources(current_user.id) # resource names already in the db for the logged in user

    if not df.empty:
        df.dropna(axis=0, how='all', inplace=True) # removes all rows with all values = nan
        df.drop_duplicates(keep='first', inplace=True) # removes all duplicate rows, keep only 1
        df.replace(to_replace=np.nan, value="", inplace=True) # replace each nan value with an empty string 
        
        for i, row in df.iterrows():
            # if resourcename/username is blank or global_logon is not boolean or resourcename already in db => skip this record
            if not row['resourcename']  or not row['username'] or not isinstance(row['global_logon'], bool) or row['resourcename'] in resources_in_db:
                skipped_rows.append(i)
            
            # if global_logon is false but no password is provided for the resource => skip this record
            elif not row['global_logon'] and not row['password']:
                skipped_rows.append(i)

            # consider saving the record in the db
            else:
                added_rows.append(i)

            # sanitizing the link and additional_info fields
            row['link'] = re.sub(regex, delim, row['link'])
            row['additional_info'] = re.sub(regex, delim, row['additional_info'])

        # remove the skipped rows from the dataframe
        df.drop(labels=skipped_rows, axis=0, inplace=True)
        
        return {
            'df': df,
            'skipped_rows': ", ".join([str(i) for i in skipped_rows]),
            'added_rows': ", ".join([str(i) for i in added_rows]),
        }


##################################################################################################
################################## THESE FUNCTIONS ARE NOT USED ##################################
##################################################################################################
global_logon_temp_psw = 'initialpsw'
global_logon_file = os.path.join(os.path.join(os.path.dirname(os.path.abspath(__file__)), UPLOAD_FOLDER), 'globallogon.txt')

def initialize_global_logon():
    '''
    This section ensures there is always a psw in the text file.
    Open the text file if it exists, else create a new one.
    If the file is empty, add a temp password to be used for globallogon
    assign the content to the environment variable 'GLOBAL_LOGON'.
    The environment variable will be wiped out when you exit the app and 
    will always be created when the app is started.
    '''
    with open(global_logon_file, mode='r+') as f:
        content = f.read()
        if not content:
            f.write(global_logon_temp_psw)
            os.environ['GLOBAL_LOGON'] = global_logon_temp_psw
        else:
            os.environ['GLOBAL_LOGON'] = content


def updateGlobalLogon(newpsw):
    '''
    update globallogon password in the text file and the environment variable
    as well as all the records in the database that use the globallogon password
    '''
    try:
        with open(global_logon_file, mode='r+') as f:
            f.seek(0, 0) #sets the stream position to the start of the file
            f.truncate(None) # clears the content of the file
            f.write(newpsw)
            os.environ['GLOBAL_LOGON'] = newpsw

        records = Account.query.filter_by(global_logon=True).all()
        for record in records:
            record.password = newpsw
            record.lastupdate = datetime.now()
        
        db.session.commit()
        flash(f'Your GlobalLogOn has been successfully updated.', category='success')


    
    except exc.OperationalError as e:
            flash(f'{e}', category='danger')
    except exc.IntegrityError as e:
        flash(f'{e}', category='danger')
    except:
        flash(f'{sys.exc_info()[0]} {sys.exc_info()[1]}', category='danger')

def clear_session():
    if 'currentrecord' in session:
        session['currentrecord'] = None

def send_email(email, subject, html):
    msg = Message(subject=subject, recipients=[email], html=html)
    mail.send(msg)
    
