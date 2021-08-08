# project/routes.py

# standard libraries 
from datetime import datetime
import os
import itertools
import sys
import re
import pandas as pd
import secrets


# third party libraries 
from flask import Flask, render_template, url_for, request, flash, redirect, session, send_file, abort
from project import app, bcrypt, db, mail
from flask_login import login_user, current_user, logout_user, login_required
from sqlalchemy import exc
from flask_wtf.csrf import CSRFError
from flask_mail import Message


# local application/library specific imports
from project.forms import AddForm, GetForm, Delete1Form, Delete2Form, UpdateForm, RegistrationForm, LoginForm, UpdatePassword, UpdateGlobalLogon, UpdateEmail, RequestResetForm, ResetPasswordForm
from project.models import Account, User
from project.utils.custom_functions import (
    getResources, getUserResources, deleteAccount, getAccount, allowed_file, uploadFile, sanitize_df_data, 
    delim, getNumberOfRecords, regex, DOWNLOAD_FOLDER, send_email, 
    generate_email_confirmation_token, confirm_email_token, check_confirmed, 
    tokenize_username
)



@app.route('/', methods=['GET', 'POST'])
@app.route('/home', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
@login_required
@check_confirmed
def home():
    records = getAccount(list_format="list")
    return render_template('home.html', title="Home")
    
    #return redirect(url_for('all'))
    #return render_template('all.html', title="Accounts Repository - Home", records=records)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated and current_user.email_confirmed:
        return redirect(url_for('home'))

    # create an instance of the registration form
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf_8')
        user_record = {
            'username':form.username.data,
            'email':form.email.data,
            'password':hashed_password,
            'global_logon': form.global_logon.data,
        }
        user = User(**user_record)
        db.session.add(user)
        db.session.commit()

        # send email confirmation link
        subject = "Confirm your email"
        token = generate_email_confirmation_token(user.email)
        confirm_url = url_for('confirm_email', token=token, _external=True) #link in email user will click on
        html = render_template('email/activate.html', confirm_url=confirm_url) #email content
        send_email(user.email, subject, html)

        flash(f'An account has been created for the username {user.username}. An email confirmation link has been sent to you to activate your account. Please click on the embedded link in your email to activate the account. You will not be able to log into the application without activating your account.', category='success')
        return redirect(url_for('login'))

    return render_template('register.html', title='Register', form=form)

@app.route('/confirm/<token>', methods=['GET'])
def confirm_email(token):
    try:
        email = confirm_email_token(token)
    except:
        flash(app.config['CONFIRMATION_LINK_INVALID_MSG'], 'danger')

    user = User.query.filter_by(email=email).first_or_404()
    if user.email_confirmed:
        if not current_user.is_authenticated:
            # display this message only if the use is authenticated but not logged in
            flash('Account already confirmed. Please login.', 'success')
    else:
        user.email_confirmed = True
        #db.session.add(user)
        db.session.commit()
        flash(f'Your email, {email}, has been confirmed and your account has been activated.', category='success')
    
    return redirect(url_for('login'))

# login view
@app.route('/login', methods=['GET', 'POST'])
def login():
    
    if current_user.is_authenticated and current_user.email_confirmed:
        return redirect(url_for('home'))
    
    # create an instance of the login form
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if user.email_confirmed:
                # if user with that email exists and his password matches what is in the db
                # log the user in
                login_user(user, remember=form.remember.data)

                next_page = request.args.get('next', None)
                return redirect(next_page) if next_page else redirect(url_for('home'))
            else:
                login_user(user, remember=form.remember.data)
                return redirect(url_for('unconfirmed'))
        else:
            flash("Login unsuccessful. Please check your email and password.", category='danger') 
    return render_template('login.html', title='Login', form=form)



@app.route('/unconfirmed', methods=['GET'])
@login_required
def unconfirmed():
    if current_user.email_confirmed:
        return redirect('home')

    flash('You must confirm your email.', 'warning')
    return render_template('email/unconfirmed.html')

@app.route('/resend', methods=['GET'])
@login_required
def resend_confirmation():
    print("resend_confirmation", current_user)

    subject = "Confirm your email"
    token = generate_email_confirmation_token(current_user.email)
    confirm_url = url_for('confirm_email', token=token, _external=True) #link in email user will click on
    html = render_template('email/activate.html', confirm_url=confirm_url) #email content
    send_email(current_user.email, subject, html)

    flash(f'You are almost done! A new confirmation email has been sent to {current_user.email}. Please click on the embedded link to complete the registration.', category='success')
    return redirect(url_for('login'))
    


@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/account', methods=['GET', 'POST'])
@login_required
@check_confirmed
def account():
    form_update_password = UpdatePassword(prefix='a')
    form_update_global = UpdateGlobalLogon(prefix='b')
    form_update_email = UpdateEmail(prefix='c')
        
    return render_template('account.html', title="account", form_password=form_update_password, form_global=form_update_global, form_email=form_update_email)


@app.route('/account/updatePassword', methods=['GET', 'POST'])
@login_required
@check_confirmed
def updatePassword():
    form_update_password = UpdatePassword(prefix='a')
    form_update_global = UpdateGlobalLogon(prefix='b')
    form_update_email = UpdateEmail(prefix='c')
    
    # updating user password
    if form_update_password.validate_on_submit():
        current_password = form_update_password.current_password.data
        new_password = form_update_password.new_password.data
        
        if current_password != new_password:
            user = User.query.filter_by(username=current_user.username).first()
            user.password = bcrypt.generate_password_hash(new_password).decode('utf_8')
            db.session.commit()

            flash(f'Your password has been successfully changed', category='success')
            return redirect(url_for('logout'))
        else:
            flash(f'Your new password and the current one are the same. No updates were made.', category='info')


    return render_template('account.html', title="account", form_password=form_update_password, form_global=form_update_global, form_email=form_update_email)

@app.route('/account/updateGlobalLogon', methods=['GET', 'POST'])
@login_required
@check_confirmed
def updateGlobalLogon():
    form_update_password = UpdatePassword(prefix='a')
    form_update_global = UpdateGlobalLogon(prefix='b')
    form_update_email = UpdateEmail(prefix='c')
    
    # updating global logon
    if form_update_global.validate_on_submit():
        new_global_logon = form_update_global.new_global_logon.data
        if new_global_logon != current_user.global_logon:
            user = User.query.filter_by(username=current_user.username).first()
            user.global_logon = new_global_logon
            
            # updating all user resources with new global logon
            for account in user.accounts:
                if account.global_logon:
                    account.password = new_global_logon
            
            db.session.commit()
            flash(f'Your Global Logon has been successfully changed', category='success')
        else:
            flash(f'Your new Global Logon is the same as the current one. No updates were made.', category='info')


    return render_template('account.html', title="account", form_password=form_update_password, form_global=form_update_global, form_email=form_update_email)




@app.route('/account/updateEmail', methods=['GET', 'POST'])
@login_required
@check_confirmed
def updateEmail():
    form_update_password = UpdatePassword(prefix='a')
    form_update_global = UpdateGlobalLogon(prefix='b')
    form_update_email = UpdateEmail(prefix='c')
    
    # updating user email
    if form_update_email.validate_on_submit() and form_update_email.submit.data:
        #print(form_update_email.submit.data) # returns True if submit button is clicked
        new_email = form_update_email.new_email.data
        if new_email != current_user.email:
            user = User.query.filter_by(username=current_user.username).first()
            user.email = new_email
            user.email_confirmed = False
            db.session.commit()

            # send email confirmation link
            subject = "Confirm your email"
            token = generate_email_confirmation_token(user.email)
            confirm_url = url_for('confirm_email', token=token, _external=True) #link in email user will click on
            html = render_template('email/activate.html', confirm_url=confirm_url) #email content
            send_email(user.email, subject, html)
            flash(f'Your email has been successfully updated. An email confirmation link has been sent to you to verify your new email. Please click on the embedded link in your email to complete the verification process. You will not be able to log into the application without completion of the email verification.', category='info')
            return redirect(url_for('logout'))
            

        else:
            flash(f'Your new email is the same as the current one. No updates were made.', category='info')

    return render_template('account.html', title="account", form_password=form_update_password, form_global=form_update_global, form_email=form_update_email)






# FLASK SQLALCHEMY
@app.route('/add', methods=['GET', 'POST'])
@login_required
@check_confirmed
def add():
    form = AddForm()
    if form.validate_on_submit():
        # extracting data from the submitted form
        account_info = {
            'resourcename': form.resourcename.data, 
            'username': form.username.data, 
            'password': current_user.global_logon if form.global_logon.data else form.password.data, 
            'global_logon': form.global_logon.data, # True or False
            'link': form.resourcelink.data, 
            'additional_info': form.additionalinfo.data,
        }

        # sanitizing the link and additional info fields
        # in case user added a new line, remove it and replace it with ; delimiter
        account_info['link'] = re.sub(regex, delim, account_info['link'])
        account_info['additional_info'] = re.sub(regex, delim, account_info['additional_info'])

        account = Account(owner=current_user, **account_info) #create 1 account record for active user
        
        try:
            db.session.add(account) #prepare the record to be added to the db table
            db.session.commit() #add the record to the database table
            flash(f'account for {account_info["resourcename"]} has been added!', category='success')

            # before displaying the record in a table, the value for key='link' must be converted to a list of links
            # without leading/trailing spaces. same thing for additional info
            # account_info['link'] is a string of semi-colon separated links: link1;link2;link3
            # first the semi-colon separated string is converted to an list using the split() method
            # if account_info['link'] is not empty and the element in the list in not empty, remove all trailing/leading spaces
            # from that link and add it to the list. else, do not add it.
            account_info['link'] = [link.strip() for link in account_info['link'].split(sep=delim) if account_info['link'] and link]
            account_info['additional_info'] = [info.strip() for info in account_info['additional_info'].split(sep=delim) if account_info['additional_info'] and info]

            print(account_info['link'])
            print(account_info['additional_info'])

            return render_template('add.html', title="Add New Account", form=form, record=account_info)

            #return redirect(url_for('home'), record=account_info)
        
        except exc.OperationalError as e:
            flash(f'{e}', category='danger')
            db.session.rollback()
        except exc.IntegrityError as e:
            flash(f'{e}', category='danger')
            db.session.rollback()
        except:
            flash(f'{sys.exc_info()[0]} {sys.exc_info()[1]}', category='danger')
            db.session.rollback()

        
    return render_template('add.html', title="Add New Account", form=form)


@app.route('/bulk_upload', methods=['GET', 'POST'])
@login_required
@check_confirmed
def bulk_upload():
    # from upload function to be written later
    records = []

    if request.method == "GET":
        return render_template('bulk_upload.html', title="Bulk Upload") 
   
    upload_dict = uploadFile(request.files)
    if upload_dict['error']:
        flash(upload_dict['error'], category='danger')
        return render_template('bulk_upload.html', title="Bulk Upload")

    try:
        df = pd.read_csv(upload_dict['file'], delimiter=',', header=0, error_bad_lines=False, 
                skipinitialspace=True, skip_blank_lines=True)
        if df.empty:
            flash(f'The uploaded file has no data. No records added to the database.', category='danger')
            return render_template('bulk_upload.html', title="Bulk Upload")
        else:
            # uploaded file has some data in it...

            # DATA SANITIZATION
            df_sanitized = sanitize_df_data(df)
            df = df_sanitized['df']
            skipped_rows = df_sanitized['skipped_rows']
            added_rows = df_sanitized['added_rows']

            for i, row in df.iterrows():
                record = { 
                    'resourcename': row['resourcename'], 
                    'username': row['username'], 
                    'password': None, 
                    'global_logon': row['global_logon'], # True or False
                    'link': row['link'], #row['link'].replace(';', '\n')
                    'additional_info': row['additional_info'], #row['additional_info'].replace(';', '\n')
                }

                if record['global_logon']: # if global_logon checked
                    record['password'] = current_user.global_logon
                else:
                    record['password'] = row['password']

                
                db_record = Account(owner=current_user, **record) #create 1 db record under the active user
                db.session.add(db_record) #prepare the record to be added to the db table


                # format the link and additional info for display (convert to lists)
                record['link'] = [link.strip() for link in record['link'].split(sep=delim) if record['link'] and link]
                record['additional_info'] = [info.strip() for info in record['additional_info'].split(sep=delim) if record['additional_info'] and info]
                records.append(record)
                
            db.session.commit() #add all records to the database table
            #flash(f'The uploaded file has data in it.', category='success')

            

            return render_template('bulk_upload.html', title="Bulk Upload", 
                        added_rows=added_rows, skipped_rows=skipped_rows, records=records)

    # EXCEPTIONS HANDLING
    except pd.errors.EmptyDataError as e:
        flash(f'{e}', category='danger')
        db.session.rollback()
        return render_template('bulk_upload.html', title="Bulk Upload")

    except pd.errors.ParserError as e:
        flash(f'{e}', category='danger')
        db.session.rollback()
        return render_template('bulk_upload.html', title="Bulk Upload")

    except exc.OperationalError as e:
        flash(f'{e}', category='danger')
        db.session.rollback()
        return render_template('bulk_upload.html', title="Bulk Upload")

    except exc.IntegrityError as e:
        flash(f'{e}', category='danger')
        db.session.rollback()
        return render_template('bulk_upload.html', title="Bulk Upload")

    #except:
        #flash(f'{sys.exc_info()[0]} {sys.exc_info()[1]}', category='danger')
        #return render_template('bulk_upload.html', title="Bulk Upload")

    #else: # execute below if no exceptions

    

@app.route('/all', methods=['GET'])
@login_required
@check_confirmed
def all():
    records = getAccount(list_format="list")
    return render_template('all.html', title="All records", records=records)



@app.route('/download', methods=['GET'])
@login_required
@check_confirmed
def download():
    records = getAccount(list_format="string")  # list of dictionaries
    filename = secrets.token_hex(nbytes=16)     # tokenize the filename

    # creating the folder that stores the downloadable file.
    # the folder name is generated using itsdangerous.
    download_path = os.path.join(DOWNLOAD_FOLDER, tokenize_username(current_user.username))
    if not os.path.exists(download_path):
        os.mkdir(download_path)
    else:
        # delete all old files
        dirEntry = os.scandir(download_path)
        for entry in dirEntry:
            os.remove(entry.path)

    download_path = os.path.join(download_path, f'{filename}.csv')
    #print(download_path)

    # store records in pandas dataframe
    if records:
        columns = list(records[0].keys())
        df = pd.DataFrame(data=records)
        df.to_csv(download_path, sep=',', mode='w', index=False, columns=columns)
        
        # download section
        #return "download...."
        return send_file(download_path, as_attachment=True)

    else:
        flash(f'There are no records to download', category='info')
        return render_template('home.html', title="Home")



@app.route('/get', methods=['GET', 'POST'])
@login_required
@check_confirmed
def get():
    get_form = GetForm()
    if get_form.validate_on_submit():
        resourcename = get_form.resourcename.data
        update_option = get_form.update_option.data
        records = getAccount(dataDict={'resourcename':resourcename, 'owner_id':current_user.id}, list_format="list")

        if (update_option and records):
            return redirect(url_for('action_update', id=records[0]['id']))
        else:
            return render_template('get.html', title="Get", form=get_form, records=records)


    return render_template('get.html', title="Get", form=get_form)


@app.route('/action_delete/<id>', methods=['GET'])
@login_required
@check_confirmed
def action_delete(id):
    records = deleteAccount(dataDict={'id':id})
    if records:
    # records is a list of tuple (account.resourcename, account.username, account.add_date.strftime('%b %d, %Y %H:%M'))
        flash(f'The following record has been deleted = Resource: {records[0][0]}, created on: {records[0][2]}', category='success')
    else:
        flash(f'No record has been deleted.', category='warning')
    return redirect(url_for('all'))


@app.route('/action_update/<id>', methods=['GET', 'POST'])
@login_required
@check_confirmed
def action_update(id):
    record = getAccount(dataDict={'id':id}, list_format="list") # records is a list of dictionary, 1 record in this case
    update_form = UpdateForm()

    if update_form.validate_on_submit():
        # extract the new changes, update db table, flash
        try:
            account = Account.query.get(id) #record object
            newupdate = False # to detect whether an update is needed

            if account.username != update_form.username.data:
                newupdate = True
                account.username = update_form.username.data

            # sanitizing the link and additional info fields
            user_link = re.sub(regex, delim, update_form.resourcelink.data)
            if account.link != user_link:
                newupdate = True
                account.link = user_link

            user_additional_info = re.sub(regex, delim, update_form.additionalinfo.data)
            if account.additional_info != user_additional_info:
                newupdate = True
                account.additional_info = user_additional_info

            if account.global_logon != update_form.global_logon.data:
                newupdate = True
                account.global_logon = update_form.global_logon.data
                if update_form.global_logon.data: # if global_logon checked
                    account.password = current_user.global_logon
                else:
                    account.password = update_form.password.data
                
            #what if the checkbox state remains unchanged
            else:
                #if global_logon remains unchecked but password has changed
                if not update_form.global_logon.data and account.password != update_form.password.data: 
                    newupdate = True
                    account.password = update_form.password.data
                # what if the checkbox remains checked but somehow the resource global Logon does not match that of the user's
                elif update_form.global_logon.data and account.password != current_user.global_logon:
                    # enforce global logon password
                    newupdate = True
                    account.password = current_user.global_logon

            if newupdate:
                # updating the update-date
                account.lastupdate = datetime.now()

                # commit all changes
                db.session.commit()

                flash(f'Record for resource = {update_form.resourcename.data} has been updated', category='success')

            else:
                flash(f'Record for resource = {update_form.resourcename.data} remains unchanged', category='secondary')

            return render_template('update.html', title='Update', form=update_form, )

        except exc.OperationalError as e:
            flash(f'{e}', category='danger') 
            return render_template('update.html', title='Update', error=f'{e}')

        except:
            flash(f'{sys.exc_info()[0]} {sys.exc_info()[1]}', category='danger')
            return render_template('update.html', title='Update', error=f'{sys.exc_info()[0]} {sys.exc_info()[1]}')

    elif request.method == 'GET':
        if record:
            update_form.resourcename.data = record[0]['resourcename']
            update_form.username.data = record[0]['username']
            update_form.global_logon.data = record[0]['global_logon']
            update_form.password.data = record[0]['password']
            update_form.resourcelink.data = delim.join(record[0]['link'])
            update_form.additionalinfo.data = delim.join(record[0]['additional_info'])

            return render_template('update.html', title='Update', form=update_form)
        else:
            return abort(404)

    else:
        return render_template('update.html', title='Update', form=update_form)
        

    





@app.route('/delete1', methods=['GET', 'POST'])
@login_required
@check_confirmed
def delete1():
    form = Delete1Form()
    if form.validate_on_submit():
        resourcename = form.resourcename.data
        records = deleteAccount(dataDict={'resourcename':resourcename, 'owner_id':current_user.id})
        return render_template('delete1.html', title="Delete", form=form, records=records)
        
    return render_template('delete1.html', title="Delete", form=form)

@app.route('/delete2', methods=['GET', 'POST'])
@login_required
@check_confirmed
def delete2():
    records = []
    form = Delete2Form()

    # initialize the select field
    '''
    the choices property of the WTForms SelectField is a list tuples (value, label).
    in this case, the value and label are the same.
    '''
    choices = [(record.resourcename,record.resourcename) for record in getUserResources(current_user.id)]
    form.resourcelist.choices = choices

    if form.validate_on_submit():
        resourcename = form.resourcelist.data
        if resourcename:
            records = deleteAccount(dataDict={'resourcename':resourcename, 'owner_id':current_user.id})

            # refresh the SelectField list
            choices = [(record.resourcename,record.resourcename) for record in getUserResources(current_user.id)]
            form.resourcelist.choices = choices
            
    if choices:
        if records:
            return render_template('delete2.html', title="Delete", form=form, records=records)
        else:
            return render_template('delete2.html', title="Delete", form=form)
    else:
        if records:
            return render_template('delete2.html', title="Delete", records=records)
        else:
            return render_template('delete2.html', title="Delete")
        

    
@app.route('/delete_all', methods=['GET','POST'])
@login_required
@check_confirmed
def delete_all():
    if request.method == 'POST':
        records = deleteAccount(dataDict={'owner_id':current_user.id})
        if records:
            flash(f'All your records have been deleted.', category='success')
            return redirect(url_for('home'))
            
        else:
            flash(f'There are no records to delete.', category='warning')
            return redirect(url_for('home'))

    else:
        return render_template('delete_all.html', title="Delete All", count=getNumberOfRecords(current_user.id))


@app.route('/ajax_display_accounts', methods=['GET'])
@login_required
@check_confirmed
def ajax_display_accounts():
    userInput = request.args.get("resourcename")
    ownerId = int(request.args.get("owner_id"))
    result = []
    html_out = ''
    if userInput:
        # make user input all lowercase
        userInput = userInput.lower()

        #extract the list of resources from the database
        resources = getResources(ownerId) 

        # selectors is a list of True/False for each resource
        # True if the resource name starts with the user input else False
        selectors = [(item.lower().startswith(userInput)) for item in resources] 
        
        # return a list of all elements for which where each element in resources has a corresponding element in 
        # selectors set to True
        result = itertools.compress(resources, selectors)

        for resource in result:
            html_out += f'<button type="button" class="list-group-item list-group-item-action">{resource}</button>'
        
        return html_out

    return "missing data"


def send_reset_email(user):
    # retrieving the token for the user object argument
    token = user.get_token()
    msg = Message(subject="Password Reset Request", recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link: 
{url_for('reset_password', token=token, _external=True)}.

If you did not make this request, please ignore this email.  
    '''
    mail.send(msg)

# password reset request
@app.route('/reset_request', methods=['GET', 'POST'])
def reset_request():
    # A LOGGED IN USER DOES NOT NEED THIS PAGE. IN THE EVENT THIS HAPPENS, THE USER
    # IS REDIRECTED HOME
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = RequestResetForm()
    if form.validate_on_submit():
        # send email to user with link containing a timed token to reset password
        user = User.query.filter_by(email = form.email.data).first()
        send_reset_email(user)

        flash("An email has been sent with instructions to reset your password.", "info")
        return redirect(url_for("login"))

    return render_template('reset_request.html', title='Reset Password', form=form)

@app.route('/reset_password/<string:token>', methods=['GET', 'POST'])
def reset_password(token):
    # A LOGGED IN USER DOES NOT NEED THIS PAGE. IN THE EVENT THIS HAPPENS, THE USER
    # IS REDIRECTED HOME
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    # verification of the token
    user = User.verify_token(token) #returns user object if token is valid, else None
    if not user:
        msg = "Sorry, this change password link is not valid. Request another one using the form below."
        flash(msg, "warning")
        return redirect(url_for("reset_request"))
    
    # token is valid
    form = ResetPasswordForm()
    if form.validate_on_submit():
        # hash the new password and save it to db
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf_8')
        user.password = hashed_password
        db.session.commit()
        flash("Your password has been updated successfully. You are now able to log in.", "success")
        return redirect(url_for("login"))

    return render_template('reset_password.html', title='Reset Password', form=form)




@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('csrf_error.html', error=e), 400

@app.errorhandler(405)
def handle_405(e):
    return render_template('error.html', error=e), 405

@app.errorhandler(404)
def handle_404(e):
    return render_template('error.html', error=e), 404





@app.route('/test', methods=['GET', 'POST'])
def testing():
    return "testing endpoint"

