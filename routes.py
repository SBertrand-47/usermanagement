from flask import render_template, request, redirect, url_for, flash, session, jsonify, make_response
from models import db, App_Users
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash
import os
from itsdangerous import URLSafeTimedSerializer
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from email_validator import validate_email, EmailNotValidError
from itsdangerous import BadSignature, SignatureExpired
from werkzeug.utils import secure_filename
from random import randint
from datetime import datetime, timedelta
import functools
import re
import requests

SECRET_KEY = os.environ.get('SECRET_KEY')
serializer = URLSafeTimedSerializer(SECRET_KEY)

def nocache(view):
    @functools.wraps(view)
    def no_cache(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers[
            'Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response

    return no_cache

def configure_routes(app):

    def send_email(to_email, subject, body):
        api_key = os.environ.get("SENDGRID_API_KEY")
        from_email = 'prochatapp@sgeneratorapp.online'  # Replace this with your desired sender email address

        message = Mail(
            from_email=from_email,
            to_emails=to_email,
            subject=subject,
            plain_text_content=body
        )

        try:
            sg = SendGridAPIClient(api_key)
            response = sg.send(message)
            print(response.status_code)
            print(response.body)
            print(response.headers)
        except Exception as e:
            print(e)

    if not os.path.exists('static/user_images'):
        os.makedirs('static/user_images')

    base_dir = os.path.abspath(os.path.dirname(__file__))
    upload_dir = os.path.join(base_dir, 'static/user_images')
    UPLOAD_FOLDER = upload_dir
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

    # Registration Route
    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == 'GET':
            return render_template('register.html', site_key=os.getenv('RECAPTCHA_SITE_KEY'))

        if request.method == 'POST':
            recaptcha_response = request.form.get('g-recaptcha-response')

            # Validate reCAPTCHA
            r = requests.post('https://www.google.com/recaptcha/api/siteverify', data={
                'secret': os.getenv('RECAPTCHA_SECRET_KEY'),
                'response': recaptcha_response
            })

            result = r.json()

            print(result)

            if not result['success']:
                flash('Invalid reCAPTCHA. Please try again.', 'error')
                return render_template('register.html')


            email, password, hashed_password, first_name, last_name, gender, age, date_of_birth, \
                marital_status, nationality, profile_photo = get_form_data(
                request)

            if profile_photo is None:
                return profile_photo_error()

            if not is_password_strong(password):
                return weak_password_error()

            if not allowed_file(profile_photo.filename):
                return invalid_file_error()

            filename = save_profile_photo(profile_photo)

            if email_exists(email):
                return email_exists_error()

            new_user = create_new_user(email, hashed_password, first_name, last_name, gender, age, date_of_birth,
                                       marital_status, nationality, filename)

            send_welcome_email(new_user, first_name)

            flash('Account created successfully! Please check your email to verify your account.', 'success')
            return redirect(url_for('login'))

        return render_template('register.html')

    def get_form_data(request):
        email = request.form['user_email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        gender = request.form['gender']
        age = request.form['age']
        date_of_birth = request.form['date_of_birth']
        marital_status = request.form['marital_status']
        nationality = request.form['nationality']
        profile_photo = request.files.get('profile_photo', None)

        return email, password, hashed_password, first_name, last_name, \
            gender, age, date_of_birth, marital_status, nationality, profile_photo

    def profile_photo_error():
        flash('Profile picture is required.', 'danger')
        return render_template('register.html')

    def weak_password_error():
        flash('Your password is too weak.', 'error')
        return render_template('register.html')

    def invalid_file_error():
        flash('Invalid file format. Please upload an image file.', 'danger')
        return render_template('register.html')

    def save_profile_photo(profile_photo):
        filename = secure_filename(profile_photo.filename)
        profile_photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return filename

    def email_exists(email):
        return App_Users.query.filter_by(user_email=email).first() is not None

    def email_exists_error():
        flash('Email already exists, please use another one or Login!', 'danger')
        return redirect(url_for('register'))

    def create_new_user(email, hashed_password, first_name, last_name, gender, age, date_of_birth, marital_status,
                        nationality, filename):
        new_user = App_Users(user_email=email, password=hashed_password, first_name=first_name, last_name=last_name,
                             gender=gender, age=age, date_of_birth=date_of_birth, marital_status=marital_status,
                             nationality=nationality, is_active=False, profile_photo=filename)
        db.session.add(new_user)
        db.session.commit()
        return new_user

    def send_welcome_email(new_user, first_name):
        token = serializer.dumps(new_user.user_email, salt=os.environ.get('SECURITY_PASSWORD_SALT'))
        subject = 'Welcome to Our App!'
        body = f"Dear {first_name},\n\nThank you for signing up for our app! Please verify your email by clicking the link below:\n\n{url_for('verify_email', token=token, _external=True)}\n\nBest regards,\n\nThe App Team"
        send_email(new_user.user_email, subject, body)

    #Login and OTP handling routes
    @app.route("/", methods=["GET", "POST"])
    @nocache
    def login():
        if 'email' in session:
            return handle_logged_in_user()

        if request.method == 'POST':
            return handle_login_attempt()

        return render_template('login.html')

    def handle_logged_in_user():
        if not session.get('is_verified', False):
            return redirect(url_for('otp_verification'))

        user = App_Users.query.filter_by(user_email=session['email']).first()
        if user.user_role == 'admin':
            return redirect(url_for('admin'))
        return render_template('index.html', user=user)

    def handle_login_attempt():
        email = request.form['user_email']
        password = request.form['password']

        user = App_Users.query.filter_by(user_email=email).first()

        if not user or not check_password_hash(user.password, password):
            flash('Invalid username or password', 'error')
            return redirect(url_for('login'))

        session['email'] = email
        session['user_role'] = user.user_role

        if user.is_active:
            return handle_active_user(user)

        flash('Your account has not been activated yet. Please check your email and verify your account.', 'error')
        return redirect(url_for('login'))

    def handle_active_user(user):
        if user.user_role == 'admin':
            return redirect(url_for('admin'))

        send_otp_to_user(user.user_email)
        session['is_verified'] = False
        return redirect(url_for('otp_verification'))

    def send_otp_to_user(email):
        otp = str(randint(100000, 999999))

        subject = 'Your OTP'
        body = 'Your OTP is {}'.format(otp)
        send_email(email, subject, body)

        session['otp'] = otp
        session['otp_expiry'] = (datetime.utcnow() + timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S.%f')
        session['otp_attempts'] = 0

    @app.route('/home')
    def index():
        if 'email' not in session or not session.get('is_verified', False):
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))

        user = App_Users.query.filter_by(user_email=session['email']).first()
        return render_template('index.html', user=user)


    @app.route("/otp_verification", methods=["GET", "POST"])
    @nocache
    def otp_verification():
        if 'email' not in session:
            return redirect(url_for('login'))
        if request.method == 'POST':
            otp = request.form['otp']
            if 'otp' in session:
                # Check if OTP is expired
                if datetime.utcnow() > datetime.strptime(session['otp_expiry'], '%Y-%m-%d %H:%M:%S.%f'):
                    session.pop('email', None)  # Clear the 'email' from the session
                    flash('OTP expired. Please sign in again.', 'error')
                    return redirect(url_for('login'))
                # Check if user has exceeded maximum number of attempts
                if session['otp_attempts'] >= 3:
                    session.pop('email', None)  # Clear the 'email' from the session
                    flash('Maximum OTP attempts exceeded. Please sign in again.', 'error')
                    return redirect(url_for('login'))
                # Check if OTP is correct
                if otp == session['otp']:
                    ## 'email' is already in the session
                    session['is_verified'] = True
                    return jsonify({'status': 'verified'})
                else:
                    session['otp_attempts'] += 1
                    if session['otp_attempts'] >= 3:
                        return jsonify({'status': 'max_attempts_exceeded'})
                    else:
                        return jsonify({'status': 'incorrect', 'attempts_left': 3 - session['otp_attempts']})
            else:
                return jsonify({'status': 'incorrect', 'attempts_left': 3 - session['otp_attempts']})
        return render_template('otp_verification.html', otp_expiry=session['otp_expiry'],
                               attempts_left=3 - session['otp_attempts'], login_url=url_for('login'))

    #Verifying the Email, before login-in

    @app.route('/verify_email/<token>')
    @nocache
    def verify_email(token):
        try:
            email = serializer.loads(
                token,
                salt=os.environ.get('SECURITY_PASSWORD_SALT'),
                max_age=86400  # Token expires after 24 hours
            )
        except (BadSignature, SignatureExpired):
            flash('Email verification failed: Invalid or expired token')
            return redirect(url_for('register'))

        user = App_Users.query.filter_by(user_email=email).first()

        if user is not None:
            user.is_active = True
            db.session.commit()
            flash('Email successfully verified! You can now log in.')
            return redirect(url_for('login'))

        flash('Email verification failed: User not found')

        return redirect(url_for('register'))


    #Logout Route

    @app.route('/logout')
    @nocache
    def logout():
        session.pop('email', None)  # Remove the username from the session
        flash('You have successfully logged out.', 'success')
        return redirect(url_for('login'))  # Redirect the user to the login page


    # Resetting the password Routes

    @app.route('/forgot-password', methods=['GET', 'POST'])
    @nocache
    def forgot_password():
        if request.method == 'POST':
            return handle_forgot_password_attempt()

        return render_template('forgot_password.html')

    def handle_forgot_password_attempt():
        email = request.form['email']
        if 'email' in session:
            session.pop('email', None)

        try:
            valid_email = validate_email(email)
            email = valid_email["email"]
        except EmailNotValidError as e:
            flash(str(e))
            return redirect(url_for('forgot_password'))

        user = App_Users.query.filter_by(user_email=email).first()
        if user is None:
            flash('No account found with that email')
            return redirect(url_for('forgot_password'))

        send_password_reset_email(user)
        flash('Password reset link sent! Please check your email.')
        return redirect(url_for('login'))

    def send_password_reset_email(user):
        serializer = URLSafeTimedSerializer(os.environ.get('SECRET_KEY'))
        token = serializer.dumps(user.user_email, salt=os.environ.get('SECURITY_PASSWORD_SALT'))

        user.reset_token = token
        db.session.commit()

        subject = 'Password Reset Requested'
        body = f"Dear {user.first_name},\n\nYou recently requested to reset your password for your account. Please click the link below to reset it:\n\n{url_for('reset_password', token=token, _external=True)}\n\nIf you did not request this change, you can ignore this email and your password will remain the same.\n\nBest regards,\n\nThe Chat App Team"

        send_email(user.user_email, subject, body)

    @app.route('/reset-password/<token>', methods=['GET', 'POST'])
    def reset_password(token):
        if 'email' in session:
            return redirect(url_for('index'))

        user, valid_token = validate_reset_password_token(token)
        if user is None or not valid_token:
            flash('Invalid email address or reset token!', 'error')
            return redirect(url_for('login'))

        if request.method == 'POST':
            return handle_password_reset(user, token)

        return render_template('reset_password.html', token=token)

    def validate_reset_password_token(token):
        serializer = URLSafeTimedSerializer(os.environ.get('SECRET_KEY'))
        try:
            email = serializer.loads(
                token,
                salt=os.environ.get('SECURITY_PASSWORD_SALT'),
                max_age=3600
            )
        except:
            flash('The password reset link is invalid or has expired.', 'error')
            return None, False

        user = App_Users.query.filter_by(user_email=email).first()

        return user, user is not None and user.reset_token == token

    def handle_password_reset(user, token):
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('The passwords do not match.', 'error')
            return render_template('reset_password.html', token=token)
        if not is_password_strong(password):
            flash('Your password is too weak.', 'error')
            return render_template('reset_password.html', token=token)

        user.password = generate_password_hash(password)
        user.reset_token = None  # Invalidate the token
        db.session.commit()
        flash('Your password has been reset.', 'success')
        return redirect(url_for('login'))

    def is_password_strong(password):
        """Check password strength."""
        if len(password) < 8:
            return False
        if not re.search("[a-z]", password):
            return False
        if not re.search("[A-Z]", password):
            return False
        if not re.search("[0-9]", password):
            return False
        return True

    # Routes used by users to request verification
    @app.route('/verify_profile', methods=['GET', 'POST'])
    @nocache
    def verify_profile():
        if 'email' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))

        # Get the logged in user
        user = App_Users.query.filter_by(user_email=session['email']).first()

        if request.method == 'POST':
            return handle_verification_submission(user)

        return render_template('verify_profile.html', user=user)

    def handle_verification_submission(user):
        # Get the ID type and ID document from the form
        id_number = request.form['id_number']
        id_type = request.form['id_type']
        id_document = request.files['id_document']

        if id_document and allowed_file(id_document.filename):
            save_verification_document(user, id_number, id_type, id_document)
            flash(
                'Your document has been submitted and is pending verification. You will be notified once the process is over.',
                'success')
            return redirect(url_for('home'))

        flash('Invalid file type. Please upload a valid document.', 'error')
        return redirect(url_for('verify_profile'))

    def save_verification_document(user, id_number, id_type, id_document):
        # Save the ID document in the verification_documents folder
        filename = secure_filename(id_document.filename)
        id_document.save(os.path.join(app.config['UPLOAD_FOLDER'], 'verification_documents', filename))

        # Update the user's verification status to pending
        user.verification_status = 'PENDING'
        user.nid_or_passport = id_number
        user.document_image = filename

        # Commit the changes to the database
        db.session.commit()

    # Admin routes to be used by the admin to verify users, or reject them
    @app.route('/admin', methods=['GET', 'POST'])
    def admin():
        if 'email' not in session:
            return unauthorized_access()

        users = App_Users.query.filter_by(verification_status='PENDING').all()
        return render_template('admin.html', users=users)

    @app.route('/verify_user/<user_id>', methods=['GET'])
    def verify_user(user_id):
        if not is_admin_user():
            return unauthorized_access()

        user = get_user(user_id)
        if not user:
            return user_not_found()

        user.verification_status = 'VERIFIED'
        db.session.commit()

        send_verification_status_email(user, 'Account Verified', 'Congratulations, your account has been verified!')

        flash('User verified successfully', 'success')
        return redirect(url_for('admin'))

    @app.route('/reject_user/<user_id>', methods=['GET'])
    def reject_user(user_id):
        if not is_admin_user():
            return unauthorized_access()

        user = get_user(user_id)
        if not user:
            return user_not_found()

        user.verification_status = 'UNVERIFIED'
        db.session.commit()

        send_verification_status_email(user, 'Account Verification Failed',
                                       'Unfortunately, your account could not be verified. Please contact support for further assistance.')

        flash('User verification rejected', 'success')
        return redirect(url_for('admin'))

    def is_admin_user():
        return 'email' in session and session['user_role'] == 'admin'

    def get_user(user_id):
        return App_Users.query.filter_by(id=user_id).first()

    def unauthorized_access():
        flash('Unauthorized access', 'error')
        return redirect(url_for('login'))

    def user_not_found():
        flash('User not found', 'error')
        return redirect(url_for('admin'))

    def send_verification_status_email(user, subject, body):
        send_email(user.user_email, subject, body)


