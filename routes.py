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

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == 'POST':
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

            if profile_photo is None:
                flash('Profile picture is required.', 'danger')
                return render_template('register.html')

            if not is_password_strong(password):
                flash('Your password is too weak.', 'error')
                return render_template('register.html')

            if not allowed_file(profile_photo.filename):
                flash('Invalid file format. Please upload an image file.', 'danger')
                return render_template('register.html')

            filename = secure_filename(profile_photo.filename)
            profile_photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            try:
                valid_email = validate_email(email)
                email = valid_email["email"]
            except EmailNotValidError as e:
                flash(str(e))
                return redirect(url_for('register'))

            if App_Users.query.filter_by(user_email=email).first() is not None:
                flash('Email already exists, please use another one or Login!', 'danger')
                return redirect(url_for('register'))

            new_user = App_Users(user_email=email, password=hashed_password, first_name=first_name,
                                 last_name=last_name, gender=gender, age=age, date_of_birth=date_of_birth,
                                 marital_status=marital_status, nationality=nationality, is_active=False,
                                 profile_photo=filename)
            db.session.add(new_user)
            db.session.commit()

            token = serializer.dumps(new_user.user_email, salt=os.environ.get('SECURITY_PASSWORD_SALT'))

            subject = 'Welcome to Our App!'
            body = f"Dear {first_name},\n\nThank you for signing up for our app! Please verify your email by clicking the link below:\n\n{url_for('verify_email', token=token, _external=True)}\n\nBest regards,\n\nThe App Team"

            send_email(email, subject, body)

            flash('Account created successfully! Please check your email to verify your account.', 'success')
            return redirect(url_for('login'))

        return render_template('register.html')


    @app.route("/", methods=["GET", "POST"])
    @nocache
    def login():
        if 'email' in session:
            user = App_Users.query.filter_by(user_email=session['email']).first()
            if user.user_role == 'admin':
                return redirect(url_for('admin'))
            else:
                return render_template('index.html', user=user)

        if request.method == 'POST':
            email = request.form['user_email']
            password = request.form['password']
            user = App_Users.query.filter_by(user_email=email).first()
            if user and check_password_hash(user.password, password):
                session['email'] = email
                session['user_role'] = user.user_role
                if user.is_active:
                    if user.user_role == 'admin':
                        return redirect(url_for('admin'))
                    else:
                        # Generate OTP
                        otp = str(randint(100000, 999999))
                        # Send OTP to user's email
                        subject = 'Your OTP'
                        body = 'Your OTP is {}'.format(otp)
                        send_email(email, subject, body)
                        # Store OTP, email and expiry time in user's session
                        session['otp'] = otp
                        session['otp_expiry'] = (datetime.utcnow() + timedelta(minutes=5)).strftime(
                            '%Y-%m-%d %H:%M:%S.%f')
                        session['otp_attempts'] = 0
                        return redirect(url_for('otp_verification'))
                else:
                    flash('Your account has not been activated yet. Please check your email and verify your account.',
                          'error')
            else:
                flash('Invalid username or password', 'error')
        return render_template('login.html')

    # Define other routes as needed
    @app.route('/home')
    def index():
            if 'email' in session:
                user = App_Users.query.filter_by(user_email=session['email']).first()
                return render_template('index.html', user=user)
            else:
                flash('Please log in to access this page', 'error')
                return redirect(url_for('login'))


    @app.route("/otp_verification", methods=["GET", "POST"])
    @nocache
    def otp_verification():
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
                    # 'email' is already in the session
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

            # Generate a unique token for resetting password
            serializer = URLSafeTimedSerializer(os.environ.get('SECRET_KEY'))
            token = serializer.dumps(user.user_email, salt=os.environ.get('SECURITY_PASSWORD_SALT'))

            # Store the token in the user's record
            user.reset_token = token
            db.session.commit()

            # Send a password reset email to the user
            subject = 'Password Reset Requested'
            body = f"Dear {user.first_name},\n\nYou recently requested to reset your password for your account. Please click the link below to reset it:\n\n{url_for('reset_password', token=token, _external=True)}\n\nIf you did not request this change, you can ignore this email and your password will remain the same.\n\nBest regards,\n\nThe Chat App Team"

            send_email(email, subject, body)

            flash('Password reset link sent! Please check your email.')
            return redirect(url_for('login'))

        # This return statement will handle the GET method and render the forgot_password.html template
        return render_template('forgot_password.html')

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

    @app.route('/reset-password/<token>', methods=['GET', 'POST'])
    def reset_password(token):
        if 'email' in session:
            return redirect(url_for('index'))

        serializer = URLSafeTimedSerializer(os.environ.get('SECRET_KEY'))
        try:
            email = serializer.loads(
                token,
                salt=os.environ.get('SECURITY_PASSWORD_SALT'),
                max_age=3600
            )
        except:
            flash('The password reset link is invalid or has expired.', 'error')
            return redirect(url_for('login'))

        user = App_Users.query.filter_by(user_email=email).first()
        if user is None or user.reset_token != token:
            flash('Invalid email address or reset token!', 'error')
            return redirect(url_for('login'))

        if request.method == 'POST':
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

        return render_template('reset_password.html', token=token)

    @app.route('/verify_profile', methods=['GET', 'POST'])
    @nocache
    def verify_profile():
        if 'email' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))

        # Get the logged in user
        user = App_Users.query.filter_by(user_email=session['email']).first()

        if request.method == 'POST':
            # Get the ID type and ID document from the form
            id_number = request.form['id_number']
            id_type = request.form['id_type']
            id_document = request.files['id_document']

            if id_document and allowed_file(id_document.filename):
                # Save the ID document in the verification_documents folder
                filename = secure_filename(id_document.filename)
                id_document.save(os.path.join(app.config['UPLOAD_FOLDER'], 'verification_documents', filename))

                # Update the user's verification status to pending
                user.verification_status = 'PENDING'
                user.nid_or_passport = id_number
                user.document_image = filename


                # Commit the changes to the database
                db.session.commit()

                flash(
                    'Your document has been submitted and is pending verification. You will be notified once the process is over.',
                    'success')
                return redirect(url_for('home'))

            else:
                flash('Invalid file type. Please upload a valid document.', 'error')
                return redirect(url_for('verify_profile'))

        # Render the verify_profile page when the request is a GET
        return render_template('verify_profile.html', user=user)

    @app.route('/admin', methods=['GET', 'POST'])
    def admin():
        if 'email' not in session:
            flash('Unauthorized access', 'error')
            return redirect(url_for('login'))

        # Get all users with a pending status
        users = App_Users.query.filter_by(verification_status='PENDING' or 'VERIFIED').all()

        return render_template('admin.html', users=users)

    @app.route('/verify_user/<user_id>', methods=['GET'])
    def verify_user(user_id):
        # Ensure the user is logged in and is an admin
        if 'email' not in session or session['role'] != 'admin':
            flash('Unauthorized access', 'error')
            return redirect(url_for('login'))

        user = App_Users.query.filter_by(id=user_id).first()

        if not user:
            flash('User not found', 'error')
            return redirect(url_for('admin'))

        # Update the user's verification status
        user.verification_status = 'VERIFIED'

        db.session.commit()

        # Send a confirmation email
        subject = 'Account Verified'
        body = 'Congratulations, your account has been verified!'
        send_email(user.user_email, subject, body)

        flash('User verified successfully', 'success')

        return redirect(url_for('admin'))

    @app.route('/reject_user/<user_id>', methods=['GET'])
    def reject_user(user_id):
        # Ensure the user is logged in and is an admin
        if 'email' not in session or session['role'] != 'admin':
            flash('Unauthorized access', 'error')
            return redirect(url_for('login'))

        user = App_Users.query.filter_by(id=user_id).first()

        if not user:
            flash('User not found', 'error')
            return redirect(url_for('admin'))

        # Update the user's verification status
        user.verification_status = 'UNVERIFIED'

        db.session.commit()

        # Send an email informing the user of the rejection
        subject = 'Account Verification Failed'
        body = 'Unfortunately, your account could not be verified. Please contact support for further assistance.'
        send_email(user.user_email, subject, body)

        flash('User verification rejected', 'success')

        return redirect(url_for('admin'))

