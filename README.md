# Welcome to Our User Registration and Authentication System

## Demo

You can see a live demo of the project here: [Demo Link](https://yourdemolink.com)


## Table of Contents
1. [Introduction](#introduction)
2. [System Features](#system-features)
3. [Installation & Setup](#installation--setup)
4. [Usage Guide](#usage-guide)
5. [Admin Usage](#admin-usage)
6. [Contributing](#contributing)

## Introduction

Our User Registration and Authentication System is a secure and robust solution for managing user registration, login, verification, and password reset functionalities. It's built with Python's Flask framework and incorporates best practices to ensure the security of user data.

## System Features

1. **User Registration**: New users can register by providing necessary details including email, password, first name, last name, gender, age, date of birth, marital status, nationality, and profile photo.

2. **Password Strength Check**: The system checks the strength of the password during registration and password reset, ensuring it's not weak. The password must be at least 8 characters long, and should include at least one uppercase letter, one lowercase letter, one digit, and one special character.

3. **Email Verification**: After successful registration, an email verification link is sent to the user's email.

4. **Identity Verification**: In addition to email verification, users are required to upload a passport or national identification card for verification.

5. **Login**: Registered and verified users can log in using their email and password. OTP will be sent on their email as 2FA

6. **Admin Dashboard**: There is a separate dashboard for administrators.

7. **Password Reset**: If a user forgets their password, they can request a password reset. A password reset link is sent to the user's email.

## Installation & Setup

1. Clone the repository to your local machine.

2. Install Python 3.7 or above if you haven't already.

3. Install the required dependencies by running `pip install -r requirements.txt` in your command line.

4. Set up your environment variables in a `.env` file in the project root. It should look something like this:

    ```dotenv
    SECRET_KEY=your_secret_key
    SECURITY_PASSWORD_SALT=your_security_password_salt
    SENDGRID_API_KEY = YOUR_SENDGRID_API_KEY
    SQLALCHEMY_DATABASE_URI = YOUR_URI
    SQLALCHEMY_TRACK_MODIFICATIONS: False
    
    ```

    Replace `your_secret_key`, `your_security_password_salt`, `YOUR_SENDGRID_API_KEY`, and `YOUR_URI` with your own values.

5. Run the application with `python main.py`.

## Usage Guide

1. Open the application in your web browser. If running locally, it will be at `http://localhost:5000`.

2. Click "Register" to create a new account. Fill out all the required fields. Upload yout profile picture, as it is required during registration

3. Check your email for a verification link. Click the link to verify your email.

4. Once verified, you can log in using your email and password, the system will send you an OTP each time you try to login so make sure your email is valid also the user will have 5 minutes to provide that OTP
   else it will expire and they will have to request a new one, also they will have 3 Attempts to give a valid OTP.

5. If you forget your password, click "Forgot Password" on the login page. Enter your email and click "Reset Password". You'll receive a password reset link in your email. Click the link and enter your new password.
   that link will be valid to be used only once.

6. If you would like to verify your profile, you will first login, and you will either be in one of three categories (UNVERIFIED,PENDING, VERIFIED), The button to verify your profile will appear on your dashboard if
you are unverified, but it won't appear if your profile is pending (being verified), or if it is already verified.

7. On their dashboard near their name their will see some icons to indicate wether they are verified, UNVERIFIED, or Pending verification by icon red cross for unverified, yellow watch for pending verification, and blue tick for verified


## Admin Usage

1. To log in as an administrator, you simply have to input administrative credentials and the system will automatically redirect your to the admin dashboard for simplicity sake, to try the admin dashboard 
use the following credentials
    ```
	email: sibomanabertrand@gmail.com
	password : CyberSecure2023
    ```
for demo purpose the admin will not be required to provide an OTP(one time password) to login.


2. After the admin login, he will be able to accept the submitted verification request, or reject them, an email will be sent to the user to let them know if they were approved or not.

3. As an administrator, you can view all registered users, verify their identities, and manage user accounts.

## Contributing

Contributions are welcome! Please fork the repository and create a pull request with your changes. For major changes, please open an issue first to discuss what you would like to change.

---

Thank you for using our User Registration
