# Welcome to Our User Registration and Authentication System

## Demo

You can see a live demo of the project here: [Demo Link](https://user-account-mgt.herokuapp.com/)


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

Welcome to our web application. If you're accessing it locally, the application is available at http://localhost:5000.

1. **Account Registration:** Begin by clicking on the "Register" button to set up a new account. Please ensure that you fill out all required fields, including the upload of your profile picture, as this is mandatory during the registration process.

2. **Email Verification:** After registering, you will receive an email with a verification link. Please click on this link to confirm your email address. This verification step is essential for the security of your account.

3. **Logging In:** Upon verification, you may log in using your registered email and password. Note that for added security, our system will send an OTP (One-Time Password) to your email each time you attempt to log in. Please ensure your email address is valid and accessible. The OTP will expire after 5 minutes, and you are allowed up to 3 attempts to input the correct OTP.

4. **Password Recovery:** In case you forget your password, simply click on the "Forgot Password" button on the login page. Enter your email address and click "Reset Password". You will receive an email with a one-time use link to reset your password.

5. **Profile Verification:** Once logged in, you may wish to verify your profile. Depending on your account status, you will fall into one of three categories: UNVERIFIED, PENDING, or VERIFIED. If your account is unverified, a verification button will be available on your dashboard. This button will not be visible if your profile is pending verification or has already been verified.

6. **Verification Status Indicators:** To easily ascertain your verification status, you will see an icon next to your name on your dashboard: a red cross signifies an unverified account, a yellow watch indicates a pending verification, and a blue tick denotes a verified account.

Thank you for choosing our application. We look forward to providing you with a secure and user-friendly experience.

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
    RECAPTCHA_SECRET_KEY = YOUR_GOOGLE_RECAPTCHA_SECRET_KEY
    RECAPTCHA_SITE_KEY = YOUR_SITE_RECAPTCHA_KEY
    
    ```

    Replace `your_secret_key`, `your_security_password_salt`, `YOUR_SENDGRID_API_KEY`, and `YOUR_URI` with your own values.

5. Run the application with `python main.py`.

## Usage Guide

1. Open the application in your web browser. If running locally, it will be at `http://localhost:5000` locally or https://user-account-mgt.herokuapp.com/

2. Click "Register" to create a new account. Fill out all the required fields. Upload yout profile picture, as it is required during registration

3. Check your email for a verification link. Click the link to verify your email. ( Remember to check your spam folder, and Promotion, email will appear to be from "prochatapp@sgeneratorapp.online)

4. Once verified, you can log in using your email and password, the system will send you an OTP each time you try to login so make sure your email is valid also the user will have 5 minutes to provide that OTP
   else it will expire and they will have to request a new one, also they will have 3 Attempts to give a valid OTP.

5. If you forget your password, click "Forgot Password" on the login page. Enter your email and click "Reset Password". You'll receive a password reset link in your email. Click the link and enter your new password.
   that link will be valid to be used only once.

6. If you would like to verify your profile, you will first login, and you will either be in one of three categories (UNVERIFIED,PENDING, VERIFIED), The button to verify your profile will appear on your dashboard if
you are unverified, but it won't appear if your profile is pending (being verified), or if it is already verified.

7. On their dashboard near their name their will see some icons to indicate wether they are verified, UNVERIFIED, or Pending verification by icon red cross for unverified, yellow watch for pending verification, and blue tick for verified


## Admin Usage

1. Administrative Login: To access the administrative interface, you'll need to use the dedicated administrative credentials. Upon successful login, you will be automatically redirected to the admin dashboard. For demonstration purposes, please use the following credentials:
    ```
	email: sibomanabertrand@gmail.com
	password : CyberSecure2023
    ```
Please note that, unlike regular user accounts, the administrative account does not require OTP (One-Time Password) authentication for login, simplifying the process.


2. Admin Dashboard and Permissions: Once logged in as an administrator, you have access to several advanced features. This includes the ability to review and process verification requests. Upon a decision on a verification request, an automated email will be sent to the respective user, communicating whether their request was approved or denied.

3. User Management: As an administrator, you have a comprehensive view of all users that requested verification. This allows for efficient identity verification and streamlined management of user accounts.

## Contributing

Contributions are welcome! Please fork the repository and create a pull request with your changes. For major changes, please open an issue first to discuss what you would like to change.

---

Thank you for using our User Registration
