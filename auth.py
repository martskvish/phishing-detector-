#smtplib is a built in Python library for sending emails using the Simple Mail Transfer Protocol (SMTP).
#email.mime.text is a library for craeting email messages with text conetnt. (MIME stands for Multipurpose Internet Mail Extensions)
#os for interacting with the operating system, such as accessing environment variables.
#random for generating random numbers, which is used here to create a one-time password (OTP).
#dotenv for loading environment variables from a .env file.

import smtplib
from email.mime.text import MIMEText
import os
import random
from dotenv import load_dotenv
from paths import CREDS_ENV_PATH

#Load enviromantal variables form .env file.
#Storing sensitive info in .env file and loading them using python-dotenv is a good practice to keep them secure and separate from the codebase.
load_dotenv(CREDS_ENV_PATH)

#Define function to generate random 6 digit value from 100000 to 999999 as OTP.
def gen_otp():
    otp = random.randint(100000, 999999)
    return otp

#Define function to send OTP to user's email using SMTP protocol.
def send_otp(email, otp):

    #Define email and password to login to email account.
    #Retrive email and password from environment variables for security.
    origin = os.getenv("EMAIL_USER")
    passw = os.getenv("EMAIL_PASS")

    #Define message to be sent to user's email addres with the generated OTP.
    mail = MIMEText(f"YOUR one time password is:  {otp}")
    mail["subject"] = "Verification Code For Phishing Detector"
    mail["from"] = origin
    mail["to"] = email

    #Open connection to SMTP server, start TLS for security, login using credentials and send the generated emil to user's email address.
    #After close connection to SMTP server.
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(origin, passw)
    server.send_message(mail)

    server.quit()

