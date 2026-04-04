import smtplib
from email.mime.text import MIMEText
import os
import random
from dotenv import load_dotenv

#Load enviromantal variables form .env file.
load_dotenv("creds.env")

def gen_otp():
    otp = random.randint(100000, 999999)
    return otp

def send_otp(email, otp):
    origin = os.getenv("EMAIL_USER")
    passw = os.getenv("EMAIL_PASS")

    mail = MIMEText(f"YOUR one time password is:  {otp}")
    mail["subject"] = "Verification Code For Phishing Detector"
    mail["from"] = origin
    mail["to"] = email

    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(origin, passw)
    server.send_message(mail)

    server.quit()

