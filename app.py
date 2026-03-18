#import falasd and its functions for web development
#sqlite3 for database interaction
#werkzeug.security for password hashing and verification

from flask import Flask, render_template, request, redirect
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from bs4 import BeautifulSoup

#import funtions from extractor files
from HTML_extraction_analysis import extraxt_html_content, extract_text_from_html, HTMLtext_analysis, SQL_HTML_database_extraction, HTML_tag_analyser
from URL_extraction_analysis import decompose_url


#initalizes a flask applicatio and assigns it to the variable app. 
app = Flask(__name__)


#define route for the root URL ("/") and associates it with the login function.
#When a user visits the root URL, login function is called and  "login.html" template is rendered whcih is sent back to the user's browser.
@app.route("/")
def login():
    return render_template("login.html")

#define route for "/login_verify" URL and specifies that it only accepts POST requests.
#When a user submits the login form, the login_verify function is called.
@app.route("/login_verify", methods=["POST"])
def login_verify():
    email = request.form.get('email')
    password = request.form.get('password')

    Connection = sqlite3.connect("users.db")
    cursor = Connection.cursor() 

    #This SQL command checks if there is a user in the USERS table with the provided email and password.
    user = cursor.execute("SELECT * FROM USERS WHERE email = ?", (email,)).fetchone()
    Connection.close()

    #If no user is found with the provided credentials, redirect to the login page.
    #If a user is found, redirect to the home page.
    if user == None:
        return redirect("/")
    else:
        if check_password_hash(user[3], password):
            username = user[1]
            return redirect(f"/home?username={username}&email={email}")
        else:
            return redirect("/")

#This defines a route for the /home URL. 
#When user visits the /home URL, home function is called.
#request.args.get() Retrieves username and email from the query parameters in the URL.
@app.route("/home")
def home():
    username = request.args.get('username')
    email = request.args.get('email')

    #Renders the home.html template and passes the username and email as variables to the template.
    return render_template("home.html", username=username, email=email)


#This defines a route for the /register URL.
#When user visits the /register URL, register function is called.
@app.route("/register")
def register():
    return render_template("signup.html")


#Defines a route for the /add_user URL that accepts POST requests.
#When a user submits the registration form, add_user function is called.
@app.route("/add_user", methods=["POST"])
def add_user():

    #Retrieves the username, email, and password from the form data submitted.
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')

    #initializes connection to the SQLite database.
    Connection = sqlite3.connect("users.db")
    cursor = Connection.cursor()

    #Checks if user with provided email already exists.
    ans = cursor.execute("SELECT * FROM USERS WHERE email = ?", (email,)).fetchone()
    
    #If user with provided email and password already exists, close the database connection and render the signup page with an error message.
    if ans is not None:
        return render_template("signup.html", error="Email already exists")
    
    password_hash = generate_password_hash(password)
    
    #If user does not exist, insert new user into the USERS table with the provided username, email, and password.
    cursor.execute("INSERT INTO USERS (username, email, password) VALUES (?, ?, ?)", (username, email, password_hash))
    
    
    Connection.commit()
    Connection.close()

    #Redirect to the login page after successful registration.
    return redirect("/")

#Defines a route for the /scan URL that accepts POST requests.
@app.route("/scan", methods=["POST"])
def scan():
    #Retrieves the URL from the form data submitted by the user.
    url = request.form.get('url')

    #Decompose the URL, extract HTML content, extract visible text from the HTML and analyze the text for suspicious words.
    decompose_urld = decompose_url(url)
    unfiltered_HTML = extraxt_html_content(url)
    HTML_text_content = extract_text_from_html(unfiltered_HTML)
    HTML_suswords = HTMLtext_analysis(HTML_text_content, SQL_HTML_database_extraction())
    HTML_DETECTED_TAGS = HTML_tag_analyser(unfiltered_HTML, decompose_urld['domain'])

    #Renders the scan.html template and passes the decomposed URL and visible text as variables.
    return render_template("scan.html", url=decompose_urld, visible_text=HTML_text_content, suswords=HTML_suswords, detected_tags=HTML_DETECTED_TAGS)

#run the Flask application in debug mode.
if __name__ == "__main__":
    app.run(debug=True)