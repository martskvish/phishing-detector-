#import falasd and its functions for web development
#sqlite3 for database interaction
#random for generating a random secret key.

from flask import Flask, render_template, request, redirect
import sqlite3
# import random

#initalizes a flask applicatio and assigns it to the variable app. 
app = Flask(__name__)

# app.secret_key = str(random.randint(1, 40))


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
    user = cursor.execute("SELECT * FROM USERS WHERE email = ? AND password = ?", (email, password)).fetchall()
    Connection.close()

    #If no user is found with the provided credentials, redirect to the login page.
    #If a user is found, redirect to the home page.
    if len(user) == 0:
        return redirect("/")
    else:
        username = user[0][1]
        return redirect(f"/home?username={username}&email={email}")
    

#This defines a route for the /home URL. 
#When user visits the /home URL, home function is called.
#Retrieves username and email from the query parameters in the URL using request.args.get()
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

    #Retrieves the username, email, and password from the form data submitted
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')

    #initializes connection to the SQLite database
    Connection = sqlite3.connect("users.db")
    cursor = Connection.cursor()

    #Checks if user with provided email and password already exists
    ans = cursor.execute("SELECT * FROM USERS WHERE email = ? AND password = ?", (email, password)).fetchall()
    
    #If user with provided email and password already exists, redirect to the login page
    if len(ans) > 0:
        Connection.close()
        return render_template("login.html")
    
    #If user does not exist, insert new user into the USERS table with the provided username, email, and password.
    else:
        cursor.execute("INSERT INTO USERS (username, email, password) VALUES (?, ?, ?)", (username, email, password))
    
    
    Connection.commit()
    Connection.close()

    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True)