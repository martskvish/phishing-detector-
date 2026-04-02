#Import falasd and its functions for web development.
#sqlite3 for database interaction.
#werkzeug.security for password hashing and verification.
#datatime for stroing history of scans.

from flask import Flask, render_template, request, redirect, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

#Import funtions from extractor files
from HTML_extraction_analysis import extraxt_html_content, extract_text_from_html, HTMLtext_analysis, SQL_HTML_database_extraction, HTML_tag_analyser
from URL_extraction_analysis import decompose_url, levenshteins_distance_domain, analyse_subdomain_path, protocol_analysis
from EXTRA_factor_detectors import WHOIS_lookup, SSL_certificate_analysis

#Initalizes a flask applicatio and assigns it to the variable app. 
app = Flask(__name__)

#Used to sign/encrypt the session cookie stored in the user's browser so it can't be tampered with
app.secret_key = "3d6f45a5fc12445dbac2f59c3b1c97364"

#Define route for the root URL "/" and associates it with the login function.
#When a user visits the root URL, login function is called and  "login.html" template is rendered whcih is sent back to the user's browser.
@app.route("/")
def login():
    return render_template("login.html")

#Define route for "/login_verify" URL and specifies that it only accepts POST requests.
#When a user submits the login form, the login_verify function is called.
@app.route("/login_verify", methods=["POST"])
def login_verify():

    #Get email and password from the submitted HTML form
    email = request.form.get('email')
    password = request.form.get('password')

    #Initialize coonection to users.db
    Connection = sqlite3.connect("DB/users.db")
    cursor = Connection.cursor() 

    #This SQL command checks if there is a user in the USERS table with the provided email and gets all columns.
    user = cursor.execute("SELECT * FROM USERS WHERE email = ?", (email,)).fetchone()
    Connection.close()

    #If no user is found with the provided credentials, redirect to the login page.
    #If a user is found, redirect to the home page, while storing user_id, username and email safely on server's side.
    if user == None:
        return redirect("/")
    else:
        if check_password_hash(user[3], password):
            session["user_id"] = user[0]
            session["username"] = user[1]
            session["email"] = user[2]
            return redirect("/home")
        else:
            return redirect("/")

#Define route for logout
#When triggered clears session
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

#This defines a route for the /home URL. 
#When user visits the /home URL, home function is called.
#If user is not logged in, they are redirected to the login page.
#If user is logegd in, the home.html template is rendered and the username is passed as a variable to the template.
@app.route("/home")
def home():

    #If user is not logged in, send them back to login page
    if 'user_id' not in session:
        return redirect("/")
    #Renders the home.html template and passes the username and email as variables to the template.
    return render_template("home.html", username=session["username"])


#This defines a route for the /register URL.
#When user visits the /register URL, register function is called.
@app.route("/register")
def register():
    return render_template("signup.html")


#Defines a route for the /add_user URL that accepts POST requests.
#When a user submits the registration form, add_user function is called.
@app.route("/add_user", methods=["POST"])
def add_user():

    #Retrieves the username, email and password from the form data submitted.
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')

    #initializes connection to the SQLite database.
    Connection = sqlite3.connect("DB/users.db")
    cursor = Connection.cursor()

    #Checks if user with provided email already exists.
    ans = cursor.execute("SELECT * FROM USERS WHERE email = ?", (email,)).fetchone()
    
    #If user with provided email and password already exists, close the database connection and render the signup page with an error message.
    if ans is not None:
        return render_template("signup.html", error="Email already exists")
    
    #Generate password hash to protect real password 
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

    if "user_id" not in session:
        return redirect("/")

    #Pass current time and date to time variable.
    #Retrieves the URL from the form data submitted by the user.
    time = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    url = request.form.get('url')

    #Decompose the URL, extract HTML content, extract visible text from the HTML and analyze the text for suspicious words.
    decompose_urld = decompose_url(url)
    unfiltered_HTML = extraxt_html_content(url)
    HTML_text_content = extract_text_from_html(unfiltered_HTML)
    HTML_sus_score, HTML_sus_keywords = HTMLtext_analysis(HTML_text_content, SQL_HTML_database_extraction())
    HTML_DETECTED_TAGS = HTML_tag_analyser(unfiltered_HTML, decompose_urld["domain"])
    Domain_distance = levenshteins_distance_domain(decompose_urld["domain"])
    URL_path_subdomain_analysis = analyse_subdomain_path(decompose_urld["subdomains"],decompose_urld["path"],decompose_urld["query"])
    protocol_score = protocol_analysis(decompose_urld["protocol"])
    WHOIS = WHOIS_lookup(decompose_urld["domain"])

    #calculate overall score.
    total_score = HTML_sus_score + HTML_DETECTED_TAGS[0] + URL_path_subdomain_analysis[3] + protocol_score[1] + Domain_distance[3] + WHOIS[0]
    
    #Compare score to thresholds and classify website
    overall_classification = ""
    if total_score <= 0:
        overall_classification = "Safe"
    elif total_score <= 30:
        overall_classification = "Low Risk"
    elif total_score <= 60:
        overall_classification = "Suspicious"
    elif total_score <= 90:
        overall_classification = "Likely Phishing"
    else:
        overall_classification = "Phishing"
    
    colour_map = {"Safe": "#22c55e", "Low Risk": "#84cc16","Suspicious": "#f59e0b", "Likely Phishing": "#f97316", "Phishing": "#ef4444"}

    #initailize connection.
    Connection = sqlite3.connect("DB/users.db")
    cursor = Connection.cursor()


    #Insert scan data into history table.
    #Get the id of scan which was just automaticaly assigned to row.
    cursor.execute("INSERT INTO history (URL, TIMEDATE, TOTALSCORE, CLASSIFICATION) VALUES (?, ?, ?, ?)", (url, time, total_score, overall_classification))
    scan_id = cursor.lastrowid

    cursor.execute("INSERT INTO user_history_link (user_id, history_id) VALUES (?, ?)", (session["user_id"], scan_id))

    #Commit and update database.
    Connection.commit()
    Connection.close()

    #Renders the scan.html template and passes the decomposed URL, visible text, distance of domain, suspicious words and characters as variables.
    return render_template("scan.html", url=decompose_urld, visible_text=HTML_text_content, HTMLtext_analysis_score=HTML_sus_score, suswords=HTML_sus_keywords,
                           detected_tags=HTML_DETECTED_TAGS, domain_distance = Domain_distance, path_subdomain_analysis = URL_path_subdomain_analysis, total_score=total_score,
                           protocol=protocol_score, web_classification = overall_classification, whois_reassons_score = WHOIS)

@app.route("/history",  methods=["GET"])
def scan_history():

    #Check if user is logged in and session has user_id, to stop unauthorized access.
    if "user_id" not in session:
        return redirect("/")
    

    #Initaliaze connection to user database
    Connection = sqlite3.connect("DB/users.db")
    cursor = Connection.cursor()

    #Fetch all IDs of past scans which have provided user_id associated
    history_ids = cursor.execute("SELECT history_id FROM user_history_link WHERE user_id = ?", (session["user_id"],)).fetchall()

    #Turn outputed tuple from sql query to list
    result = []
    for index in history_ids:
        result.append(index[0])

    #Append every scan corresponding to extracted scan IDs
    scans = []
    for i in result:    
        scan_data= cursor.execute("SELECT * FROM history WHERE id = ?", (i,)).fetchone()
        scans.append(scan_data)

    #Renders /history.html and passes scans as list reversed to show newest scan first.
    return render_template("/history.html", scans_list= scans[::-1])

#Run the Flask application.
#With debug mode on to get more info about errors/bugs.
if __name__ == "__main__":
    app.run(debug=True)