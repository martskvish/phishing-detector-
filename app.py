#Import falasd and its functions for web development.
#sqlite3 for database interaction.
#werkzeug.security for password hashing and verification.
#datatime for storing history of scans.
#dotenv for loading environment variables from a .env file.
#os for interacting with files and environment variables on the operating system.
#csv for ecporting scan history to a CSV file.
#io module used to create file-like objects in memeory. no need to create a physical file on disk.
#fpdf for generating pdf report of scans.
#secrets to generate random API key for use. 

from flask import Flask, render_template, request, redirect, send_file, session, Response, stream_with_context
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from dotenv import load_dotenv
import os
import csv
import io
from fpdf import FPDF
import secrets

#Import funtions from extractor files
from HTML_extraction_analysis import extraxt_html_content, extract_text_from_html, HTMLtext_analysis, SQL_HTML_database_extraction, HTML_tag_analyser, HTML_code_jaccard
from URL_extraction_analysis import decompose_url, levenshteins_distance_domain, analyse_subdomain_path, protocol_analysis, host_location
from EXTRA_factor_detectors import WHOIS_lookup, SSL_certificate_analysis, Openphish_API, COMP_DB_URL
from auth import gen_otp, send_otp

#Load enviromantal variables form .env file.
load_dotenv("creds.env")

#Initalizes a flask applicatio and assigns it to the variable app. 
app = Flask(__name__)

#For keep second copy of scan IDs. 
current_scan_ids = {}

#Used to sign/encrypt the session cookie stored in the user's browser so it can't be tampered with.
#Generates a random 32 byte hexadecimal string, making program more secure and less vulnerable to session hijacking.
app.secret_key = os.getenv("SECRET_KEY")

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
            session["settings_previous_scan_period"] = user[4]
            return redirect("/home")
        else:
            return redirect("/")

#Define route for logout
#When triggered clears session to remove all stored user data and redirect user to the login page. 
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
    Connection.close()
    
    #If user with provided email and password already exists, close the database connection and render the signup page with an error message.
    if ans is not None:
        return render_template("signup.html", error="Email already exists")
    
    #Generate password hash to protect real password.
    session["password_hash"] = generate_password_hash(password)

    #Store username and email in session.
    session["username"] = username
    session["email"] = email

    #Generate a one time password and expiration time for th OTP with 3 minute duration starting form the moment of generation in ISO format for easy comparison later on.
    session["otp"] = gen_otp()

    #Print OTP temproraly for easier user creation.
    print(f"current users's OTP {session["otp"]}")

    session["otp_exp"] = (datetime.datetime.now() + datetime.timedelta(minutes=3)).isoformat()

    #Use the send_otp function to send the generated OTP to the user's email address.
    send_otp(email, session["otp"])

    #Redirect to the login page after successful registration.
    return redirect("verify_user")

@app.route("/verify_user", methods=["GET", "POST"])
def verify_user():

    #If there is no OTP in the session, registartion has not been completed, return user to signup_page.
    if "otp" not in session:
        return redirect("/signup")
    
    #Else if there is an OTP in the session and user submits the form, check if OTP is correct and not expired.
    #If OTP is expired, render the auth.tml with error message.
    #If OTP is correct, add user to database and redirect to home page.
    if request.method == "POST":

        #Compare current time with OTP expirtion time stored in session using ISO format for easy comparison.
        if datetime.datetime.now() > datetime.datetime.fromisoformat(session["otp_exp"]):
            return render_template("auth.html", error="One Time Password has expired. Try again")
        
        if session["otp"] == int(request.form.get("otp")):
            connect = sqlite3.connect("DB/users.db")
            cursor = connect.cursor()

            #Insert user detail into USERS table.
            cursor.execute("INSERT INTO USERS (username, email, password) VALUES (?, ?, ?)", (session["username"], session["email"], session["password_hash"]))

            #Commit and close connection to database.
            connect.commit()
            connect.close()
        
            return redirect("/")
        
        return render_template("auth.html", error = "Incorrect One Time passcode. Try again")
    
    return render_template("auth.html")
        

#Defines a route for the /scan URL that accepts POST requests.
@app.route("/scan", methods=["POST"])
def scan():

    #Check user in session.
    if "user_id" not in session:
        return redirect("/")

    url = request.form.get('url')

    def stream_scan():
        #Pass current time and date to time variable.
        #Retrieves the URL from the form data submitted by the user.
        time = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        yield "data: Starting scan\n\n"
        
        Connection = sqlite3.connect("DB/users.db")
        cursor = Connection.cursor()

        #Check if URL has already been scanned.
        #Cursor executes a SQL command to select the id and TIMEDATE of the most recent scan of the provided URL from the history table.
        #ORDER BY id DESC LIMIT 1 orders the results by id in descending order and limits the result to 1 row, retrieving only most recent scan.
        exist = cursor.execute("SELECT id, TIMEDATE FROM history WHERE URL = ? ORDER BY id DESC LIMIT 1",(url,)).fetchone()
        exist_url = False

        Connection.commit()
        Connection.close()

        #If URL has been scanned before, check if the scan is less than 3 days old. 
        #If it is set exist_url to True, if not set exist_url to False to trigger a new scan and update the database with new scan data.
        if exist:
            scan_time = datetime.datetime.strptime(exist[1], "%d-%m-%Y %H:%M:%S")
            if (datetime.datetime.now() - scan_time).days < session["settings_previous_scan_period"]:
                exist_url = True
            else:
                exist_url = False
            
        if not exist_url:

            #Updtate Openphish feed.
            Openphish_API()

            #Decompose the URL, extract HTML content, extract visible text from the HTML and analyze the text for suspicious words and analyse HTML tags.
            #Analyse URL's domain, subdomain with levenshtein distance, path and query for suspicious elements, and check protocol.
            #Yield allows to send data to the frontend in real time as each step of the scan is completed.
            #Yield allows function to return a value without exiting.

            yield "data: Starting scan\n\n"
            yield "data: Decomposing URL\n\n" 
            decompose_urld = decompose_url(url)
            yield "data: Extracting and analysing HTML content\n\n"
            unfiltered_HTML = extraxt_html_content(url)
            HTML_text_content = extract_text_from_html(unfiltered_HTML)
            HTML_sus_score, HTML_sus_keywords = HTMLtext_analysis(HTML_text_content, SQL_HTML_database_extraction())
            HTML_DETECTED_TAGS = HTML_tag_analyser(unfiltered_HTML, decompose_urld["domain"])
            yield "data: Analysing domain, subdomain, path and protocol\n\n"
            Domain_distance = levenshteins_distance_domain(decompose_urld["domain"])
            URL_path_subdomain_analysis = analyse_subdomain_path(decompose_urld["subdomains"],decompose_urld["path"],decompose_urld["query"])
            protocol_score = protocol_analysis(decompose_urld["protocol"])
            yield "data: Performing WHOIS lookup\n\n"
            WHOIS = WHOIS_lookup(decompose_urld["domain"])
            yield "data: Analysing SSL certificate\n\n"
            SSL_certificate = SSL_certificate_analysis(url)
            yield "data: Extracting IP information\n\n"
            IP_address, IP_country, IP_city = host_location(decompose_urld["domain"])
            yield "data: Comparing domain with phishing domain list\n\n"
            COMP_DB_URL_result = COMP_DB_URL(decompose_urld["domain"])

            #Set IN_database flag as True if domain was found in the phishing database.
            if COMP_DB_URL_result[0] == 100:
                IN_database = True
            else:
                IN_database = False

            #Check if the closest domain found starts with http:// or https://, if not add https://.
            if not Domain_distance[0].startswith(("http://", "https://")):
                closest_domain_url = "https://" + Domain_distance[0]
            else:
                closest_domain_url = Domain_distance[0]
            similar_HTML = extraxt_html_content(closest_domain_url)
            jaccard_similarity = HTML_code_jaccard(unfiltered_HTML,similar_HTML,Domain_distance[1])

            #Calculate overall score.
            total_score = HTML_sus_score + HTML_DETECTED_TAGS[0] + URL_path_subdomain_analysis[3] + protocol_score[1] + Domain_distance[3] + WHOIS[0] + SSL_certificate[0] + jaccard_similarity[2] + COMP_DB_URL_result[0]

            #Compare score to thresholds and classify website.
            #Define color variables to improve visual appeal of the scan resul page.
            overall_classification = ""
            if total_score <= 0:
                overall_classification = "Safe"
                colour = "#22c55e"
            elif total_score <= 30:
                overall_classification = "Low Risk"
                colour = "#84cc16"
            elif total_score <= 60:
                overall_classification = "Suspicious"
                colour = "#ebd218"
            elif total_score <= 90:
                overall_classification = "Likely Phishing"
                colour = "#f97316"
            else:
                overall_classification = "Phishing"
                colour = "#ef4444"

            #As scanning takes time to reduce risk of DB errors open connection later.
            Connection = sqlite3.connect("DB/users.db")
            cursor = Connection.cursor()

            #Insert scan data into history table.
            #", ".join(str(t) for t in HTML_DETECTED_TAGS[1]) is used to convert list of detected HTML tags into a comma saparated stirng. Same applies to other list variables. 
            #Get the id of scan which was just automaticaly assigned to row to link scan id with user. 
            cursor.execute("""INSERT INTO history (URL, TIMEDATE, TOTALSCORE, CLASSIFICATION, html_text_score, html_text_keywords,
                            html_tag_score, html_detected_tags, domain_closest, domain_distance, domain_reason, domain_score,
                            subdomain_detected, path_chars, path_words, subdomain_score, protocol_reason, protocol_score,
                            whois_score, whois_reason, whois_nameservers, whois_registrar, ssl_score, ssl_message, Visible_Text, jaccard_similarity, jaccard_reason, jaccard_score, ip_address, ip_country, ip_city, color, In_database)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (url, time, total_score, overall_classification, HTML_sus_score, ", ".join((str(t) for t in HTML_sus_keywords)),
                            HTML_DETECTED_TAGS[0], ", ".join(str(t) for t in HTML_DETECTED_TAGS[1]), Domain_distance[0], Domain_distance[1], Domain_distance[2],
                            Domain_distance[3], ", ".join(str(x) for x in URL_path_subdomain_analysis[0]), ", ".join(str(x) for x in URL_path_subdomain_analysis[1]), ", ".join(str(x) for x in URL_path_subdomain_analysis[2]),
                            URL_path_subdomain_analysis[3], protocol_score[0], protocol_score[1],
                            WHOIS[0], ", ".join(str(r) for r in WHOIS[1]), ", ".join(str(r) for r in WHOIS[2]), WHOIS[3], SSL_certificate[0], SSL_certificate[1], HTML_text_content, jaccard_similarity[0], jaccard_similarity[1], jaccard_similarity[2],
                            IP_address, IP_country, IP_city, colour, IN_database))
            scan_id = cursor.lastrowid

            #Get current year and month to store in statistics table.
            now = datetime.datetime.now()
            year_month = now.strftime("%Y-%m")
            
            #Updtae each month's statistics in the table, coresponding to ovrall classification of the scans performed in the month by all users.
            #Unique constraint on date field allows use of "INSERT OR IGNORE" to insert a new row for the month if it doesn't exist.
            cursor.execute("""INSERT OR IGNORE INTO statistics (date) VALUES (?)""", (year_month,))
            if overall_classification == "Safe":
                cursor.execute("""UPDATE statistics SET Safe = Safe + 1 WHERE date = ?""", (year_month,))
            elif overall_classification == "Low Risk":
                cursor.execute("""UPDATE statistics SET Low_Risk = Low_Risk + 1 WHERE date = ?""", (year_month,))   
            elif overall_classification == "Suspicious":
                cursor.execute("""UPDATE statistics SET Suspicious = Suspicious + 1 WHERE date = ?""", (year_month,))   
            elif overall_classification == "Likely Phishing":
                cursor.execute("""UPDATE statistics SET Likely_Phishing = Likely_Phishing + 1 WHERE date = ?""", (year_month,))
            else:
                cursor.execute("""UPDATE statistics SET Phishing = Phishing + 1 WHERE date = ?""", (year_month,))

            #Link scan ID with user ID in user_history_link table.
            cursor.execute("""INSERT INTO user_history_link (user_id, history_id) VALUES (?, ?)""", (session["user_id"], scan_id))

            Connection.commit()
            Connection.close()

            current_scan_ids[session["user_id"]] = scan_id
            session["curr_scan_id"] = scan_id
        else:
            #Initializes connection to database.
            Connection = sqlite3.connect("DB/users.db")
            cursor = Connection.cursor()

            #If URL has already been scanned, fetch scan data from database and use it to render the scan.html template.
            #id=0, URL=1, TIMEDATE=2, TOTALSCORE=3, CLASSIFICATION=4, html_text_score=5, html_text_keywords=6, html_tag_score=7, html_detected_tags=8, domain_closest=9, domain_distance=10, domain_reason=11, domain_score=12, subdomain_detected=13, path_chars=14, path_words=15, subdomain_score=16, 
            #protocol_reason=17, protocol_score=18, whois_score=19, whois_reason=20, whois_nameservers=21, whois_registrar=22, ssl_score=23, ssl_message=24, Visible_Text=25, jaccard_similarity=26, jaccard_reason=27, jaccard_score=28, ip_address=29, ip_country=30, ip_city=31, colour=32
            scan_data = cursor.execute("SELECT * FROM history WHERE id = ?", (exist[0],)).fetchone()
            decompose_urld = decompose_url(scan_data[1])
            HTML_text_content = scan_data[25]
            HTML_sus_score = scan_data[5]
            HTML_sus_keywords = scan_data[6].split(", ")
            HTML_DETECTED_TAGS = (scan_data[7], scan_data[8].split(", "))
            Domain_distance = (scan_data[9], scan_data[10], scan_data[11], scan_data[12])
            URL_path_subdomain_analysis = (scan_data[13].split(", "), scan_data[14].split(", "), scan_data[15].split(", "), scan_data[16])
            protocol_score = (scan_data[17], scan_data[18])
            WHOIS = (scan_data[19], scan_data[20].split(", "), scan_data[21].split(", "), scan_data[22])
            SSL_certificate = (scan_data[23], scan_data[24])
            total_score = scan_data[3]
            overall_classification = scan_data[4]
            jaccard_similarity = (scan_data[26], scan_data[27], scan_data[28])
            IP_address, IP_country, IP_city = scan_data[29], scan_data[30], scan_data[31]
            colour = scan_data[32]
            IN_database = scan_data[33]

            #Link scan ID with user ID.
            cursor.execute("""INSERT INTO user_history_link (user_id, history_id) VALUES (?, ?)""", (session["user_id"], exist[0]))

            #Store current scan ID in session to be used for PDF function.
            session["curr_scan_id"] = exist[0]
            current_scan_ids[session["user_id"]] = int(exist[0])

            #Commit and update database.
            Connection.commit()
            Connection.close()
        
        #After the scanning process is complete, yield the URL to be used in the frontend to render the scan results page.
        yield "data: DONE\n\n"

    #Stream the output of the scanning process to the frontend in real time using Server-Sent Events (SSE) with the appropriate MIME type for SSE.
    #MIME type "text/event-stream" tells the browser to expect a stream of events, allowing the frontend to update the loading bar.
    return Response(stream_with_context(stream_scan()), mimetype="text/event-stream")

@app.route("/scan_result")
def scan_result():

    #Check user's session.
    if "user_id" not in session:
        return redirect("/")

    #Initialize connection.
    Connection = sqlite3.connect("DB/users.db")
    cursor = Connection.cursor()

    #Assign scan ID from session or from current_scan_ids.
    #If scan ID is not found, redirect to home page.
    scan_id = session.get("curr_scan_id") or current_scan_ids.get(session["user_id"])
    if scan_id is None:
        return redirect("/home")
    
    #Fetch scan data.
    scan_data = cursor.execute("SELECT * FROM history WHERE id = ?", (scan_id,)).fetchone()
    Connection.close()

    #Decompose extracted list and return variables.
    decompose_urld = decompose_url(scan_data[1])
    HTML_text_content = scan_data[25]
    HTML_sus_score = scan_data[5]
    HTML_sus_keywords = scan_data[6].split(", ")
    HTML_DETECTED_TAGS = (scan_data[7], scan_data[8].split(", "))
    Domain_distance = (scan_data[9], scan_data[10], scan_data[11], scan_data[12])
    URL_path_subdomain_analysis = (scan_data[13].split(", "), scan_data[14].split(", "), scan_data[15].split(", "), scan_data[16])
    protocol_score = (scan_data[17], scan_data[18])
    WHOIS = (scan_data[19], scan_data[20].split(", "), scan_data[21].split(", "), scan_data[22])
    SSL_certificate = (scan_data[23], scan_data[24])
    total_score = scan_data[3]
    overall_classification = scan_data[4]
    jaccard_similarity = (scan_data[26], scan_data[27], scan_data[28])
    IP_address, IP_country, IP_city = scan_data[29], scan_data[30], scan_data[31]
    colour = scan_data[32]
    #As SQLITE stores Boolean as 1/0 convetion of value is needed. 
    IN_database = scan_data[33]

    return render_template("scan.html", url=decompose_urld, visible_text=HTML_text_content, HTMLtext_analysis_score=HTML_sus_score, suswords=HTML_sus_keywords,
                           detected_tags=HTML_DETECTED_TAGS, domain_distance = Domain_distance, path_subdomain_analysis = URL_path_subdomain_analysis, total_score=total_score,
                           protocol=protocol_score, web_classification = overall_classification, whois_reassons_score = WHOIS, SSL_reassons_score = SSL_certificate, jaccard_similarity = jaccard_similarity, 
                           ip_address_info=(IP_address, IP_country, IP_city,), web_classification_color=colour, IN_database=IN_database)

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
        scan_data = cursor.execute("SELECT * FROM history WHERE id = ?", (i,)).fetchone()
        scans.append(scan_data)

    #Renders /history.html and passes scans as list reversed to show newest scan first.
    return render_template("/history.html", scans_list= scans[::-1])

@app.route("/export_history", methods=["GET"])
def export_history():
    
    #Check if user is logged in.
    if "user_id" not in session:
        return redirect("/")
    
    #Connect to user database and fetch all scan IDs associated with the user.
    Connection = sqlite3.connect("DB/users.db")
    cursor = Connection.cursor()
    history_ids = cursor.execute("SELECT history_id FROM user_history_link WHERE user_id = ?", (session["user_id"],)).fetchall()

    print(history_ids)
    #Turn outputed tuple from sql query to list.
    #Fetch all scan data corresponding to user's scan IDs.
    #Only append first five items from scan.data.
    result = []
    scans = []
    for index in history_ids:
        result.append(index[0])
    for i in result:    
        scan_data = cursor.execute("SELECT * FROM history WHERE id = ?", (i,)).fetchone()
        scans.append((scan_data[0], scan_data[1], scan_data[2], scan_data[3], scan_data[4]))

    #close connection.
    Connection.commit()
    Connection.close()

    #Creates an empty in-memory text file. (preserve memory usage, initaly was planing to save file on disk and than delete after download).
    #write coresponding id,url,result,date to each row of the CSV file for each scan in scans list.
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "url", "date", "total score", "classification"])
    writer.writerows(scans)

    #Moves the buffer's cursor back to the start.
    output.seek(0)
    
    #Read entire buffer as string and convert it to bytes.
    #io.BtyesIO wraps those bytes in memory bytes buffer which send_file can work with.
    #Define file type as text/csv, set it to be downloaded as an attachment and give it a name based on the user's username.
    return send_file(io.BytesIO(output.getvalue().encode()),mimetype="text/csv",as_attachment=True,download_name=f"{session["username"]}_scan_history.csv")

@app.route("/export_PDF", methods=["GET"])
def export_PDF():
    
    #Check user's login.
    if "user_id" not in session:
        return redirect("/")
    
    #Initialize connection to DB.
    Connection = sqlite3.connect("DB/users.db")
    cursor = Connection.cursor()

    #Extract scan data from for the scan ID that is stored in session.
    #Decompose extracted list into variables for easier use later on.
    scan_data = cursor.execute("SELECT * FROM history WHERE id = ?", (current_scan_ids[session["user_id"]],)).fetchone()
    decompose_urld = decompose_url(scan_data[1])
    HTML_text_content = scan_data[25]
    HTML_sus_score = scan_data[5]
    HTML_sus_keywords = scan_data[6].split(", ")
    HTML_DETECTED_TAGS = (scan_data[7], scan_data[8].split(", "))
    Domain_distance = (scan_data[9], scan_data[10], scan_data[11], scan_data[12])
    URL_path_subdomain_analysis = (scan_data[13].split(", "), scan_data[14].split(", "), scan_data[15].split(", "), scan_data[16])
    protocol_score = (scan_data[17], scan_data[18])
    WHOIS = (scan_data[19], scan_data[20].split(", "), scan_data[21].split(", "), scan_data[22])
    SSL_certificate = (scan_data[23], scan_data[24])
    total_score = scan_data[3]
    overall_classification = scan_data[4]
    jaccard_similarity = (scan_data[26], scan_data[27], scan_data[28])
    IP_address = (scan_data[29], scan_data[30], scan_data[31])
    IN_database = scan_data[33]

    #Create a PDF object, Add a page and Set font.
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    
    #Error: UnicodeEncodeError: 'latin-1' codec can't encode character '\u2018' in position 83: ordinal not in range(256)
    #Unicode chars can't be encoded with latin-1
    def clean_text(text):
        #Check if text is empty.
        if text is None:
            return ""

        #Define characters that may cause problem FPDF.
        #problematic unicode char : replacment.
        #Used ai to generate possible problematic chars
        replacements = {"\u2018": "'", "\u2019": "'", "\u201c": '"',"\u201d": '"', "\u2013": "-", "\u2014": "-", "\u2026": "...", }

        #Turn text into string
        text = str(text)

        #Loop through items in dictionary, whilie difining key and item.
        #Replace problematic characters.
        for old, new in replacements.items():
            text = text.replace(old, new)

        #Make text safer by replacing unsuppoerted chars insted of causing error. 
        return text.encode("latin-1", "replace").decode("latin-1")

    #Function to turn titles into bold and bigger font.
    def heading(text):
        pdf.set_font("Arial", style = "B", size=13)
        pdf.multi_cell(0, 8, txt=clean_text(text))

    #Function for normal text, set font back to normal and smaller size.
    def row(text):
        pdf.set_font("Arial", size=11)
        pdf.multi_cell(0, 7, txt=clean_text(text))

    #Write scan report to PDF, using the defined functions to format the text and make it more visually appealing.
    #ln(2) adds a line break of 2 units to create space between sections.
    #If text is too long, multi_cell() wraps it onto the next line.
    pdf.set_font("Arial", style="B", size=16)
    pdf.multi_cell(0, 10, txt=f"Scan Report for {decompose_urld}", align='C')
    pdf.set_font("Arial", size=11)
    pdf.multi_cell(0, 7, txt=f"Scan Date: {scan_data[2]}")
    pdf.multi_cell(0, 7, txt=f"Overall Classification: {overall_classification}")
    pdf.multi_cell(0, 7, txt=f"Total Score: {total_score}")
    pdf.ln(2)
    heading("URL Decomposition:")
    row(f"  - Protocol: {decompose_urld['protocol']}")
    row(f"  - Domain: {decompose_urld['domain']}")
    row(f"  - Subdomains: {', '.join(decompose_urld['subdomains'])}")
    row(f"  - Path: {decompose_urld['path']}")
    row(f"  - Query: {decompose_urld['query']}")
    pdf.ln(2)
    heading("HTML Text Analysis:")
    row(f"  - Suspicious Score: {HTML_sus_score}")
    row(f"  - Suspicious Keywords: {', '.join(HTML_sus_keywords)}")
    row(f"  - Jaccard Similarity: {jaccard_similarity[0]}")
    row(f"  - Jaccard Reason: {jaccard_similarity[1]}")
    row(f"  - Jaccard Score: {jaccard_similarity[2]}")
    pdf.ln(2)
    heading("HTML Tag Analysis:")
    row(f"  - Suspicious Score: {HTML_DETECTED_TAGS[0]}")
    row(f"  - Detected Tags: {', '.join(HTML_DETECTED_TAGS[1])}")
    pdf.ln(2)
    heading("Domain Analysis:")
    row(f"  - Closest Legitimate Domain: {Domain_distance[0]}")
    row(f"  - Levenshtein Distance: {Domain_distance[1]}")
    row(f"  - Reason: {Domain_distance[2]}")
    row(f"  - Domain Score: {Domain_distance[3]}")
    pdf.ln(2)
    heading("Subdomain and Path Analysis:")
    row(f"  - Detected Subdomains: {', '.join(URL_path_subdomain_analysis[0])}")
    row(f"  - Suspicious Characters in Path: {', '.join(URL_path_subdomain_analysis[1])}")
    row(f"  - Suspicious Words in Path: {', '.join(URL_path_subdomain_analysis[2])}")
    row(f"  - Subdomain and Path Score: {URL_path_subdomain_analysis[3]}")
    pdf.ln(2)
    heading("Protocol Analysis:")
    row(f"  - Protocol Used: {protocol_score[0]}")
    row(f"  - Protocol Score: {protocol_score[1]}")
    pdf.ln(2)
    heading("WHOIS Analysis:")
    row(f"  - WHOIS Score: {WHOIS[0]}")
    row(f"  - WHOIS Reasons: {', '.join(WHOIS[1])}")
    row(f"  - WHOIS Nameservers: {', '.join(WHOIS[2])}")
    row(f"  - WHOIS Registrar: {WHOIS[3]}")
    pdf.ln(2)
    heading("SSL Certificate Analysis:")
    row(f"  - SSL Score: {SSL_certificate[0]}")
    row(f"  - SSL Message: {SSL_certificate[1]}")
    pdf.ln(2)
    heading("Host Location Analysis:")
    row(f"  - IP Address: {IP_address[0]}")
    row(f"  - Country: {IP_address[1]}")
    row(f"  - City: {IP_address[2]}")
    heading("Comparison with Phishing Database:")
    row(f"  - In Database: {'Yes (score +100)' if IN_database else 'No'})")
    pdf.ln(2)
    heading("Visible Text:")
    row(f"{HTML_text_content}")

    #Create PDF and convert it inot bytes so flask can send it as downlaodable file. 
    pdf_bytes = pdf.output(dest="S").encode("latin-1")
    #Pass the generated PDF as bytes to send file, set the file type and name for download. 
    return send_file(io.BytesIO(pdf_bytes),mimetype="application/pdf",as_attachment=True,download_name=f"{session["username"]}_scan_report.pdf")
    
@app.route("/stats", methods=["GET", "POST"])
def stats():
    #Check user's login.
    if "user_id" not in session:
        return redirect("/")
    
    #Initailize connection.
    Connection = sqlite3.connect("DB/users.db")
    cursor = Connection.cursor()

    #Fetch all date columns from the statistics table.
    dates = cursor.execute("SELECT date FROM statistics").fetchall()
     
    #Turn outputed tuple into list for better string handling.
    result = []
    for index in dates:
        result.append(index[0])

    #Get the current date selected and load stats for that month.
    year = request.form.get("year")
    statss = cursor.execute("SELECT * FROM statistics WHERE date = ?", (year,)).fetchone()

    
    #If submit buttun pressed (post method) calculate total scans.
    #Else if redirected to page (get method) make total NONE. 
    if request.method == "POST": 
        
        #Calculate total amount of scans.
        #Statss ouptut (1, '2026-04', 7, 2, 1, 0, 0)
        total = 0 
        for i in range(2, len(statss)):
            total = total + int(statss[i])

    else:
        total = None
    
    #Commit and close connection.
    Connection.commit()
    Connection.close()

    return render_template ("stats.html", stats=statss, date=year, year=result, total_scans=total)
    
@app.route("/settings", methods=["GET", "POST"])
def settings():
    #Check user's login.
    if "user_id" not in session:
        return redirect("/")
    
    #If user submits form.
    if request.method == "POST":

        form_type = request.form.get("form_type")

        print(form_type)

        if form_type == "change_password":
            #Get old and new passwords from form.
            old_password = request.form.get("old_password")
            new_password = request.form.get("new_password")

            #Initalize connection. 
            Connection = sqlite3.connect("DB/users.db")
            cursor = Connection.cursor()

            #Fetch user's current password hash from database to verify old password.
            user_password = cursor.execute("SELECT password FROM users WHERE id = ?", (session["user_id"],)).fetchone()
            Connection.close()

            #Check if the provided old password matches the stored password hash using check_password_hash.
            if check_password_hash(user_password[0], old_password):
                new_password_hash = generate_password_hash(new_password)

                #Connect to DB.
                Connection = sqlite3.connect("DB/users.db")
                cursor = Connection.cursor()

                #Update the user's password in the database with the new password hash.
                cursor.execute("UPDATE users SET password = ? WHERE id = ?", (new_password_hash, session["user_id"]))

                #Commit the changes and close the connection.
                Connection.commit()
                Connection.close()

            #Retrun settings.html with approptiate message. 
                return render_template("settings.html", message = "Password updated successfully", username = session["username"])
            else:
                return render_template("settings.html", message = "Incorrect current password. Try again.", username = session["username"])
            
        elif form_type == "previous_scan_period":

            #Get new scan period from form.
            new_scan_period = request.form.get("new_scan_period")


            #Connect to DB.
            Connection = sqlite3.connect("DB/users.db")
            cursor = Connection.cursor()

            #Update the user's preferred scan period in the database.
            cursor.execute("UPDATE users SET settings_previous_scan_period = ? WHERE id = ?", (new_scan_period, session["user_id"]))

            #Commit and close the connection.
            Connection.commit()
            Connection.close()

            #Update local session variable.
            session["settings_previous_scan_period"] = int(new_scan_period)
        
        elif form_type == "generate_api_key":

        #-------------------ADD HASHING AND ENCRYPTION OF API KEY-------------------#

            #Connect to DB.
            Connection = sqlite3.connect("DB/users.db")
            cursor = Connection.cursor()    

            #Fetch the user's existing API key.
            API_key = cursor.execute("SELECT API_KEY FROM users WHERE id = ?", (session["user_id"],)).fetchone()

            #If API key exists, return it to the user.
            #If not, generate a new API key, and store it in the database. 
            if API_key[0] is not None:
                print(API_key[0])
                return render_template("settings.html", username = session["username"], message_api = "API key already generated", key = API_key[0])
            else: 
                API_key = secrets.token_hex(36)
                cursor.execute("UPDATE users SET API_KEY = ? WHERE id = ?", (API_key, session["user_id"]))

            #Close conncetion to database. 
            Connection.commit()
            Connection.close()
            
            return render_template("settings.html", username = session["username"] ,message_api = "API key has been generated", key = API_key)
    
    return render_template("settings.html", username = session["username"])

@app.route("/delete_account", methods=["POST", "GET"])
def delete_account():
    #Check user's login.
    if "user_id" not in session:
        return redirect("/")
    
    #Get user's response from the confirmation prompt in the frontend.
    confirmed = request.args.get("confirmed")

    #If user confirms account deletion, delete the user's account and associated history data from the database for privacy and security reasons.
    if confirmed == "true":
        
        connect = sqlite3.connect("DB/users.db")
        cursor = connect.cursor()

        cursor.execute("DELETE FROM users WHERE id = ?", (session["user_id"],))
        cursor.execute("DELETE FROM user_history_link WHERE user_id = ?", (session["user_id"],))


        connect.commit()
        connect.close()

        return render_template("login.html", message = "Account deleted successfully.")


#Run the Flask application.
#With debug mode on to get more info about errors/bugs.
if __name__ == "__main__":
    app.run(debug=True)
