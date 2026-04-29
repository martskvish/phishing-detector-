
#Imports Python’s SQLite database module. 
import sqlite3

#Opens a connection to a SQLite database file named "users.db". If the file does not exist, it will be created. 
#The connection object is stored in the variable connection. Establishes a connection so Python can send SQL commands.
#A cursor allows the program to execute SQL commands.
connection = sqlite3.connect("DB/users.db")
cursor = connection.cursor()

#Command tells the database to create a table called USERS. Table will have three columns: id, username, email, password and historyID.
#Id column is set as the primary key, which means it must be unique for each user. 
#Password column is also set to not allow null values.
cmd1 = """CREATE TABLE IF NOT EXISTS USERS (id INTEGER PRIMARY KEY AUTOINCREMENT, username, email, password varchar(50) NOT NULL)"""

#Sends the SQL command to SQLite.
cursor.execute(cmd1)


#Command tells the database to create a table called USERS. Table will have three columns: id, URL, TIMEDATE and TOTALSCORE.
'''
To improve efficiency, the system stores previous scan results in the SQL database.
If a URL has been scanned recently, the program retrieves stored results instead of repeating all phishing detection algorithms.
However, because website content may change over time, a cache expiry period of 3 days is used. After this period, the system performs a fresh scan and updates the database.
'''

cmd2 = """CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY AUTOINCREMENT, URL, TIMEDATE, TOTALSCORE, CLASSIFICATION,
           html_text_score INTEGER, html_text_keywords TEXT, html_tag_score	INTEGER, html_detected_tags	TEXT, domain_closest TEXT,
            domain_distance REAL, domain_reason TEXT, domain_score INTEGER, subdomain_detected	TEXT, path_chars TEXT, path_words TEXT,
            subdomain_score INTEGER, protocol_reason TEXT, protocol_score INTEGER, whois_score INTEGER, whois_reason TEXT, 
            whois_nameservers TEXT, whois_registrar TEXT, ssl_score INTEGER, ssl_message TEXT, Visible_Text TEXT, jaccard_similarity REAL, jaccard_reason TEXT, jaccard_score INTEGER)"""
cmd3 = """CREATE TABLE IF NOT EXISTS user_history_link (id INTEGER PRIMARY KEY AUTOINCREMENT, 
           user_id INTEGER NOT NULL, history_id INTEGER NOT NULL)"""
cmd4 = """CREATE TABLE IF NOT EXISTS statistics (id INTEGER PRIMARY KEY AUTOINCREMENT, date, Safe INTEGER, Low_Risk INTEGER, Suspicious INTEGER, Likely Phishing INTEGER, Phishing INTEGER)"""

cursor.execute(cmd2)
cursor.execute(cmd3)
cursor.execute(cmd4)

connection.commit()
connection.close()