
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
cmd1 = """CREATE TABLE IF NOT EXISTS USERS (id INTEGER PRIMARY KEY AUTOINCREMENT, username, email, password varchar(50) NOT NULL, historyID)"""

#Sends the SQL command to SQLite.
cursor.execute(cmd1)


#Command tells the database to create a table called USERS. Table will have three columns: id, URL, TIMEDATE and TOTALSCORE.

cmd2 = """CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY AUTOINCREMENT, URL, TIMEDATE, TOTALSCORE)"""
cmd3 = """CREATE TABLE IF NOT EXISTS user_history_link (id INTEGER PRIMARY KEY AUTOINCREMENT, 
           user_id INTEGER NOT NULL, history_id INTEGER NOT NULL)"""

cursor.execute(cmd2)
cursor.execute(cmd3)

connection.commit()
connection.close()