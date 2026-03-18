
#imports Python’s SQLite database module. 
import sqlite3

#opens a connection to a SQLite database file named "users.db". If the file does not exist, it will be created. 
#The connection object is stored in the variable connection. Establishes a connection so Python can send SQL commands.
#A cursor allows the program to execute SQL commands.
connection = sqlite3.connect("users.db")
cursor = connection.cursor()

#command tells the database to create a table called USERS. Table will have three columns: username, email, and password.
#email column is set as the primary key, which means it must be unique for each user and cannot be null. 
#password column is also set to not allow null values.
cmd1 = """CREATE TABLE IF NOT EXISTS USERS (id INTEGER PRIMARY KEY AUTOINCREMENT, username, email, password varchar(50) NOT NULL)"""

#sends the SQL command to SQLite.
cursor.execute(cmd1)

#try block allows the program to catch errors without crashing.
#If an error happens, the program jumps to the except block.
try:

    #This SQL command inserts a new row into the USERS table.
    #Question marks are placeholders for the values that will be inserted into the table.
    #It prevents SQL injection attacks. 
    cmd2 = """INSERT INTO USERS(username, email, password) VALUES (?, ?, ?)"""

    #This inserts data into the table.
    #permanently saves changes to the database.
    # cursor.execute(cmd2, ("admin", "admin@example.com", "admin123"))
    connection.commit()
    # print("User inserted successfully")

#If the email already exists in the database,
#IntegrityError will be raised because email column is a primary key and must be unique.
except sqlite3.IntegrityError:
    print("User already exists")

# testing
# fetchall() retrieves every row.
ans = cursor.execute("SELECT * FROM USERS").fetchall()

#This checks if the query returned zero rows.
#If users exist, it prints a header and loop through each row.
if len(ans) == 0:
    print("No users found")
else:
    print("Users in database:")
    for i in ans:
        print(i)


#This closes the database safely.
connection.close()