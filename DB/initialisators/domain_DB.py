#Import sqlite3 to connect and interact with SQL database.
import sqlite3

#Initailize connection to database
connection = sqlite3.connect("DB/cert_domain.db")
cursor = connection.cursor()

#Create certified domain names' database.
cursor.execute("CREATE TABLE IF NOT EXISTS domains (id INTEGER PRIMARY KEY, domain TEXT)")

#Open DB/domain.txt where domains are stored using read method.
#Takes line from character, strips whitespaces and splits string in two parts before TAB character and after TAB character.
#After inserts first part as a integer and second part as tring into certified domain database.
with open("DB/initialisators/domain.txt", "r") as f:
    for line in f:
        parts = line.strip().split("\t")
        cursor.execute("INSERT INTO domains VALUES (?, ?)", (int(parts[0]), parts[1]))

#Commit changes and close connection
connection.commit()
connection.close()