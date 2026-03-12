from flask import Flask, render_template, request, redirect
import sqlite3
import random

app = Flask(__name__)
app.secret_key = str(random.randint(1, 40))

@app.route("/")
def login():
    return render_template("login.html")

@app.route("/login_verify", methods=["POST"])
def login_verify():
    email = request.form.get('email')
    password = request.form.get('password')

    Connection = sqlite3.connect("users.db")
    cursor = Connection.cursor()
    
    user = cursor.execute("SELECT * FROM USERS WHERE email = ? AND password = ?", (email, password)).fetchall()
    Connection.close()
    if len(user) == 0:
        return redirect("/")
    else:
        username = user[0][0]
        return redirect(f"/home?username={username}&email={email}")
    
@app.route("/home")
def home():
    username = request.args.get('username')
    email = request.args.get('email')

    return render_template("home.html", username=username, email=email)


@app.route("/register")
def register():
    return render_template("signup.html")


@app.route("/add_user", methods=["POST"])
def add_user():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')

    Connection = sqlite3.connect("users.db")
    cursor = Connection.cursor()

    ans = cursor.execute("SELECT * FROM USERS WHERE email = ? AND password = ?", (email, password)).fetchall()
    
    if len(ans) > 0:
        Connection.close()
        return render_template("login.html")
    else:
        cursor.execute("INSERT INTO USERS (username, email, password) VALUES (?, ?, ?)", (username, email, password))
    
    
    Connection.commit()
    Connection.close()

    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)