from flask import Flask, render_template, request, redirect, session
from database import create_users_table
from auth import register_user, login_user

app = Flask(__name__)
app.secret_key = "your_secret_key"

create_users_table()

@app.route("/")
def home():
    if "user" in session:
        return redirect("/dashboard")
    return redirect("/login")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        success, message = register_user(username, email, password)

        if success:
            return redirect("/login")
        else:
            return message

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        success, result = login_user(username, password)

        if success:
            session["user"] = result["username"]
            return redirect("/dashboard")
        else:
            return result

    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")

    return render_template("dashboard.html", user=session["user"])

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/login")

if __name__ == "__main__":
    app.run(debug=True)
