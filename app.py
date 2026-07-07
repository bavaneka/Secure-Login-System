from flask import Flask, render_template, request, redirect, url_for, session
from flask_bcrypt import Bcrypt
from database import db
from models import User
import re

app = Flask(__name__)

app.config["SECRET_KEY"] = "mysecretkey123"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

bcrypt = Bcrypt(app)
db.init_app(app)


@app.route("/")
def home():
    return render_template("index.html")


# ---------------- REGISTER ---------------- #

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]

        # Empty field validation
        if username == "" or email == "" or password == "":
            return "All fields are required!"

        # Username validation
        if len(username) < 3:
            return "Username must be at least 3 characters."

        # Email validation
        email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'

        if not re.match(email_pattern, email):
            return "Invalid Email Address!"

        # Password validation
        if len(password) < 8:
            return "Password must be at least 8 characters."

        # Duplicate email
        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            return "Email already registered!"

        # Hash password
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        # Save user
        new_user = User(
            username=username,
            email=email,
            password=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("login"))

    return render_template("register.html")


# ---------------- LOGIN ---------------- #

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):

            session["username"] = user.username

            return redirect(url_for("dashboard"))

        return "Invalid Email or Password!"

    return render_template("login.html")


# ---------------- DASHBOARD ---------------- #

@app.route("/dashboard")
def dashboard():

    if "username" not in session:
        return redirect(url_for("login"))

    return render_template("dashboard.html", username=session["username"])


# ---------------- LOGOUT ---------------- #

@app.route("/logout")
def logout():

    session.pop("username", None)

    return redirect(url_for("login"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(debug=True)