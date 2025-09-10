from flask import Flask, render_template, redirect, url_for, request, flash
from models import db, User
from config import Config
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import re

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # Redirect if not logged in

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def create_tables():
    db.create_all()

# ---------- Helpers ----------
def is_valid_email(email: str) -> bool:
    return bool(re.match(r"^[^@]+@[^@]+\.[^@]+$", email))

# ---------- Routes ----------
@app.route('/')
def index():
    return render_template("index.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', "").strip()
        email = request.form.get('email', "").strip().lower()
        password = request.form.get('password', "")

        # --- Validation ---
        if len(username) < 3:
            flash("Username must be at least 3 characters long.")
            return redirect(url_for('register'))

        if not is_valid_email(email):
            flash("Invalid email format.")
            return redirect(url_for('register'))

        if len(password) < 6:
            flash("Password must be at least 6 characters long.")
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash("Email already registered.")
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash("Username already taken.")
            return redirect(url_for('register'))

        # --- Create user ---
        try:
            new_user = User(username=username, email=email)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful. Please log in.")
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash("Error during registration. Try again.")
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', "").strip().lower()
        password = request.form.get('password', "")

        if not email or not password:
            flash("Both email and password are required.")
            return redirect(url_for('login'))

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            flash("Login successful.")
            return redirect(url_for('secret'))
        else:
            flash("Invalid email or password.")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have logged out.")
    return redirect(url_for('index'))

@app.route('/secret')
@login_required
def secret():
    return render_template('secret.html', username=current_user.username)

if __name__ == '__main__':
    app.run(debug=True)