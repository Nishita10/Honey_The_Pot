import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, redirect, url_for, session

# Initialize Flask App
app = Flask(__name__)
app.secret_key = "your_secret_key"  # Required for session management

# Logging Setup (File Only)
logging_format = logging.Formatter('%(asctime)s - %(message)s')
honeypot_logger = logging.getLogger('HoneypotLogger')
honeypot_logger.setLevel(logging.INFO)

# Ensure no duplicate handlers
if honeypot_logger.hasHandlers():
    honeypot_logger.handlers.clear()

# # Rotating File Handler (writes to file only)
# file_handler = RotatingFileHandler('https_audits.log', maxBytes=5000, backupCount=5)
# file_handler.setFormatter(logging_format)
# honeypot_logger.addHandler(file_handler)

file_handler = RotatingFileHandler('https_audits.log', maxBytes=5000, backupCount=5, delay=True)
file_handler.setFormatter(logging_format)
honeypot_logger.addHandler(file_handler)


# Dummy Database for Registered Users
users_db = {}

# Home Route (Logs Visit)
@app.route('/')
def index():
    ip_address = request.remote_addr
    honeypot_logger.info(f'Page visited - IP: {ip_address}, Page: Home')
    return render_template('index.html')

# About Route (Logs User Choice)
@app.route('/about', methods=['GET', 'POST'])
def about():
    ip_address = request.remote_addr
    if request.method == 'POST':
        choice = request.form.get('offer_choice')
        honeypot_logger.info(f'User selected an offer - IP: {ip_address}, Choice: {choice}')
    return render_template('about.html')

# Address Route (Logs Visit)
@app.route('/address')
def address():
    ip_address = request.remote_addr
    honeypot_logger.info(f'Page visited - IP: {ip_address}, Page: Address')
    return render_template('address.html')

# Signup Route (Logs New User Registration)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip_address = request.remote_addr

        users_db[username] = password
        honeypot_logger.info(f'New user registered - IP: {ip_address}, Username: {username}, Password: {password}')

        return redirect(url_for('login'))
    return render_template('register.html')

# Offer Selection Tracker
@app.route('/track_selection', methods=['POST'])
def track_selection():
    ip_address = request.remote_addr
    choice = request.form.get('offer_choice', 'Unknown')
    honeypot_logger.info(f'User selected an offer - IP: {ip_address}, Choice: {choice}')
    return redirect(url_for('about'))

# Login Route (Logs Login Attempts)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip_address = request.remote_addr

        if username in users_db and users_db[username] == password:
            session['username'] = username
            honeypot_logger.info(f'User logged in - IP: {ip_address}, Username: {username}')
            return redirect(url_for('index'))
        else:
            honeypot_logger.info(f'Failed login attempt - IP: {ip_address}, Username: {username}, Password: {password}')
            return "Invalid credentials. Try again."
    return render_template('login.html')

# Logout Route (Logs Logout Activity)
@app.route('/logout')
def logout():
    ip_address = request.remote_addr
    username = session.get('username', 'Unknown')
    honeypot_logger.info(f'User logged out - IP: {ip_address}, Username: {username}')
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Keep debug=True so the run button shows logs if needed
    app.run(debug=True, port=5000, host="0.0.0.0")
