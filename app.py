from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify, send_file, send_from_directory, abort, make_response
import smtplib
import random
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import config
import json
import os
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from config import EMAIL, PASSWORD, HOST, PORT, RAZORPAY_KEY_ID
from routes.payment import payment_bp
from datetime import datetime, timedelta
import razorpay
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from io import BytesIO
import uuid
import time
import zipfile
import subprocess
import socket
import requests
import re
from email_config import init_mail, send_feedback_email
from pymongo import MongoClient
from sqlalchemy.exc import SQLAlchemyError
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Secret key for flash messages
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email configuration
app.config['MAIL_SERVER'] = HOST
app.config['MAIL_PORT'] = PORT
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = EMAIL
app.config['MAIL_PASSWORD'] = PASSWORD

# Razorpay configuration
app.config['RAZORPAY_KEY_ID'] = RAZORPAY_KEY_ID

db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'home'

# Register payment blueprint
app.register_blueprint(payment_bp)

# Initialize Razorpay client
razorpay_client = razorpay.Client(auth=(os.getenv('RAZORPAY_KEY_ID'), os.getenv('RAZORPAY_KEY_SECRET')))

# OpenRouter Configuration
OPENROUTER_API_KEY = "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"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    verified = db.Column(db.Boolean, default=False)
    subscription_plan = db.Column(db.String(20), default='free')
    subscription_end_date = db.Column(db.DateTime)
    phone = db.Column(db.String(15), nullable=True)
    subscription_status = db.Column(db.String(20), default='inactive')
    subscription_start_date = db.Column(db.DateTime)
    payment_id = db.Column(db.String(100))
    free_trials_remaining = db.Column(db.Integer, default=10)
    free_trials_used = db.Column(db.Integer, default=0)
    last_trial_date = db.Column(db.DateTime)
    transactions = db.relationship('Transaction', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.email}>'

# Add this with your other table definitions
class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    feedback_text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    feedback_count = db.Column(db.Integer, default=0)  # Track feedback count per user

# Add new model for customized templates
class CustomizedTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    html = db.Column(db.Text, nullable=False)
    css = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_modified = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Drop and recreate all tables
with app.app_context():
    db.drop_all()
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# User storage (in a real app, this should be in a database)
users_file = 'users.json'

# Load users from file if it exists
def load_users():
    if os.path.exists(users_file):
        with open(users_file, 'r') as f:
            return json.load(f)
    return {}

# Save users to file
def save_users(users):
    with open(users_file, 'w') as f:
        json.dump(users, f)

# Initialize users
users = load_users()

# OTP storage (in a real app, this should be in a database)
otp_storage = {}

# Initialize email
init_mail(app)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# MongoDB configuration with error handling
try:
    MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
    mongo_client = MongoClient(MONGO_URI)
    mongo_db = mongo_client['ai_website_builder']
    feedback_collection = mongo_db['feedback']
    community_feed_collection = mongo_db['community_feed']
    # Test the connection
    mongo_client.server_info()
except Exception as e:
    print(f"MongoDB Connection Error: {str(e)}")
    # Fallback to use SQLite only if MongoDB is not available
    feedback_collection = None
    community_feed_collection = None

# Route to show registration form (GET method)
@app.route('/')
def home():
    return render_template('register.html')

@app.route('/auth')
def auth():
    return render_template('register.html')

# Route to handle login (POST method) - keeping for backward compatibility
@app.route('/register', methods=['POST'])
def register():
    email = request.form.get('email').strip().lower()  # Normalize email
    password = request.form.get('password')
    
    # Check if user exists in database
    user = User.query.filter_by(email=email).first()
    
    if user:
        # Verify password
        if check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid password. Please try again.', 'danger')
            return redirect(url_for('home'))
    else:
        flash('User not found. Please sign up.', 'danger')
        return redirect(url_for('home'))

# Route to handle signup (POST method)
@app.route('/signup', methods=['POST'])
def signup():
    try:
        email = request.form.get('email').strip().lower()  # Normalize email
        password = request.form.get('password')
        confirm_password = request.form.get('confirm-password')
        name = request.form.get('name')
        
        # Validate input
        if not email or not password or not confirm_password or not name:
            flash('All fields are required.', 'danger')
            return redirect(url_for('home'))
        
        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('home'))
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered. Please login.', 'danger')
            return redirect(url_for('home'))
        
        # Generate OTP (6-digit random number)
        otp = str(random.randint(100000, 999999))
        
        # Store OTP temporarily
        otp_storage[email] = otp
        
        # Create new user with 10 free trials
        hashed_password = generate_password_hash(password)
        new_user = User(
            email=email, 
            password=hashed_password, 
            name=name, 
            verified=False,
            free_trials_remaining=10,
            free_trials_used=0
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            
            # Send OTP email
            send_otp(email, otp)
            
            # Flash success message and redirect to OTP verification
            flash('OTP sent to your email! Please verify.', 'success')
            return redirect(url_for('verify_otp', email=email))
            
        except Exception as e:
            db.session.rollback()
            print(f"Error in signup: {str(e)}")
            flash('Signup failed. Please try again.', 'danger')
            return redirect(url_for('home'))
            
    except Exception as e:
        print(f"Error in signup route: {str(e)}")
        flash('An error occurred. Please try again.', 'danger')
        return redirect(url_for('home'))

# Route for OTP verification
@app.route('/verify-otp/<email>', methods=['GET', 'POST'])
def verify_otp(email):
    if request.method == 'POST':
        try:
            otp_input = request.form.get('otp')
            stored_otp = otp_storage.get(email)
            
            if not stored_otp:
                flash('OTP has expired. Please request a new one.', 'danger')
                return redirect(url_for('home'))
            
            if otp_input == stored_otp:
                # Mark user as verified
                user = User.query.filter_by(email=email).first()
                if user:
                    user.verified = True
                    db.session.commit()
                    # Remove OTP from storage
                    otp_storage.pop(email, None)
                    flash('Email verified successfully! Please login to continue.', 'success')
                    return redirect(url_for('home'))
                else:
                    flash('User not found.', 'danger')
                    return redirect(url_for('home'))
            else:
                flash('Invalid OTP. Please try again.', 'danger')
                return render_template('verify_otp.html', email=email)
                
        except Exception as e:
            print(f"Error in OTP verification: {str(e)}")
            flash('An error occurred. Please try again.', 'danger')
            return redirect(url_for('home'))
    
    return render_template('verify_otp.html', email=email)

# Route to handle logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

# Dashboard route
@app.route('/dashboard')
@login_required
def dashboard():
    # Check if user has used all free trials and redirect to subscription page
    if current_user.free_trials_remaining == 0 and current_user.subscription_plan == 'free':
        flash('You have used all your free trials. Please subscribe to continue.', 'warning')
        return redirect(url_for('subscription'))
    
    # Add trial usage tracking
    if current_user.subscription_plan == 'free' and current_user.free_trials_remaining > 0:
        # Check if this is the first visit today
        today = datetime.now().date()
        if not current_user.last_trial_date or current_user.last_trial_date.date() < today:
            current_user.free_trials_used += 1
            current_user.free_trials_remaining -= 1
            current_user.last_trial_date = datetime.now()
            db.session.commit()
            
            # If this was the last free trial, show a message
            if current_user.free_trials_remaining == 0:
                flash('You have used your last free trial. Please subscribe to continue using our services.', 'warning')
    
    return render_template('dashboard.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'update_profile':
            email = request.form.get('email')
            phone = request.form.get('phone')
            
            # Check if email is already taken by another user
            existing_user = User.query.filter(User.email == email, User.id != current_user.id).first()
            if existing_user:
                flash('Email is already taken by another user.', 'danger')
                return redirect(url_for('dashboard'))
            
            # Update user information
            current_user.email = email
            current_user.phone = phone
            db.session.commit()
            
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('dashboard'))
    
    return render_template('profile.html')

@app.route('/subscription')
@login_required
def subscription():
    return render_template('subscription.html')

def create_receipt_pdf(transaction_id, plan, amount, date, customer_name, customer_email):
    # Create a BytesIO buffer to store the PDF
    buffer = BytesIO()
    
    # Create the PDF object using ReportLab
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    
    # Add company logo (if available)
    # p.drawImage('path_to_logo.png', 50, height - 100, width=100, height=50)
    
    # Add receipt header
    p.setFont("Helvetica-Bold", 24)
    p.drawString(50, height - 50, "Payment Receipt")
    
    # Add receipt details
    p.setFont("Helvetica", 12)
    y = height - 100
    
    # Add company details
    p.drawString(50, y, "Your Company Name")
    p.drawString(50, y - 20, "Address Line 1")
    p.drawString(50, y - 40, "City, State, ZIP")
    p.drawString(50, y - 60, "Email: support@yourcompany.com")
    
    # Add separator line
    p.line(50, y - 80, width - 50, y - 80)
    
    # Add customer details
    y = y - 120
    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, y, "Customer Details")
    p.setFont("Helvetica", 12)
    p.drawString(50, y - 20, f"Name: {customer_name}")
    p.drawString(50, y - 40, f"Email: {customer_email}")
    
    # Add transaction details
    y = y - 80
    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, y, "Transaction Details")
    p.setFont("Helvetica", 12)
    p.drawString(50, y - 20, f"Transaction ID: {transaction_id}")
    p.drawString(50, y - 40, f"Date: {date}")
    p.drawString(50, y - 60, f"Plan: {plan}")
    p.drawString(50, y - 80, f"Amount: {amount}")
    
    # Add footer
    p.setFont("Helvetica", 10)
    p.drawString(50, 50, "This is a computer generated receipt and doesn't require a signature.")
    p.drawString(50, 30, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Save the PDF
    p.showPage()
    p.save()
    
    # Move buffer position to start
    buffer.seek(0)
    return buffer

@app.route('/payment-success', methods=['POST'])
@login_required
def payment_success():
    try:
        data = request.json
        
        # Verify payment signature
        params_dict = {
            'razorpay_payment_id': data['razorpay_payment_id'],
            'razorpay_order_id': data['razorpay_order_id'],
            'razorpay_signature': data['razorpay_signature']
        }
        
        try:
            razorpay_client.utility.verify_payment_signature(params_dict)
        except razorpay.errors.SignatureVerificationError:
            return jsonify({
                'success': False,
                'error': 'Invalid payment signature'
            }), 400
        
        # Update user subscription in database
        user = current_user
        user.subscription_plan = data['plan']
        user.subscription_status = 'active'
        user.subscription_start_date = datetime.now()
        user.payment_id = data['razorpay_payment_id']
        db.session.commit()
        
        # Record the transaction
        transaction = Transaction(
            user_id=user.id,
            payment_id=data['razorpay_payment_id'],
            order_id=data['razorpay_order_id'],
            amount=data['amount'],
            plan=data['plan'],
            status='success',
            timestamp=datetime.now()
        )
        db.session.add(transaction)
        db.session.commit()
        
        return jsonify({'success': True})
        
    except Exception as e:
        # Log the error for debugging
        print(f"Payment processing error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to process payment'
        }), 500

@app.route('/generate-receipt', methods=['POST'])
@login_required
def generate_receipt():
    try:
        data = request.json
        
        # Verify if the transaction belongs to the current user
        transaction = Transaction.query.filter_by(
            payment_id=data['transactionId'],
            user_id=current_user.id
        ).first()
        
        if not transaction:
            return jsonify({
                'success': False,
                'error': 'Transaction not found'
            }), 404
        
        # Generate PDF receipt
        pdf_buffer = create_receipt_pdf(
            transaction_id=data['transactionId'],
            plan=data['plan'],
            amount=data['amount'],
            date=data['date'],
            customer_name=data['customerName'],
            customer_email=data['customerEmail']
        )
        
        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'receipt-{data["transactionId"]}.pdf'
        )
        
    except Exception as e:
        # Log the error for debugging
        print(f"Receipt generation error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to generate receipt'
        }), 500

# Add Transaction model for database
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    payment_id = db.Column(db.String(100), unique=True, nullable=False)
    order_id = db.Column(db.String(100), unique=True, nullable=False)
    amount = db.Column(db.Float, nullable=False)
    plan = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f'<Transaction {self.payment_id}>'

def send_otp(email, otp):
    print(f"OTP for {email}: {otp}")  # For debugging
    subject = "Your OTP Code"
    body = f"Your OTP is: {otp}"

    # Set up the MIME (Multipurpose Internet Mail Extensions)
    msg = MIMEMultipart()
    msg['From'] = config.EMAIL  # Sender's email
    msg['To'] = email  # Receiver's email
    msg['Subject'] = subject  # Email subject
    msg.attach(MIMEText(body, 'plain'))  # Attach the body of the email

    try:
        print(f"Attempting to connect to SMTP server: {config.HOST}:{config.PORT}")
        # Establish connection to Gmail's SMTP server
        with smtplib.SMTP(config.HOST, config.PORT) as server:
            print("Starting TLS...")
            server.starttls()  # Secure the connection using TLS
            print("Logging in with email:", config.EMAIL)
            server.login(config.EMAIL, config.PASSWORD)  # Log in to Gmail's SMTP server
            print("Sending email...")
            server.sendmail(config.EMAIL, email, msg.as_string())  # Send the email
        print(f"OTP sent successfully to {email}")
    except Exception as e:
        print(f"Failed to send OTP: {str(e)}")
        print(f"Error type: {type(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")

def has_subscription(user_id):
    """
    Check if a user has an active subscription or free trials remaining.
    
    Args:
        user_id: The ID of the user to check
        
    Returns:
        bool: True if the user has an active subscription or free trials remaining, False otherwise
    """
    user = User.query.get(user_id)
    if not user:
        return False
        
    # Check if user has an active paid subscription
    if user.subscription_plan != 'free' and user.subscription_status == 'active':
        return True
        
    # Check if user has free trials remaining
    if user.subscription_plan == 'free' and user.free_trials_remaining > 0:
        return True
        
    return False

def track_trial_usage(user_id):
    """
    Track the usage of a free trial by a user.
    
    Args:
        user_id: The ID of the user to track
        
    Returns:
        bool: True if the trial was successfully tracked, False otherwise
    """
    user = User.query.get(user_id)
    if not user or user.subscription_plan != 'free' or user.free_trials_remaining <= 0:
        return False
        
    # Update trial usage
    user.free_trials_used += 1
    user.free_trials_remaining -= 1
    user.last_trial_date = datetime.now()
    
    # If this was the last free trial, update subscription status
    if user.free_trials_remaining == 0:
        user.subscription_status = 'expired'
        
    db.session.commit()
    return True

@app.route('/generator')
@login_required
def generator():
    return render_template('generator.html')

def generate_website_content(prompt):
    try:
        headers = {
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "HTTP-Referer": "https://github.com/bhukya-srinivas/otp_registration_project",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": "openai/gpt-3.5-turbo",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a professional web developer. Generate a complete website based on the user's description. Return ONLY a JSON object with 'html' and 'css' fields. Do not include any explanations or other text. The response should be in this exact format: {\"html\": \"<your html code>\", \"css\": \"<your css code>\"}"
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.7,
            "max_tokens": 2000
        }
        
        response = requests.post(OPENROUTER_URL, headers=headers, json=data)
        response.raise_for_status()
        
        result = response.json()
        content = result['choices'][0]['message']['content']
        
        try:
            # Try to parse the content as JSON
            website_data = json.loads(content)
            if isinstance(website_data, dict) and 'html' in website_data and 'css' in website_data:
                return website_data
            else:
                # If JSON is valid but doesn't have the expected structure
                # Extract HTML and CSS using regex as fallback
                raise json.JSONDecodeError("Invalid structure", content, 0)
                
        except json.JSONDecodeError:
            # If content is not valid JSON, extract HTML and CSS using regex
            html_pattern = r'<html>.*?</html>|<body>.*?</body>|<div.*?>.*?</div>'
            css_pattern = r'<style>(.*?)</style>|\/\* CSS \*\/(.*?)\/\* End CSS \*\/'
            
            # Find all HTML matches and combine them
            html_matches = re.findall(html_pattern, content, re.DOTALL)
            html = '\n'.join(html_matches) if html_matches else "<div>Generated content could not be parsed</div>"
            
            # Find all CSS matches and combine them
            css_matches = []
            for match in re.finditer(css_pattern, content, re.DOTALL):
                # Take the first non-None group from each match
                css_group = next((g for g in match.groups() if g is not None), '')
                css_matches.append(css_group)
            css = '\n'.join(css_matches) if css_matches else ""
            
            return {
                'html': html,
                'css': css
            }
            
    except Exception as e:
        print(f"Error generating website content: {str(e)}")
        return None

@app.route('/generate-website', methods=['POST'])
@login_required
def generate_website():
    try:
        # Verify that the request has JSON content
        if not request.is_json:
            return jsonify({
                'success': False,
                'error': 'Request must be JSON'
            }), 400

        # Check subscription/trial status
        if not has_subscription(current_user.id):
            return jsonify({
                'success': False, 
                'error': 'Subscription required'
            }), 403
        
        data = request.get_json()
        prompt = data.get('prompt')
        
        if not prompt:
            return jsonify({
                'success': False, 
                'error': 'No prompt provided'
            }), 400
        
        # Generate website content
        website_data = generate_website_content(prompt)
        
        if not website_data:
            return jsonify({
                'success': False,
                'error': 'Failed to generate website content'
            }), 500

        if 'html' not in website_data or 'css' not in website_data:
            return jsonify({
                'success': False,
                'error': 'Invalid website content generated'
            }), 500

        # Track trial usage for free users
        if current_user.subscription_plan == 'free':
            if not track_trial_usage(current_user.id):
                return jsonify({
                    'success': False,
                    'error': 'No free trials remaining'
                }), 403

        # Store the generated content in the session for download
        session['last_generated_website'] = {
            'html': website_data['html'],
            'css': website_data['css']
        }

        # Store in community feed if MongoDB is available
        if community_feed_collection is not None:
            try:
                feed_doc = {
                    'user_id': current_user.id,
                    'user_name': current_user.name,
                    'user_email': current_user.email,
                    'description': prompt,
                    'html': website_data['html'],
                    'css': website_data['css'],
                    'created_at': datetime.utcnow()
                }
                community_feed_collection.insert_one(feed_doc)
            except Exception as mongo_error:
                print(f"MongoDB Error: {str(mongo_error)}")
                # Continue even if MongoDB fails

        return jsonify({
            'success': True,
            'html': website_data['html'],
            'css': website_data['css']
        })
            
    except Exception as e:
        print(f"Error in generate_website route: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An error occurred while generating the website'
        }), 500

@app.route('/download-website')
@login_required
def download_website():
    try:
        # Get the last generated website content from session
        website_data = session.get('last_generated_website')
        if not website_data:
            return "No website content available for download", 404

        # Create complete HTML document
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Generated Website</title>
    <style>
{website_data['css']}
    </style>
</head>
<body>
{website_data['html']}
</body>
</html>"""

        # Create response with HTML content
        response = make_response(html_content)
        response.headers['Content-Type'] = 'text/html'
        response.headers['Content-Disposition'] = 'attachment; filename=generated_website.html'
        
        return response
        
    except Exception as e:
        print(f"Error in download_website route: {str(e)}")
        return "Error generating download", 500

@app.route('/chatbot')
@login_required
def chatbot():
    if current_user.subscription_plan == 'free' and current_user.free_trials_remaining == 0:
        flash('You have used all your free trials. Please upgrade to a paid plan to continue using the chatbot.', 'warning')
        return redirect(url_for('subscription'))
    return render_template('chatbot.html')

@app.route('/submit-feedback', methods=['POST'])
@login_required
def submit_feedback():
    if not current_user.is_authenticated:
        return jsonify({'success': False, 'error': 'User not authenticated'}), 401
        
    try:
        feedback_text = request.json.get('feedback')
        if not feedback_text:
            return jsonify({'success': False, 'error': 'Feedback text is required'}), 400

        # Check if user has already submitted 2 feedbacks
        feedback_count = Feedback.query.filter_by(user_id=current_user.id).count()
        if feedback_count >= 2:
            return jsonify({'success': False, 'error': 'You have already submitted the maximum number of feedbacks (2)'}), 400

        # Store in SQLite
        feedback = Feedback(
            user_id=current_user.id,
            feedback_text=feedback_text,
            feedback_count=feedback_count + 1
        )
        db.session.add(feedback)
        db.session.commit()

        # Store in MongoDB if available
        if feedback_collection is not None:
            try:
                feedback_doc = {
                    'user_id': current_user.id,
                    'user_email': current_user.email,
                    'user_name': current_user.name,
                    'feedback_text': feedback_text,
                    'created_at': datetime.utcnow(),
                    'feedback_count': feedback_count + 1
                }
                feedback_collection.insert_one(feedback_doc)
            except Exception as mongo_error:
                print(f"MongoDB Error: {str(mongo_error)}")
                # Continue even if MongoDB fails as we have the data in SQLite

        # Send feedback email
        try:
            send_feedback_email(current_user.email, feedback_text)
        except Exception as email_error:
            print(f"Email Error: {str(email_error)}")
            # Continue even if email fails

        return jsonify({
            'success': True,
            'message': 'Feedback submitted successfully',
            'remaining_feedbacks': 2 - (feedback_count + 1)
        })

    except Exception as e:
        db.session.rollback()
        print(f"Feedback Submission Error: {str(e)}")
        return jsonify({'success': False, 'error': 'Error submitting feedback. Please try again.'}), 500

@app.route('/community-feed', methods=['GET'])
def community_feed():
    # Get the latest 20 items, newest first
    feed_items = list(community_feed_collection.find().sort('created_at', -1).limit(20))
    for item in feed_items:
        item['_id'] = str(item['_id'])  # Convert ObjectId to string for JSON
    return jsonify(feed_items)

@app.route('/feedback-messages', methods=['GET'])
def feedback_messages():
    try:
        # Get feedback from MongoDB
        feedbacks = list(feedback_collection.find().sort('created_at', -1).limit(20))
        
        # Convert ObjectId to string for JSON serialization
        for fb in feedbacks:
            fb['_id'] = str(fb['_id'])
            
        return jsonify({
            'success': True,
            'feedbacks': feedbacks
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/save-customized-template', methods=['POST'])
@login_required
def save_customized_template():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = [
            'templateName', 
            'templateHtml', 
            'templateCss',
            'customizations'
        ]
        
        for field in required_fields:
            if field not in data:
                return jsonify({'status': 'error', 'message': f'Missing required field: {field}'}), 400

        # Get customizations
        customizations = data['customizations']
        
        # Apply customizations to the template CSS
        custom_css = data['templateCss'] + f"""
            :root {{
                --primary-color: {customizations.get('primaryColor', '#000000')};
                --secondary-color: {customizations.get('secondaryColor', '#ffffff')};
                --font-family: {customizations.get('fontFamily', 'Arial')}, sans-serif;
                --heading-color: {customizations.get('headingColor', '#000000')};
                --text-color: {customizations.get('textColor', '#000000')};
            }}
            
            body {{
                font-family: var(--font-family);
                color: var(--text-color);
            }}
            
            h1, h2, h3, h4, h5, h6 {{
                color: var(--heading-color);
            }}
        """

        # Create new customized template
        new_template = CustomizedTemplate(
            user_id=current_user.id,
            name=data['templateName'],
            html=data['templateHtml'],
            css=custom_css
        )

        db.session.add(new_template)
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'Template saved successfully',
            'template_id': new_template.id
        })

    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': 'Database error occurred while saving the template'
        }), 500
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/feedback-count', methods=['GET'])
@login_required
def get_feedback_count():
    try:
        feedback_count = Feedback.query.filter_by(user_id=current_user.id).count()
        remaining_feedbacks = max(0, 2 - feedback_count)
        return jsonify({
            'success': True,
            'remaining_feedbacks': remaining_feedbacks
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
