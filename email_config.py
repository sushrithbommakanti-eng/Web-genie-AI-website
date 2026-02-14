# Email configuration
MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = 'bhukyadeva23@gmail.com'  # Replace with your email
MAIL_PASSWORD = 'flit bcgw alcc zwcf'     # Replace with your app password

from flask_mail import Mail, Message

mail = Mail()

def init_mail(app):
    app.config['MAIL_SERVER'] = MAIL_SERVER
    app.config['MAIL_PORT'] = MAIL_PORT
    app.config['MAIL_USE_TLS'] = MAIL_USE_TLS
    app.config['MAIL_USERNAME'] = MAIL_USERNAME
    app.config['MAIL_PASSWORD'] = MAIL_PASSWORD
    mail.init_app(app)

def send_feedback_email(feedback_text, user_email=None):
    try:
        subject = 'New Website Feedback Received'
        sender = MAIL_USERNAME
        recipients = [MAIL_USERNAME]  # Send to yourself
        
        body = f"""
        New feedback received:
        
        User: {user_email if user_email else 'Anonymous'}
        Feedback: {feedback_text}
        """
        
        msg = Message(
            subject=subject,
            sender=sender,
            recipients=recipients,
            body=body
        )
        
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending feedback email: {str(e)}")
        return False 

def send_otp(email, otp):
    print(f"OTP for {email}: {otp}")  # For debugging
    try:
        subject = 'OTP for your account'
        sender = MAIL_USERNAME
        recipients = [email]
        
        body = f"""
        Your OTP for account verification is: {otp}
        """
        
        msg = Message(
            subject=subject,
            sender=sender,
            recipients=recipients,
            body=body
        )
        
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending OTP email: {str(e)}")
        return False 