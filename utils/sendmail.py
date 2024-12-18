import os
import smtplib
from email.mime.text import MIMEText
from utils.helpers import green, red, reset
from email.mime.multipart import MIMEMultipart
from itsdangerous import URLSafeTimedSerializer


serializer = URLSafeTimedSerializer(os.getenv("SECRET_KEY"))


def generate_confirmation_token(email):
    return serializer.dumps(email, salt="email-confirm-salt")


def confirm_token(token, expiration=300):
    try:
        email = serializer.loads(token, salt="email-confirm-salt", max_age=expiration)
    except Exception:
        return None
    return email


def send_email(to_email, subject, body):
    try:
        smtp_host = os.getenv("SMTP_HOST")
        smtp_port = os.getenv("SMTP_PORT")
        smtp_user = os.getenv("SMTP_USER")
        smtp_pass = os.getenv("SMTP_PASS")

        message = MIMEMultipart()
        message["From"] = smtp_user
        message["To"] = to_email
        message["Subject"] = subject
        message.attach(MIMEText(body, "html"))

        with smtplib.SMTP_SSL(smtp_host, smtp_port) as server:
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, to_email, message.as_string())
            print(green + "Confirmation email sent successfully!" + reset)
    except Exception as e:
        print(red + f"Error sending email: {e}" + reset)


def email_confirmation(email):
    token = generate_confirmation_token(email)
    confirmation_link = f"http://127.0.0.1:5000/confirm/2fa/{token}"
    send_email(
        to_email=email,
        subject="Confirm Your 2FA",
        body=f"""
    <html>
        <body>
            <p>Hello,</p>
            <p>Please confirm login by clicking the link below:</p>
            <a href="{confirmation_link}">Confirm Your Email</a>
            <p>This link will expire in 5 minutes.</p>
        </body>
    </html>
    """,
    )
