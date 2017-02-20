import re


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


# user validation
def validate_user(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


# password validation
def validate_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


# email validation
def validate_email(email):
    return not email or EMAIL_RE.match(email)

