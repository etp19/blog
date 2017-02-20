import hashlib
import hmac
import random
import string

x = hashlib.sha256('udacity')
SECRET = '+d2d2dfrente'  # secret key


def hash_srt(s):
    return hmac.new(SECRET, s).hexdigest()


def make_hash(s):
    return "%s|%s" % (s, hash_srt(s))  # make hash


def test_security(h):
    val = h.split('|')[0]
    if h == make_hash(val):
        return val


# implement the function make_salt() that returns a string of 5 random
# letters use python's random module.


def make_salt():
    """this is the function to make ramdom letters called salt."""
    return ''.join(random.choice(string.letters) for i in range(5))


def make_pw_hash(name, pw, salt=None):
    """this class call call function make_salt and
    store the value in salt, then I join the name
    with the pw and add the salt, finally return the
    encrypted version of the strings"""
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)


def valid_pw(name, pw, h):
    """test is username and password are correct"""
    salt = h.split(",")[1]
    return h == make_pw_hash(name, pw, salt)

