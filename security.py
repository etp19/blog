import hashlib
import hmac
import random
import string

x = hashlib.sha256('udacity')
SECRET = '+d2d2dfrente'


def hash_srt(s):
    return hmac.new(SECRET, s).hexdigest()


def make_hash(s):
    return "%s|%s" % (s, hash_srt(s))


def test_security(h):
    val = h.split('|')[0]
    if h == make_hash(val):
        return val


# implement the function make_salt() that returns a string of 5 random
# letters use python's random module.
# Note: The string package might be useful here.

def make_salt():#this is the function to make ramdom letters called salt.
    return ''.join(random.choice(string.letters) for i in range(5))


#print make_salt()


def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()#call the function make_salt and store the value in salt
    h = hashlib.sha256(name + pw + salt).hexdigest() #In this function we join the name with the pw and also we add the salt.
    return '%s,%s' % (h, salt)  #after that we take the salt only and h which is encrypt version of everything and return it.


def valid_pw(name, pw, h): #this function test if the username and password are good
    salt = h.split(",")[1]
    return h == make_pw_hash(name,pw,salt)

h = make_pw_hash('spez', 'hunter2')
print valid_pw('spez', 'hunter2', h)
#print make_pw_hash('spez', 'hunter2','PEhRn')
print h

#print make_pw_hash("Eduardo", "water875")
print make_hash("14")
print test_security("14|2c66b804f0e51f85163afed94161ceef")
print make_pw_hash("Eduardo12", "12345", "sasas")