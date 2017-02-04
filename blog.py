import os
import re
from string import letters
import webapp2
import jinja2
import user_and_password
import security
from google.appengine.ext import ndb


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = security.make_hash(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and security.test_security(cookie_val) #return cookie_val, this is a shortcut for if statement.

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key.id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


class MainPage(BlogHandler):
    def get(self):
            self.render("index.html")


##### user stuff

def users_key(group = 'default'):
    return ndb.Key('users', group)


class User(ndb.Model):
    name = ndb.StringProperty(required=True)
    pw_hash = ndb.StringProperty(required=True)
    email = ndb.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = cls.query(cls.name == name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = security.make_pw_hash(name, pw)
        return cls(parent=users_key(),
                   name=name,
                   pw_hash=pw_hash,
                   email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and security.valid_pw(name, pw, u.pw_hash):
            return u


##### blog stuff

def blog_key(name='default'):
    return ndb.Key('blogs', name)


class Post(ndb.Model):
    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
    user_post = ndb.KeyProperty(kind=User)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class Reply(ndb.Model):#check this, it is the database for the comments
    content = ndb.StringProperty(required=True)
    post_info = ndb.KeyProperty(kind=Post)
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
    user = ndb.KeyProperty(kind=User)


class Likes(ndb.Model): #start working from here.
    post_info = ndb.KeyProperty(kind=Post)
    user = ndb.KeyProperty(kind=Post, repeated=True)


class BlogFront(BlogHandler):
    def get(self):
        posts = ndb.gql("select * from Post order by created desc limit 10")
        self.render("blog.html", posts=posts)


class PostPage(BlogHandler): #something must be wrong here, but I cannot figure out what it is.
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()
        if not post:
            self.error(404)
            return
        comments = ndb.gql("select * from Reply where post_info = :1 order by created desc limit 10", key)
        like = ndb.gql("select * from Likes where post_info= :1", key)
        self.render("permalink.html", post=post, comments=comments, like=like)

    def post(self, post_id): # Last updated here...
        if not self.user:
            self.redirect('/blog/login')
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()
        error_comment = "The Comment cannot be empty"
        number1_button = self.request.get('comment_button')
        number2_button = self.request.get('like_button')
        if number1_button:
            comments = self.request.get('comments')
            if comments and self.user:
                save_comment = Reply(parent=blog_key(), content=comments, user=self.user.key, post_info=post.key)
                save_comment.put()
                self.redirect('/blog/%s' % str(post.key.id()))
            else:
                comments = ndb.gql("select * from Reply where post_info = :1 order by created desc limit 10", key)
                like = ndb.gql("select * from Likes where post_info= :1", key)
                self.render("permalink.html", post=post, comments=comments, error_comment=error_comment, like=like)
        elif number2_button:
            result = Likes.query(Likes.post_info == key).get()
            if result:
                user_like = result.user
                user_like.append(self.user.key.id())
                add_like = Likes(parent=blog_key(), post_info=post, user=user_like)
                add_like.put()
                self.redirect('/blog/%s' % str(post.key.id()))
            else:
                user_list = [self.user.key.id()]
                some = Likes(parent=blog_key(), post_info=post, user=user_list)
                some.put()
                self.redirect('/blog/%s' % str(post.key.id()))


#check from here for changes in database.
class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/blog/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('title')
        content = self.request.get('blog_content')

        if subject and content:
            p = Post(parent=blog_key(), user_post=self.user.key, subject=subject, content=content)
            p_key = p.put()
            self.redirect('/blog/%s' % str(p_key.id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, blog_content=content, error=error)


class Signup(BlogHandler):
    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        params = dict(username=self.username,
                      email=self.email)

        if not user_and_password.validate_user(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not user_and_password.validate_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not user_and_password.validate_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog/welcome')


class Login(BlogHandler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog/welcome')
        else:
            msg = 'Invalid login'
            self.render('login.html', invalid_login=msg)


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog/login')


class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('blog/signup')


class ShowUser(BlogHandler):
    def get(self):
        if self.user:
            self.render("base.html", user=self.user.name)
        else:
            pass


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/signup', Register),
                               ('/logout', Logout),
                               ('/blog/welcome', Welcome),
                               ('/blog/login', Login),
                               ('/blog/', ShowUser)
                               ],
                              debug=True)

