import os
import re
from string import letters
import user_and_password
import security
import webapp2
import jinja2
from google.appengine.ext import db

not_valid_pass = "That wasn't a valid password."
not_valid_user = "That's not a valid username."
not_valid_email = "That's not a valid email."
pass_no_match = "Your passwords didn't match."
user_exist = "This user already exist"

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
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class BlogDB(db.Model):
    blog_title = db.StringProperty(required=True)
    blog_content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.blog_content.replace('\n', '<br>')
        return render_str("post.html", content = self)


class UsersDB(db.Model):
    username = db.StringProperty(required=True)
    user_email = db.StringProperty()
    user_password = db.StringProperty(required=True)


class FrontBlog(BlogHandler):
    def get(self):
        posts = db.GqlQuery("select * from BlogDB order by created desc limit 10")
        self.render("blog.html", posts=posts)


class SeePost(BlogHandler):
    def get(self, post_id):
        post_key = db.Key.from_path('BlogDB', int(post_id))
        post = db.get(post_key)

        if not post:
            self.error(404)

        else:
            self.render("permalink.html", post=post)


class NewPost(BlogHandler):
    def get(self):
        self.render("newpost.html")

    def post(self):
        post_title = self.request.get("title")
        post_content = self.request.get("content")

        if post_title and post_content:
            p = BlogDB(blog_title=post_title, blog_content=post_content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))

        else:
            error = "subject and content, please!"
            self.render("newpost.html", blog_title=post_title, blog_content=post_content, error=error)


class SignUp(BlogHandler):
    def get(self):
        self.render("signup.html")


    def post(self):
        have_error = False
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")
        params = dict(username=username, email=email)

        if not user_and_password.validate_user(username):
            params['error_username'] = not_valid_user
            have_error = True

        if not user_and_password.validate_password(password):
            params['error_password'] = not_valid_pass
            have_error = True
        elif password != verify:
            params['error_verify'] = pass_no_match
            have_error = True

        if not user_and_password.validate_email(email):
            params['error_email'] = not_valid_email
            have_error = True

        users = db.GqlQuery("select * from UsersDB where username = :1", username).get() #take the user info from the database

        if not users: #see if exist user.
            secure_pw = security.make_pw_hash(username, password) #hash the password and store it in secure_pw
            put_info = UsersDB(username=username, user_email=email, user_password=secure_pw) #put the information in database
            put_info.put()
        else:
            params['error_exist'] = user_exist
            have_error = True

        if have_error:
            self.render("signup.html", **params)

        else:
            self.response.headers['Content-Type'] = 'text/html'
            user_id = 0
            id_cookie_srt = self.request.cookies.get('user_id')
            if id_cookie_srt:
                cookie_val = security.test_security(id_cookie_srt)
                if cookie_val:
                    user_id = int(cookie_val)

            user_id += 1
            new_cookie_val = security.make_hash(str(user_id))
            self.response.headers.add_header('Set-Cookie', 'user_id=%s' % new_cookie_val)
            self.render("welcome.html", username=username)


class MainPage(BlogHandler):
    def get(self):
        self.render("index.html")






app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', FrontBlog),
                               ('/blog/([0-9]+)', SeePost),
                               ('/blog/newpost', NewPost),
                               ('/signup', SignUp)
                               ],
                              debug=True)