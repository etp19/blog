import os
import time
import datetime
import webapp2
import jinja2
import user_and_password
import security
from google.appengine.ext import ndb

# set the location for the template folder
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


# render templates
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


class BlogHandler(webapp2.RequestHandler):
    """ Template stuff, this facilitate handles requests such as
        write, redirection and render. """
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        # set the cookie
        cookie_val = security.make_hash(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        # read the cookie
        cookie_val = self.request.cookies.get(name)
        # return cookie_val, this is a shortcut for if statement.
        return cookie_val and security.test_security(
            cookie_val)

    def login(self, user):
        # set the cookie value using user id
        self.set_secure_cookie('user_id', str(user.key.id()))

    def logout(self):
        # remove cookie
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def user_own_post(self, post_id):
        # Test if user is the one that wrote the blog.
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()
        if self.user.key == post.user_post:
            return True
        else:
            return False

    def user_own_comment(self, comment_id):
        # Test if user is the one that wrote the blog.
        key = ndb.Key('Reply', int(comment_id), parent=blog_key())
        post = key.get()
        if self.user.key == post.user:
            return True
        else:
            return False

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


# blog main page
class MainPage(BlogHandler):
    def get(self):
        self.redirect('/blog/')


# key that defines a user group
def users_key(group='default'):
    return ndb.Key('users', group)


class User(ndb.Model):
    """ Create a class to store the user information
    in Google datastore with ndb client """
    name = ndb.StringProperty(required=True)
    pw_hash = ndb.StringProperty(required=True)
    email = ndb.StringProperty()
    phone = ndb.IntegerProperty()

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = cls.query(cls.name == name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None, phone=None):
        pw_hash = security.make_pw_hash(name, pw)
        return cls(parent=users_key(),
                   name=name,
                   pw_hash=pw_hash,
                   email=email,
                   phone=phone)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and security.valid_pw(name, pw, u.pw_hash):
            return u


def blog_key(name='default'):
    return ndb.Key('blogs', name)


class Post(ndb.Model):
    """ Create a class to store all the post information
        in Google datastore with ndb client, also
        use kind=User to point to the User database
        as a many to one relationship """
    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
    user_post = ndb.KeyProperty(kind=User)

    @property
    def user_name(self):
        return self.user_post.get().name

    # replace in template new line in python for new line in html.
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class Reply(ndb.Model):
    """ Create a class to store all the comments
        in Google datastore with ndb client, also
        use kind=User to point to the User database
        as a many to one relationship """
    content = ndb.StringProperty(required=True)
    post_info = ndb.KeyProperty(kind=Post)
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
    user = ndb.KeyProperty(kind=User)

    @property
    def user_replay(self):
        return self.user.get().name


class Likes(ndb.Model):
    """ Create a class to store likes
        in Google datastore with ndb client, I use repeated
        true property in order to save a list of users id. """
    post_info = ndb.KeyProperty(kind=Post)
    user = ndb.IntegerProperty(repeated=True)


class BlogFront(BlogHandler):
    """ Render the main page and queries the most recent
        with a limit of 10. """
    def get(self):
        posts = ndb.gql("select * from Post order by created desc limit 10")
        self.render("blog.html", posts=posts)


class PostPage(BlogHandler):
    """ Create a class display each post individually
        and it handlers the comments,
        likes and deleting each post. """
    def get(self, post_id):
        # get post key
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()
        if not post:
            self.error(404)
            return
        comments = ndb.gql("select * from Reply where post_info = :1 "
                           "order by created desc limit 10", key)
        like = ndb.gql("select * from Likes where post_info= :1", key)
        if self.user:

            if self.user.key == post.user_post:
                self.render("permalink.html",
                            post=post,
                            comments=comments,
                            like=like,
                            user_delete=self.user)
            else:
                self.render("permalink.html",
                            post=post,
                            comments=comments,
                            like=like)
        else:
            self.render("permalink.html",
                        post=post,
                        comments=comments,
                        like=like)

    def post(self, post_id):
        if not self.user:
            return self.redirect('/blog/login')
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()
        error_comment = "The Comment cannot be empty"
        error_like = "You cannot Like your own post"
        # multiple options, if else statement needed.
        number1_button = self.request.get('comment_button')
        number2_button = self.request.get('like_button')
        delete_request = self.request.get('delete')
        if number1_button:
            """ Handles the comment session,
                it test if there is a comment and if the user is login,
                 if true it save it to the database if not
                 it will render permalink with the values already storage """
            comments = self.request.get('comments')
            if comments and self.user:
                save_comment = Reply(parent=blog_key(),
                                     content=comments,
                                     user=self.user.key,
                                     post_info=post.key)
                save_comment.put()
                return self.redirect('/blog/%s' % str(post.key.id()))
            else:
                comments = ndb.gql("select * from Reply where post_info = :1 "
                                   "order by created desc limit 10", key)
                like = ndb.gql("select * from Likes where post_info= :1", key)
                return self.render("permalink.html",
                                   post=post,
                                   comments=comments,
                                   error_comment=error_comment,
                                   like=like,
                                   user_delete=True)
        elif number2_button:
            """ Handles the likes session, it queries the likes
                and test if user exist and if he is
                not the post author in order to add a like. """
            result = Likes.query(Likes.post_info == key).get()
            if self.user:
                """ If is not the same user it will proceed to add it to
                    a python list and stored in datastore,
                    if user id is already in the list it will be
                    removed. """
                if not self.user_own_post(post_id):
                    if result:
                        user_like = result.user
                        if self.user.key.id() in user_like:
                            user_like.remove(self.user.key.id())
                            result.put()
                            return self.redirect('/blog/%s' % str(post.key.id()))
                        else:
                            user_like.append(self.user.key.id())
                            result.put()
                            return self.redirect('/blog/%s' % str(post.key.id()))
                    else:
                        # first time user will make the list.
                        user_list = [self.user.key.id()]
                        some = Likes(parent=blog_key(),
                                     post_info=post.key,
                                     user=user_list)
                        some.put()
                        return self.redirect('/blog/%s' % str(post.key.id()))
                else:
                    # user not login will render the same page again.
                    comments = ndb.gql("select * from Reply "
                                       "where post_info = :1 "
                                       "order by created desc limit 10", key)
                    like = ndb.gql("select * from Likes "
                                   "where post_info= :1", key)
                    return self.render("permalink.html",
                                       post=post,
                                       comments=comments,
                                       error_like=error_like,
                                       like=like,
                                       user_delete=True)
        elif delete_request:
            # delete the blog
            if self.user:
                if self.user_own_post(post_id):
                    post.key.delete()
                    return self.redirect('/blog')
                else:
                    return self.redirect('/blog/%s' % str(post.key.id()))

            else:
                return self.redirect('/blog/login')

    def comments(self, *a, **kw):
        raise NotImplementedError


class NewPost(BlogHandler):
    """This is the class responsible for creating new blog posts"""
    def get(self):
        if self.user:
            return self.render("newpost.html")
        else:
            return self.redirect("/blog/login")

    def post(self):
        if not self.user:
            return self.redirect('/blog')

        subject = self.request.get('title')
        content = self.request.get('blog_content')
        # if there is a post it will be stored in database
        if subject and content:
            p = Post(parent=blog_key(),
                     user_post=self.user.key,
                     subject=subject,
                     content=content)
            p_key = p.put()
            return self.redirect('/blog/%s' % str(p_key.id()))
        else:
            error = "subject and content, please!"
            return self.render("newpost.html",
                               subject=subject,
                               blog_content=content,
                               error=error)


class Signup(BlogHandler):
    """ Class that handles the user signup form
        and test for validations. """
    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        self.phone = self.request.get('phone')
        # dictionary store error messages
        params = dict(username=self.username,
                      email=self.email)
        # validate parameters
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
            return self.render('signup.html', error=have_error, **params)
        else:
            return self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    """ Use the inputs to register the new user
        in datastore """
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            return self.render('signup.html',
                               error_username=msg,
                               error=True)
        else:
            if isinstance(self.phone, int):
                u = User.register(self.username,
                                  self.password,
                                  self.email,
                                  self.phone)
                u.put()
            else:
                u = User.register(self.username,
                                  self.password,
                                  self.email)
                u.put()

            self.login(u)
            return self.redirect('/blog')


class Login(BlogHandler):
    """ Handles the user login form,
        test if username and password match
        with the one in database. """
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            return self.redirect('/blog/')
        else:
            msg = 'Invalid login'
            return self.render('login.html', invalid_login=msg)


class Logout(BlogHandler):
    """ Use this class to logout the user
        by deleting the user cookie. """
    def get(self):
        self.logout()
        return self.redirect('/blog/login')


class ShowUser(BlogHandler):
    """ This class work with base html and
        is designed to reflect the user name
        in the nav bar once the user is logged """
    def get(self):
        if self.user:
            return self.render("base.html", user=self.user.name)
        else:
            pass


class EditHandler(BlogHandler):
    """ Allow users to edit their own posts, if it is
        not their own post it will be redirect it to main page """
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()
        if post:
            if self.user:
                if self.user_own_post(post_id):
                    return self.render("edit_blog.html",
                                       title=post.subject,
                                       blog_content=post.content)
                else:
                    return self.redirect('/blog/')

            else:
                return self.redirect('/blog/login')

    def post(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        self.post = key.get()
        request_update = self.request.get('update')
        cancel_update = self.request.get('cancel')
        if self.user:
            if self.user_own_post(post_id):
                if request_update:
                    update_title = self.request.get("update_title")
                    update_content = self.request.get("update_content")
                    self.post.subject = update_title
                    self.post.content = update_content
                    self.post.put()
                    return self.redirect('/blog/%s' % str(self.post.key.id()))
                elif cancel_update:
                    return self.redirect('/blog')
            else:
                return self.redirect('/blog')
        else:
            return self.redirect('/blog/login')


class EditComment(BlogHandler):
    """ Allow users to edit their own comments, if it is
        not their own post it will be redirect it to main page. """
    def get(self, comment_id):
        key = ndb.Key('Reply', int(comment_id), parent=blog_key())
        comments = key.get()
        if comments:
            if self.user:
                if self.user_own_comment(comment_id):
                    return self.render("edit_comment.html",
                                       blog_content=comments.content)
                else:
                    return self.redirect('/blog')
            else:
                return self.redirect('/blog/login')
        else:
            return self.redirect('/blog')

    def post(self, comment_id):
        key = ndb.Key('Reply', int(comment_id), parent=blog_key())
        comments = key.get()
        if self.user:
            if self.user_own_comment(comment_id):
                request_update = self.request.get('update')
                cancel_update = self.request.get('cancel')
                if request_update:
                    update_content = self.request.get("update_comment")
                    comments.content = update_content
                    comments.put()
                    return self.redirect('/blog/')
                elif cancel_update:
                    return self.redirect('/blog')
            else:
                return self.redirect('/blog')
        else:
            return self.redirect('/blog/login')


class DeleteComment(BlogHandler):
    """ Allow users to delete their own comments, if it is
        not their own post it will be redirect it to main page. """
    def get(self, delete_id):
        key = ndb.Key('Reply', int(delete_id), parent=blog_key())
        comments = key.get()
        if comments:
            if self.user:
                if self.user_own_comment(delete_id):
                    comments.key.delete()
                    return self.redirect('/blog')
                else:
                    return self.redirect('/blog')

            else:
                return self.redirect('/blog/login')
        else:
            return self.redirect('/blog')


class NewBuild(BlogHandler):
    """ handles all future projects that
        are not available at the moment. """
    def get(self):
        self.render("process.html")


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/signup', Register),
                               ('/logout', Logout),
                               ('/blog/login', Login),
                               ('/blog', ShowUser),
                               ('/blog/process', NewBuild),
                               ('/blog/edit/([0-9]+)', EditHandler),
                               ('/blog/comment/([0-9]+)', EditComment),
                               ('/blog/comment_delete/([0-9]+)', DeleteComment)
                               ],
                              debug=True)
#
