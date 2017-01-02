import os
import re
from string import letters
import webapp2
import jinja2
from google.appengine.ext import db

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


class FrontBlog(BlogHandler):
    def get(self):
        posts = db.GqlQuery("select * from BlogDB order by created desc limit 10")
        self.render("blog.html", posts = posts)


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


class MainPage(BlogHandler):
    def get(self):
        self.render("index.html")


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', FrontBlog),
                               ('/blog/([0-9]+)', SeePost),
                               ('/blog/newpost', NewPost),
                               ],
                              debug=True)