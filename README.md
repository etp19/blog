# Udacity Full Stack Web Developer Nanodegree



## Project: Multi User Blog

This project is a blogging website where people can write blogs about anything, User that are register can also edit, delete
and also delete blog and comments. The website url is https://hello-world-153222.appspot.com

###How to deploy the app:

* In order to deploy the app you will have to download Google App Engine SDK from https://cloud.google.com/appengine/docs/python/download
* Download or clone my Github repository from https://github.com/etp19/blog.git
* To run locally, unsip the content and open the console in the location where you unzip the content.
* Type in the console dev_appserver.py . 
* Go to your favorite internet browser and type http://localhost:8080/blog

### Folders and Files:

####Folders:

- Materialize: This folder contains all the css styles, fonts and javascript files from materialize framework.
- Static: Contains all the custom css styles, fonts and javascript files.
- Templates: This folder contains all the necesary html templates for the application

####Python Files:

- blog.py: Contains the application code including the handlers, models etc.. 
- app.yaml: app configuration
- index.yaml: indexs necessary for the app.
- user_and_password.py: Has the login for test valid users, password and emails.
- security.py: Handles the encryption needed for passwords and cookies. 

### Frameworks and Tools Used:

- Python: Main language used by the web app
- Webapp2: Web framework used to handling routing, request etc..
- Google Datastore (ndb Client): google database for storing blog information such as users, blogs, comments and likes.
- Jinja2: Template Engine library, it allows developers to generate desired content types, such as HTML, 
while using some of the data and programming construcs such as conditionals and for loops to manipulate the output.
- Hmac, hashlib: Used for encryption
- re: Enables regular expression to be used for checking email and password input
- Materialize: Front End framework, it handles the grid system, dynamic and style of the forms and pages in general.

### Future Improvements:

- Create User profiles
- Enables users to upload photos
- Creates categories and be able to filter blogs using them. 
- Work on more styling details.

#### Note:

The site uses ramdom images from http://placekitten.com/ and http://lorempixel.com/ as a placeholder,
in future improvements users will be able to upload their own images.

### Author:

My name is Eduardo Torres and I am a udacity Nanodegree Student and also the guy behind the conntruction of this site.
I am open to any sugestion for improvement, if you have some please email me to torrespe@mail.lcc.edu, any idea is very welcome.


### Aditional Resources and Documentation:

- Google app engine: https://cloud.google.com/appengine/docs
- Datastore NDB Client: https://cloud.google.com/appengine/docs/python/ndb/
- webapp2: https://webapp2.readthedocs.io/en/latest
- jinja2: http://jinja.pocoo.org/docs/2.9/
- Materialize: http://materializecss.com/getting-started.html
- Regular Expression: https://docs.python.org/2/library/re.html
- Encryption: https://docs.python.org/2/library/hmac.html 
   https://docs.python.org/2/library/hashlib.html#module-hashlib
