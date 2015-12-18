#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import os
import jinja2
import string
import re
import random
import hmac
import time
import hashlib
import logging
from google.appengine.ext import db
from google.appengine.api import memcache
from jinja2.utils import Markup
JINJA_ENVIRONMENT= jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.dirname(__file__)+"/templates"), autoescape=True)

SECRET="XXXXXXXX"
def validCheck(exp,name):
	the_re=re.compile(exp)
	return the_re.match(name)

def make_salt():
	return ''.join(random.choice(string.letters) for x in xrange(5))

def hash_str(s):
	return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
	return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
	val=h.split('|')[0]
	if make_secure_val(val)==h:
		return val

def make_pw_hash(name, pw,salt=''):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
	###Your code here
	return h==make_pw_hash(name,pw,h.split('|')[1])

class Article(db.Model):
	title=db.StringProperty(required=True)
	content=db.TextProperty(required=True)
	user=db.StringProperty(required=False)
	modified=db.DateTimeProperty(auto_now_add=True)
		
class User(db.Model):
	name=db.StringProperty(required=True)
	password=db.StringProperty(required=True)
	email=db.StringProperty(required=False)
	joined=db.DateTimeProperty(auto_now_add=True)

class Handler(webapp2.RequestHandler):
	def write(self,*a,**kw):
		self.response.out.write(*a,**kw)

	def render_str(self, template, **params):
		t=JINJA_ENVIRONMENT.get_template(template)
		return t.render(params)
		
	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

def isLoggedIn(self):
	name= self.request.cookies.get('name')
	if name:
		return check_secure_val(name)
	else:
		self.response.headers.add_header('Set-Cookie',str('name=%s;path=%s;expires=Thu, 01 Jan 1970 00:00:00 GMT' % ('','/')))

def theUser(self):
	if isLoggedIn(self):
		user=self.request.cookies.get('name')
		if user and '|' in user:
			return user.split('|')[0]

class MainHandler(Handler):
	def get(self):
		user=theUser(self)
		content=memcache.get('frontpage')
		if not content:
			article=db.GqlQuery("SELECT content FROM Article where title= :1",'frontpage')
			content=article.get()
			memcache.set('frontpage',content)
		if content:
			self.render('wikipage.html',isLoggedIn=user,user=user,content=content)
		elif user:
			self.redirect('/_edit/')
		else:
			self.render('base.html')

class Signup(Handler):
	def write_form(self,username='',password='',verify='',email='',invalidName='',invalidPass='',invalidVerify='',invalidEmail=''):
		self.render("signup.html",username=username,password=password,verify=verify,email=email,invalidName=invalidName,invalidPass=invalidPass,invalidVerify=invalidVerify,invalidEmail=invalidEmail)

	def get(self):
		if isLoggedIn(self):
			self.redirect('/')
		else:
			self.write_form()
		
	def post(self):
		self.response.headers['Content-Type']='text/plain'
		username=self.request.get('username')
		password=self.request.get('password')
		verify=self.request.get('verify')
		email=self.request.get('email')
		userCheck=validCheck(r"^[a-zA-Z0-9_-]{3,20}$",username)
		passCheck=validCheck(r"^.{3,20}$",password)
		emailCheck=validCheck(r"^[\S]+@[\S]+\.[\S]+$",email)
		checkUser=db.GqlQuery("SELECT * FROM User where name= :1",username)
		checkUser=checkUser.get()
		try:
			checkUser=checkUser.name
		except Exception, e:
			checkUser=None

		if(userCheck and passCheck and (not email or emailCheck) and password==verify and not checkUser):
			user=User(name=username,password=make_pw_hash(username,password))
			user.put()
			self.response.headers.add_header('Set-Cookie',str('name=%s;path=/' % (make_secure_val(username))))
			self.redirect('/')
		else:
			if checkUser:
				usertext='This username is already taken'
			else:
				usertext=''
			passtext=''
			verifytext=''
			emailtext=''
			if(not userCheck):
				usertext='Invalid username'
			if(not passCheck):
				passtext='Invalid password'
			elif(password != verify):
				verifytext="Passwords didn't match"
			if(email and not emailCheck):
				emailtext='Invalid email'

			self.write_form(username,'','',email,usertext,passtext,verifytext,emailtext)

class Login(Handler):
	def get(self):
		if isLoggedIn(self):
			self.redirect('/')
		else:
			self.render("login.html",invalid="")

	def post(self):
		self.response.headers['Content-Type']='text/plain'
		username=self.request.get('username')
		password=self.request.get('password')
		checkUser=db.GqlQuery("SELECT * FROM User where name= :1",username)
		checkUser=checkUser.get()
		if checkUser and valid_pw(username,password,checkUser.password):
			self.response.headers.add_header('Set-Cookie',str('name=%s;path=%s' % (make_secure_val(username),'/')))
			self.redirect('/')
		else:
			self.render("login.html",invalid="Invalid login")

class Logout(Handler):
	def get(self):
		self.response.headers['Content-Type']='text/plain'
		self.response.headers.add_header('Set-Cookie',str('name=%s;path=%s;expires=Thu, 01 Jan 1970 00:00:00 GMT' % ('','/')))
		self.redirect('/login')
		
class EditPage(Handler):
	def get(self):
		title=self.request.path[7:]
		user=theUser(self)
		if user:
			content=memcache.get(title or 'frontpage')
			if content is None:
				article=db.GqlQuery("SELECT content FROM Article where title= :1",title or 'frontpage')
				content=article.get()
			self.render('editpage.html',isLoggedIn=True,content=content or '',user=user)
		else:
			self.redirect('/'+title or '')
			#self.response.out.write('YOU SHOULD LOGIN TO EDIT THIS PAGE')

	def post(self):
		if isLoggedIn(self):
			title=self.request.path[7:]
			content=self.request.get('content')			
			article=Article(title=title or 'frontpage',content=content)
			article.put()
			memcache.set(title or 'frontpage',content)
			self.redirect('/'+title or '')
		else:
			self.redirect('/login')

class WikiPage(Handler):
	def get(self):
		title=self.request.path[1:]
		user=theUser(self)
		content=memcache.get(title)
		if content is None:
			article=db.GqlQuery("SELECT content FROM Article where title= :1",title)
			content=article.get()
		if content is None and user:
			self.redirect('/_edit/'+title)
		else:
			self.render('wikipage.html',isLoggedIn=isLoggedIn(self),content=content,user=user)

app = webapp2.WSGIApplication([
	('/',MainHandler),('/signup',Signup),('/login',Login),('/logout',Logout),
	('/_edit'+r'/(?:[a-zA-Z0-9_-]+)*/?',EditPage),(r'/(?:[a-zA-Z0-9_-]+)*/?',WikiPage)
], debug=True)
