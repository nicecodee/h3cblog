# -*- coding: UTF-8 -*-
from flask import Flask, render_template, flash, request, url_for, session, redirect, session
from wtforms import Form, BooleanField, TextField, PasswordField, validators
from passlib.hash import sha256_crypt
from MySQLdb import escape_string as thwart
import gc
import datetime
from functools import wraps
import json

from content_mgmt import Content
from dbconnect import connection

TOPIC_DICT = Content()


app = Flask(__name__)
app.secret_key = "asfd345treghstrg"

def login_required(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'logged_in' in session:
			return f(*args, **kwargs)
		else:
			flash("You need to login first")
			return redirect(url_for('login_page'))
			
	return wrap
	
@app.route("/")
def homepage():
	return  render_template("main.html")
	
@app.route("/about-team/")
def about_team():
	return  render_template("about-team.html")
	

@app.route("/comments/")
def comments():
	return  render_template("comments.html")
	

@app.route("/privacy/")
def privacy():
	return  render_template("privacy.html")
	
#Server docs viewing	
@app.route("/server-dashboard/")
@login_required
def server_dashboard():	
	return  render_template("server-dashboard.html", TOPIC_DICT = TOPIC_DICT)


@app.route("/server-issue-handle/")
@login_required
def server_issue_handle():
	return  render_template("docs_html/server-issue-handle.html", TOPIC_DICT = TOPIC_DICT)

#Network docs viewing	
@app.route("/network-dashboard/")
@login_required
def network_dashboard():	
	return  render_template("network-dashboard.html", TOPIC_DICT = TOPIC_DICT)


#Inventory docs viewing	
@app.route("/inventory-dashboard/")
@login_required
def inventory_dashboard():	
	return  render_template("inventory-dashboard.html", TOPIC_DICT = TOPIC_DICT)


@app.route("/userinfo/")
def userinfo():
	return  render_template("userinfo.html", TOPIC_DICT = TOPIC_DICT)
	
	
@app.errorhandler(404)
def page_not_found(e):
	return  render_template("404.html")
	

	
@app.route("/logout/")
@login_required
def login():
	session.clear()
	flash("You have been logged out!")
	gc.collect()
	return redirect(url_for('homepage'))

	
@app.route("/login/", methods = ['GET','POST'])
def login_page():
	error = ''
	try:
		c, conn = connection()
		if request.method == "POST":
			data = c.execute("select * from users where username = (%s)", [thwart(request.form['username'])])
			
			#get the first record
			data = c.fetchone()[2]
			
			#check if password matches
			if sha256_crypt.verify(request.form['password'], data):
				session['logged_in'] = True
				session['username'] = request.form['username']
				
				flash("You are now logged in!")
				return redirect(url_for('server_dashboard'))
				
			else:
				error = u'身份验证失败，请重试!'
		
		gc.collect()	
		
		return render_template("login.html", error=error)
		
	except Exception as e:
		error = error = u'身份验证失败，请重试!'
		return  render_template("login.html", error = error)


class RegistrationForm(Form):
	username = TextField(u'用户名', [validators.Length(min=4, max=20)])
	email = TextField(u'邮箱', [validators.Length(min=8, max=50)])
	password = PasswordField(u'密码', [validators.Required(),validators.Length(min=6, max=30),
				validators.EqualTo('confirm', message=u'密码不匹配')])	
	confirm = PasswordField(u'重输一遍密码')
	accept_tos = BooleanField(u'我接受<a href="/privacy/">网站规定和隐私协议</a> (最后更新：2016年7月)', [validators.Required()])
		
@app.route("/register/", methods = ['GET','POST'])
def register_page():
	try:
		form = RegistrationForm(request.form)
		
		if request.method == "POST" and form.validate():
			username = form.username.data
			password = sha256_crypt.encrypt((str(form.password.data))) 
			email = form.email.data
			c, conn = connection()
			
			x = c.execute("select * from users where username = (%s)", [thwart(username)])
			
			if int(x) > 0:
				flash("username taken! Try another one!")
				return render_template('register.html', form=form)
			else:
				#get the date of registeration, use China time
				datenow = datetime.datetime.utcnow()
				
				c.execute("insert into users (username, password, email, regdate) values (%s,%s,%s,%s)", (thwart(username), thwart(password), thwart(email), datenow))
				conn.commit()
				
				flash("Thanks for registering!")
				c.close()
				conn.close()
				gc.collect()
				
				session['logged_in'] = True
				session['username'] = username
				
				return redirect(url_for('server_dashboard'))
		
		return render_template("register.html", form=form)
		
	except Exception as e:
		return(str(e))


		
	
if __name__ == "__main__":
	app.run()