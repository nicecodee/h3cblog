# -*- coding: UTF-8 -*-
from flask import Flask, render_template, flash, request, url_for, session, redirect, session, send_from_directory
from wtforms import Form, BooleanField, TextField, PasswordField, validators
from passlib.hash import sha256_crypt
from MySQLdb import escape_string as thwart
import gc
import datetime, time
from functools import wraps
import json
import os
import requests

from content_mgmt import Content
from dbconnect import connection

TOPIC_DICT = Content()


app = Flask(__name__, instance_path = '/var/www/h3cblog/protected_dir')
app.secret_key = "asfd345treghstrg"

#get the location from user's ip
def get_ip_info(ip):
	
	ip_info = ''
	#淘宝IP地址库接口
	r = requests.get('http://ip.taobao.com/service/getIpInfo.php?ip=%s' %ip)
	if  r.json()['code'] == 0 :
		i = r.json()['data']

		country = i['country']  #国家
		# area = i['area']        #区域
		region = i['region']    #地区
		city = i['city']        #城市
		isp = i['isp']          #运营商
		
		ip_info = country + ' ' + region + ' ' + city + ' ' + isp
		
	return ip_info



#do the logging when a user logs in
def user_enter_log():
	try:
		c, conn = connection()
		
		timestr_filename = time.strftime("%Y%m%d", time.localtime())
		path = '/var/www/h3cblog/protected_dir/logs/' + 'user_accessed_' +  timestr_filename + '.log'
		timestr_logon = time.strftime("%Y/%m/%d-%H:%M:%S %p", time.localtime())

		with open(path, 'a') as file:
			if 'logged_in' in session:
				c.execute("select * from users where username = (%s)", [session['username']])
				
				ip_addr = request.remote_addr
				ip_loc = get_ip_info(ip_addr)
				ip_loc = ip_loc.encode('gbk')  #先解决中文乱码问题
				
				
				#get the user_type of first record
				username_db = c.fetchone()[1] 
				data = timestr_logon + ': user \"' + username_db + '\" (IP:' + ip_addr + ' ' + ip_loc + ') logs on'
				# data = timestr_logon + ': user \"' + username_db + '\" (IP:' + ip_addr + ') logs on'
				file.write(data + '\n') 

	except Exception as e:
		return str(e)
		
		
#do the logging when a user exits
def user_exit_log():
	try:
		c, conn = connection()
		
		timestr_filename = time.strftime("%Y%m%d", time.localtime())
		path = '/var/www/h3cblog/protected_dir/logs/' + 'user_accessed_' +  timestr_filename + '.log'
		timestr_logon = time.strftime("%Y/%m/%d-%H:%M:%S %p", time.localtime())

		with open(path, 'a') as file:
			if 'logged_in' in session:
				c.execute("select * from users where username = (%s)", [session['username']])
				
				ip_addr = request.remote_addr
				ip_loc = get_ip_info(ip_addr)
				ip_loc = ip_loc.encode('gbk')  #先解决中文乱码问题
				
				
				#get the user_type of first record
				username_db = c.fetchone()[1] 
				data = timestr_logon + ': user \"' + username_db + '\" (IP:' + ip_addr + ' ' + ip_loc + ') exits'
				# data = timestr_logon + ': user \"' + username_db + '\" (IP:' + ip_addr + ') logged on'
				file.write(data + '\n') 

	except Exception as e:
		return str(e)		

#do the logging when a user registers
def user_register_log():
	try:
		c, conn = connection()
		
		timestr_filename = time.strftime("%Y%m%d", time.localtime())
		path = '/var/www/h3cblog/protected_dir/logs/' + 'user_accessed_' +  timestr_filename + '.log'
		timestr_logon = time.strftime("%Y/%m/%d-%H:%M:%S %p", time.localtime())

		with open(path, 'a') as file:
			if 'logged_in' in session:
				c.execute("select * from users where username = (%s)", [session['username']])
				
				ip_addr = request.remote_addr
				ip_loc = get_ip_info(ip_addr)
				ip_loc = ip_loc.encode('gbk')  #先解决中文乱码问题
				
				
				#get the user_type of first record
				username_db = c.fetchone()[1] 
				data = timestr_logon + ': user \"' + username_db + '\" (IP:' + ip_addr + ' ' + ip_loc + ') registers and logs on'
				# data = timestr_logon + ': user \"' + username_db + '\" (IP:' + ip_addr + ') logs on'
				file.write(data + '\n') 

	except Exception as e:
		return str(e)		
		

#check if user has logged in
def login_required(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'logged_in' in session:
			return f(*args, **kwargs)
		else:
			#record the url I want to access
			session["want_url"] = request.url
			
			flash("You need to login first")
			return redirect(url_for('login_page'))			
			
	return wrap
	
	
#only logged in user(s) can access the protected directory
@app.route('/protected_dir/<path:filename>')
@login_required
def protected(filename):
	try:
		return send_from_directory(os.path.join(app.instance_path, ''), filename)
	except Exception as e:
		return redirect(url_for('homepage'))

		
	
@app.route("/")
def homepage():
	return  render_template("main.html", title=u'首页')
	
@app.route("/about-team/")
def about_team():
	return  render_template("about-team.html", title=u'团队介绍')
	

@app.route("/comments/")
def comments():
	try:
		error = ''
		# user_enter_log()

		return  render_template("comments.html", title=u'留言板', error = error)
	except Exception as e:
		return str(e)
	

@app.route("/privacy/")
def privacy():
	return  render_template("privacy.html", title=u'网站规定和隐私协议')
	

@app.route("/role-error/")
def role_error_page():
	try:
		user_type_db = ''
		c, conn = connection()
		#Be carefule!! Must use [] to quote session['username'] , otherwise it will
		#prompt a warning like: "not all arguments converted during string formatting"
		c.execute("select * from users where username = (%s)", [session['username']])
		#get the user_type of first record
		user_type_db = c.fetchone()[5] 

		
		return  render_template("role-error.html", title=u'权限错误', user_type_db=user_type_db)	
	except Exception as e:
		return str(e)
	
	
#Server docs viewing
@app.route("/server-dashboard/")
@login_required
def server_dashboard():	
	c, conn = connection()
	#Be carefule!! Must use [] to quote session['username'] , otherwise it will
	#prompt a warning like: "not all arguments converted during string formatting"
	c.execute("select * from users where username = (%s)", [session['username']])
	
	#get the user_type of first record
	user_type_db = c.fetchone()[5]
	
	#check user_type of the logged in user, if not matches, redirect to role_error_page
	if 's' == user_type_db or 'a' == user_type_db:
		return  render_template("server-dashboard.html", title=u'服务器岗文档库', TOPIC_DICT = TOPIC_DICT)
	else:
		return redirect(url_for('role_error_page'))	


@app.route("/server-issue-handle/")
@login_required
def server_issue_handle():
	return  render_template("docs_html/server-issue-handle.html", TOPIC_DICT = TOPIC_DICT)

	
#Network docs viewing	
@app.route("/network-dashboard/")
@login_required
def network_dashboard():	
	c, conn = connection()
	#Be carefule!! Must use [] to quote session['username'] , otherwise it will
	#prompt a warning like: "not all arguments converted during string formatting"
	c.execute("select * from users where username = (%s)", [session['username']])
	
	#get the user_type of first record
	user_type_db = c.fetchone()[5]
	
	#check if user_type matches
	if 'n' == user_type_db or 'a' == user_type_db:
		return  render_template("network-dashboard.html", title=u'网络岗文档库', TOPIC_DICT = TOPIC_DICT)
	else:
		return redirect(url_for('role_error_page'))	
	


#Inventory docs viewing	
@app.route("/inventory-dashboard/")
@login_required
def inventory_dashboard():	
	c, conn = connection()
	#Be carefule!! Must use [] to quote session['username'] , otherwise it will
	#prompt a warning like: "not all arguments converted during string formatting"
	c.execute("select * from users where username = (%s)", [session['username']])
	
	#get the user_type of first record
	user_type_db = c.fetchone()[5]
	
	#check if user_type matches
	if 'i' == user_type_db or 'a' == user_type_db:
		return  render_template("inventory-dashboard.html", title=u'资产岗文档库', TOPIC_DICT = TOPIC_DICT)
	else:
		return redirect(url_for('role_error_page'))	
		
	
@app.errorhandler(404)
def page_not_found(e):
	return  render_template("404.html")
	

	
@app.route("/logout/")
@login_required
def login():
	user_exit_log() #do the logging
	
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
			#Be carefule!! Must use [] to quote thwart(request.form['username']), otherwise it will
			#prompt a warning like: "not all arguments converted during string formatting"
			c.execute("select * from users where username = (%s)", [thwart(request.form['username'])])
			
			#get the password of first record
			pwd_in_db = c.fetchone()[2]
			
			#check if password matches
			if sha256_crypt.verify(request.form['password'], pwd_in_db):
				session['logged_in'] = True
				session['username'] = request.form['username']
				
				user_enter_log()  #do the logging
				flash("You are now logged in!")
				

				#redirect to the exact url I want to access
				return redirect(session["want_url"])

				
			else:
				error = u'身份验证失败，请重试!'
		
		gc.collect()	
		
		return render_template("login.html", title=u'登陆', error=error)
		
	except Exception as e:
		error = error = u'身份验证失败，请重试!'
		return  render_template("login.html", title=u'登陆', error = error)


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
				return render_template('register.html', title=u'注册', form=form)
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
				
				user_register_log() #do the logging
				
				return redirect(url_for('homepage'))
		
		return render_template("register.html", title=u'注册', form=form)
		
	except Exception as e:
		return(str(e))


		
	
if __name__ == "__main__":
	app.run()