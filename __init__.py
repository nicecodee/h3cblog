# -*- coding: UTF-8 -*-
from flask import Flask, render_template, flash, request, url_for, session,redirect, session, send_from_directory
from wtforms import Form, BooleanField, TextField, PasswordField, validators, RadioField
from wtforms.validators import DataRequired, Length
from passlib.hash import sha256_crypt
from MySQLdb import escape_string as thwart
import gc
import datetime, time
from functools import wraps
# import json
import os
import requests
import sys 
import shutil
from werkzeug import secure_filename
import re
from dbconnect import connection
from config import SECRET_KEY, instance_path, LOGS_PATH,SERVER_DOCS_PATH, NETWORK_DOCS_PATH, INVENTORY_DOCS_PATH, DOCS_PATH, UPLOAD_FOLDER, ALLOWED_EXTENSIONS


app = Flask(__name__)
#when using config.py, ALWAYS remember to assign "SECRET_KEY" and "instance_path" to app!!!
app.secret_key=SECRET_KEY         
# app.instance_path=instance_path

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
		
		ip_info = country + '/' + region + '/' + city + '/' + isp
	return ip_info


@app.template_filter('urlencode')
def urlencode_filter(s):
    if type(s) == 'Markup':
        s = s.unescape()
    s = s.encode('utf8')
    s = urllib.quote_plus(s)
    return Markup(s)	
	
	
#solve the chinese code problem
def	set_cn_encoding():
	reload(sys)
	sys.setdefaultencoding('utf-8')

	
#calculate the number of logs/users/docs for 'sya-admim' badges displaying
def sysadm_badges_number():
	try:
		#Get number of logs and display it with "bootstrap badge"
		loglist = []
		for logfile in os.listdir(LOGS_PATH):
			loglist.append(logfile)
		num_logs = len(loglist)
		
		#Get number of users and display it with "bootstrap badge"
		c, conn = connection()
		c.execute("SELECT * from users;")
		num_users = int(c.rowcount)
		
		#Get number of docs and display it with "bootstrap badge"
		num_docs = sum([len(files) for root,dirs,files in os.walk(DOCS_PATH)])
		
		return(num_logs, num_users, num_docs)
	except Exception as e:
		return str(e)
	
	
	
#do the logging when a user logs in
def write_log_info(info_type):
	try:
		c, conn = connection()
		
		timestr_filename = time.strftime("%Y%m%d", time.localtime())
		path = LOGS_PATH + 'user_accessed_' +  timestr_filename + '.log'
		timestr_logon = time.strftime("%Y/%m/%d-%H:%M:%S-%p", time.localtime())

		with open(path, 'ab') as file:
			if 'logged_in' in session:
				c.execute("select * from users where username = (%s)", [session['username']])
				
				ip_addr = request.remote_addr
				ip_loc = get_ip_info(ip_addr)
				
				#get the auth_type of first record
				username_db = c.fetchone()[1] 
				
				#write logs according to the info_type
				if 'login' == info_type:
					data = timestr_logon + ' ' + username_db + ' ' + ip_addr + '-' + ip_loc + u' 登入'
				elif 'register' == info_type:
					data = timestr_logon + ' ' + username_db + ' ' + ip_addr + '-' + ip_loc + u' 注册并登入'
				elif 'logout' == info_type:
					data = timestr_logon + ' ' + username_db + ' ' + ip_addr + '-' + ip_loc + u' 退出'
				elif 'server' == info_type:
					data = timestr_logon + ' ' + username_db + ' ' + ip_addr + '-' + ip_loc + u' 访问了服务器岗文档'
				elif 'serverDenied' == info_type:
					data = timestr_logon + ' ' + username_db + ' ' + ip_addr + '-' + ip_loc + u' 尝试访问服务器岗文档库被系统拒绝'
				elif 'network' == info_type:
					data = timestr_logon + ' ' + username_db + ' ' + ip_addr + '-' + ip_loc + u' 访问了网络岗文档库'
				elif 'networkDenied' == info_type:
					data = timestr_logon + ' ' + username_db + ' ' + ip_addr + '-' + ip_loc + u' 尝试访问网络岗文档库被系统拒绝'
				elif 'inventory' == info_type:
					data = timestr_logon + ' ' + username_db + ' ' + ip_addr + '-' + ip_loc + u' 访问了资产岗文档库'
				elif 'inventoryDenied' == info_type:
					data = timestr_logon + ' ' + username_db + ' ' + ip_addr + '-' + ip_loc + u' 尝试访问资产岗文档库被系统拒绝'
					
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
			# session["want_url"] = request.url
			
			flash("You need to login first")
			return redirect(url_for('login_page'))			
			
	return wrap
	
	
#only logged in user(s) can access the protected directory
# @app.route('/protected_dir/<path:filename>')
# @login_required
# def protected(filename):
	# try:
		# return send_from_directory(os.path.join(app.instance_path, ''), filename)
	# except Exception as e:
		# return redirect(url_for('homepage'))

		
	
@app.route("/")
def homepage():
	return  render_template("main.html", title=u'首页')
	
@app.route("/about-team/")
def about_team():
	return  render_template("about-team.html", title=u'团队介绍')
	
	
	
@app.route("/sys-admin/")
def sys_admin():
	c, conn = connection()
	#Be carefule!! Must use [] to quote session['username'] , otherwise it will
	#prompt a warning like: "not all arguments converted during string formatting"
	c.execute("select * from users where username = (%s)", [session['username']])
	
	#get the auth_type of first record
	auth_type_db = c.fetchone()[5]
	
	#check auth_type of the logged in user, if not matches, redirect to role_error_page
	if 'superadm' == auth_type_db:
		set_cn_encoding()
		write_log_info('server')
		
		#Get number of logs/users/docs and display them with "bootstrap badge"
		num_logs = (sysadm_badges_number())[0]
		num_users = (sysadm_badges_number())[1]
		num_docs = (sysadm_badges_number())[2]
		
		return  render_template("sys-admin.html", title=u'系统管理', num_logs=num_logs, num_users=num_users, num_docs=num_docs)
	else:
		write_log_info('superadmDenied')
		return redirect(url_for('role_error_page'))	



@app.route('/user-auth-edit/<username>/', methods = ['GET','POST'])
def user_auth_edit(username):
	error = ''
	try:
		set_cn_encoding()
		username=username 
		c, conn = connection()
		if request.method == "POST":
			permit = (request.values.get("user_auth")).encode('utf-8')
		
			#Be carefule!! Must use [] to quote username , otherwise it will
			#prompt a warning like: "not all arguments converted during string formatting"
			c.execute("update users set auth_type='%s' where username='%s'" % (permit,username) )
			conn.commit()
			
			c.close()
			conn.close()
			gc.collect()
			flash('user authorization updated successfully!')
			return  redirect(url_for('users_list'))
		else:
			c, conn = connection()
			c.execute("select * from users where username = (%s)", [username])
			auth_type_db = c.fetchone()[5] 
			
			#Get number of logs/users/docs and display them with "bootstrap badge"
			num_logs = (sysadm_badges_number())[0]
			num_users = (sysadm_badges_number())[1]
			num_docs = (sysadm_badges_number())[2]
			
			return render_template("user-auth-edit.html", title=u'修改权限', auth_type_db=auth_type_db,username=username,
			num_logs=num_logs, num_users=num_users, num_docs=num_docs, error=error)
	
	except Exception as e:
		return str(e)

		
@app.route('/user-delete/<username>/')
@app.route('/user-delete/')
def user_delete(username):
	try:
		set_cn_encoding()
		username=username 
		c, conn = connection()

		#Be carefule!! Must use [] to quote username , otherwise it will
		#prompt a warning like: "not all arguments converted during string formatting"
		# c.execute("delete from users where username='%s'" % (username) )
		c.execute("delete from users where username= (%s)", [username] )
		conn.commit()
		
		c.close()
		conn.close()
		gc.collect()
		flash('user deleted successfully!')
		return  redirect(url_for('users_list'))
	
	except Exception as e:
		return str(e)		

	
		
@app.route("/users-list/")
def users_list():
	try:
		c, conn = connection()

		#get all users
		c.execute("select `username`, `auth_type`, `email`, `regdate`  from users")
		users_db = c.fetchall()
		
		#Get number of logs/users/docs and display them with "bootstrap badge"
		num_logs = (sysadm_badges_number())[0]
		num_users = (sysadm_badges_number())[1]
		num_docs = (sysadm_badges_number())[2]
			
		return render_template("users-list.html", title=u'用户列表', users_db=users_db, num_logs=num_logs, num_users=num_users, num_docs=num_docs)	
	except Exception as e:
		return str(e)


@app.route('/log-delete/<filename>/')
@app.route('/log-delete/')
def log_delete(filename):
	try:
		set_cn_encoding()
		filename = filename 
		filename = LOGS_PATH + filename
		os.remove(filename)

		flash('log deleted successfully!')
		return  redirect(url_for('logs_list'))
	
	except Exception as e:
		return str(e)		
	
	
@app.route("/logs-list/")
def logs_list():
	list = []
	#取得logs目录下的所有文件（列表）
	files = os.listdir(LOGS_PATH)
	#列表按文件名排序
	files.sort(reverse = True)  
	for logfile in files:
		list.append(logfile)
	return  render_template("logs-list.html", title=u'日志列表', list=list)	
		
		
@app.route('/log-show/<filename>/')
@app.route("/log-show/") 
def log_show(filename):
	try:
		set_cn_encoding()
		filename = filename 
		
		list = []
		#取得logs目录下的所有文件（列表）
		files = os.listdir(LOGS_PATH)
		#列表按文件名排序
		files.sort(reverse = True)  
		for logfile in files:
			list.append(logfile)
			
		fn = filename
		
		path = LOGS_PATH + fn
		with open(path, 'r') as file:
			event_lines = file.readlines()

		data = []
		num = len(event_lines)

		for x in range(num):
			data.append(event_lines[x].split(" "))
		
		return  render_template("log-show.html", title=u'查看日志', num=num, data=data, list=list, fn=fn)
		
	except Exception as e: 
		return str(e)
	
	
@app.route("/comments/")
def comments():
	try:
		error = ''

		return  render_template("comments.html", title=u'留言板', error = error)
	except Exception as e:
		return str(e)
	

@app.route("/privacy/")
def privacy():
	return  render_template("privacy.html", title=u'网站规定和隐私协议')
	
	

	
@app.route("/role-error/")
def role_error_page():
	try:
		auth_type_db = ''
		c, conn = connection()
		#Be carefule!! Must use [] to quote session['username'] , otherwise it will
		#prompt a warning like: "not all arguments converted during string formatting"
		c.execute("select * from users where username = (%s)", [session['username']])
		#get the auth_type of first record
		auth_type_db = c.fetchone()[5] 

		
		return  render_template("role-error.html", title=u'权限错误', auth_type_db=auth_type_db)	
	except Exception as e:
		return str(e)


# For a given file, return whether it's an allowed type or not
def doc_allowed(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS		
	

	
# @app.route('/doc-upload/', methods=['GET', 'POST'])
# def doc_upload():
	# try:
		# filename = ''
		# if request.method == 'POST':
			# file = request.files['file']
			# if file and doc_allowed(file.filename):
				# filename = secure_filename(file.filename)
				# file.save(os.path.join(UPLOAD_FOLDER, filename))
				
			# #start to upload
			# send_from_directory(UPLOAD_FOLDER,filename)	
			
			# flash('doc uploaded OK!')
			# return redirect(url_for('docs_dashboard'))
		# return render_template("doc-upload.html", title=u'文档上传')	
	# except Exception as e:
		# return str(e)
		
		
@app.route('/doc-upload/', methods=['GET', 'POST'])
def doc_upload():
	try:
		filename = ''
		if request.method == 'POST':
			file = request.files['file']
			doc_type = (request.values.get("doc_type")).encode('utf-8')
			
			UP_FOLDER = DOCS_PATH + doc_type + '/'
			
			if file and doc_allowed(file.filename):
				filename = secure_filename(file.filename)
				file.save(os.path.join(UP_FOLDER, filename))
			
			#start to upload
			send_from_directory(UP_FOLDER,filename)	
			
			flash('file type is: %s!' % type(filename))
			flash('filename is: %s!' % filename)
			return redirect(url_for('docs_dashboard'))
		return render_template("doc-upload.html", title=u'文档上传')	
	except Exception as e:
		return str(e)

		
		
#main docs viewing
@app.route("/docs-dashboard/")
@login_required
def docs_dashboard():
	#Get number of docs and display it with "bootstrap badge"
	server_list = []
	network_list = []
	inventory_list = []
	for server_file in os.listdir(SERVER_DOCS_PATH):
		server_list.append(server_file)
	for netowrk_file in os.listdir(NETWORK_DOCS_PATH):
		network_list.append(netowrk_file)
	for inventory_file in os.listdir(INVENTORY_DOCS_PATH):
		inventory_list.append(inventory_file)
	num_server = len(server_list)
	num_network = len(network_list)
	num_inventory = len(inventory_list)
	
	return  render_template("docs-dashboard.html", title=u'文档库', num_server=num_server, num_network=num_network, num_inventory=num_inventory)	


@app.route('/doc-type-edit/<filename>/', methods = ['GET','POST'])
def doc_type_edit(filename):
	error = ''
	try:
		filename = filename.encode('utf-8')
		old_doc_type = ''
		
		if request.method == "POST":
			new_doc_type = (request.values.get("doc_type")).encode('utf-8')
			#find the path by the filename
			for root, dirs, files in os.walk(DOCS_PATH):
				for file in files:
					if file == filename:
						old_path_file = "%s/%s" % (root,file)
						old_doc_type = (os.path.split(root))[1]
						break   #if we found it, exit the loop
						
			new_path_file = DOCS_PATH + new_doc_type + '/' + filename
			#copy the old_path_file to new_path_file of new type
			shutil.copy(old_path_file, new_path_file) 
			#remove the old_path_file
			os.remove(old_path_file)
		
			flash('doc type updated successfully!')
			return  redirect(url_for('docs_list'))
		else:
			
			#find the old_doc_type
			for root, dirs, files in os.walk(DOCS_PATH):
				for file in files:
					if file == filename:
						old_doc_type = (os.path.split(root))[1]
						
			#Get number of logs/users/docs and display them with "bootstrap badge"
			num_logs = (sysadm_badges_number())[0]
			num_users = (sysadm_badges_number())[1]
			num_docs = (sysadm_badges_number())[2]
			return render_template("doc-type-edit.html", title=u'修改类型', filename=filename, old_doc_type=old_doc_type, 
			num_logs=num_logs, num_users=num_users, num_docs=num_docs,error=error)

	
	except Exception as e:
		return str(e)	


@app.route('/doc-name-edit/<filename>/', methods = ['GET','POST'])
def doc_name_edit(filename):
	error = ''
	try:
		set_cn_encoding()
		filename = filename.encode('utf-8')
		doc_type = ''
		
		if request.method == "POST":
			new_filename = (request.values.get("doc_name")).encode('utf-8')
			#find the path by the filename
			for root, dirs, files in os.walk(DOCS_PATH):
				for file in files:
					if file == filename:
						doc_path_file = "%s/%s" % (root,file)
						doc_type = (os.path.split(root))[1]
						break   #if we found it, exit the loop
						
			old_path_file = DOCS_PATH + doc_type + '/' + filename
			new_path_file = DOCS_PATH + doc_type + '/' + new_filename + '.pdf'
			#rename the file
			os.rename(old_path_file, new_path_file)
		
			flash('doc renamed successfully!')
			return  redirect(url_for('docs_list'))
		else:
						
			#Get number of logs/users/docs and display them with "bootstrap badge"
			num_logs = (sysadm_badges_number())[0]
			num_users = (sysadm_badges_number())[1]
			num_docs = (sysadm_badges_number())[2]
			return render_template("doc-name-edit.html", title=u'修改文件名', filename=filename,
			num_logs=num_logs, num_users=num_users, num_docs=num_docs,error=error)

	
	except Exception as e:
		return str(e)			
		
		
		
		
@app.route('/doc-delete/<filename>/')
@app.route('/doc-delete/')
def doc_delete(filename):
	try:
		filename = filename.encode('utf-8')
		
		#find the path by the filename
		for root, dirs, files in os.walk(DOCS_PATH):
			for file in files:
				if file == filename:
					filename = "%s/%s" % (root,file)
					break   #if we found it, exit the loop
		#delete the file
		os.remove(filename)

		flash('doc deleted successfully!')
		return  redirect(url_for('docs_list'))
	
	except Exception as e:
		return str(e)	

	
@app.route("/docs-list/")
def docs_list():
	try:
		set_cn_encoding()
		fnlist = []
		dirlist = []
		for root,dirs,files in os.walk(DOCS_PATH):
			for i in files:	
				fnlist.append(i)
				dirlist.append((os.path.split(root))[1])
				
		num_file = len(fnlist)
		
		#Get number of logs/users/docs and display them with "bootstrap badge"
		num_logs = (sysadm_badges_number())[0]
		num_users = (sysadm_badges_number())[1]
		num_docs = (sysadm_badges_number())[2]
			
		return render_template("docs-list.html", title=u'文档列表', num_file=num_file, fnlist=fnlist, dirlist=dirlist, 
		num_logs=num_logs, num_users=num_users, num_docs=num_docs)	
	except Exception as e:
		return str(e)

	
#Server docs viewing
@app.route("/doc-server-dashboard/")
@login_required
def doc_server_dashboard():	
	c, conn = connection()
	#Be carefule!! Must use [] to quote session['username'] , otherwise it will
	#prompt a warning like: "not all arguments converted during string formatting"
	c.execute("select * from users where username = (%s)", [session['username']])
	
	#get the auth_type of first record
	auth_type_db = c.fetchone()[5]
	
	#check auth_type of the logged in user, if not matches, redirect to role_error_page
	if 'ser' == auth_type_db or 'adm' == auth_type_db or 'superadm' == auth_type_db:
		set_cn_encoding()
		write_log_info('server')
		
		doclist = []
		for docfile in os.listdir(SERVER_DOCS_PATH):
			doclist.append(docfile)

		return  render_template("doc-server-dashboard.html", title=u'服务器岗文档库', doclist = doclist)
	else:
		write_log_info('serverDenied')
		return redirect(url_for('role_error_page'))	

# @app.route("/doc-server-show/quote(<filename>)/")		
@app.route("/doc-server-show/<filename>/")
@app.route("/doc-server-show/")
def doc_server_show(filename):	
	set_cn_encoding()
	filename = filename.encode('utf-8')
	
	doclist = []
	for docfile in os.listdir(SERVER_DOCS_PATH):
		doclist.append(docfile)
	return  render_template("doc-server-show.html", title=u'服务器岗文档', filename=filename, doclist=doclist)		
		

@app.route("/doc-network-show/<filename>/")
@app.route("/doc-network-show/")
def doc_network_show(filename):
	set_cn_encoding()
	filename = filename.encode('utf-8')

	doclist = []
	for docfile in os.listdir(NETWORK_DOCS_PATH):
		doclist.append(docfile)
	return  render_template("doc-network-show.html", title=u'网络岗文档', filename=filename, doclist=doclist)	
	

@app.route("/doc-inventory-show/<filename>/")
@app.route("/doc-inventory-show/")
def doc_inventory_show(filename):
	set_cn_encoding()
	filename = filename.encode('utf-8')
	
	doclist = []
	for docfile in os.listdir(INVENTORY_DOCS_PATH):
		doclist.append(docfile)
	return  render_template("doc-inventory-show.html", title=u'资产岗文档', filename=filename, doclist=doclist)

	
#Network docs viewing	
@app.route("/doc-network-dashboard/")
@login_required
def doc_network_dashboard():	
	c, conn = connection()
	#Be carefule!! Must use [] to quote session['username'] , otherwise it will
	#prompt a warning like: "not all arguments converted during string formatting"
	c.execute("select * from users where username = (%s)", [session['username']])
	
	#get the auth_type of first record
	auth_type_db = c.fetchone()[5]
	
	#check if auth_type matches
	if 'net' == auth_type_db or 'adm' == auth_type_db or 'superadm' == auth_type_db:
		set_cn_encoding()
		write_log_info('network')
		
		doclist = []
		for docfile in os.listdir(NETWORK_DOCS_PATH):
			doclist.append(docfile)
		
		return  render_template("doc-network-dashboard.html", title=u'网络岗文档库', doclist = doclist)	
	else:
		write_log_info('networkDenied')
		return redirect(url_for('role_error_page'))	
	


#Inventory docs viewing	
@app.route("/doc-inventory-dashboard/")
@login_required
def inventory_dashboard():	
	c, conn = connection()
	#Be carefule!! Must use [] to quote session['username'] , otherwise it will
	#prompt a warning like: "not all arguments converted during string formatting"
	c.execute("select * from users where username = (%s)", [session['username']])
	
	#get the auth_type of first record
	auth_type_db = c.fetchone()[5]
	
	#check if auth_type matches
	if 'inv' == auth_type_db or 'adm' == auth_type_db or 'superadm' == auth_type_db:
		set_cn_encoding()
		write_log_info('inventory')
		
		doclist = []
		for docfile in os.listdir(INVENTORY_DOCS_PATH):
			doclist.append(docfile)
		
		return  render_template("doc-inventory-dashboard.html", title=u'资产岗文档库', doclist = doclist)			
	else:
		write_log_info('inventoryDenied')
		return redirect(url_for('role_error_page'))	
		
	
@app.errorhandler(404)
def page_not_found(e):
	return  render_template("404.html")
	

	
@app.route("/logout/")
@login_required
def logout():
	write_log_info('logout') #do the logging
	
	session.clear()
	flash("You have been logged out!")
	gc.collect()
	return redirect(url_for('homepage'))

	
@app.route("/login/", methods = ['GET','POST'])
def login_page():
	error = ''
	try:
		set_cn_encoding()	
		
		c, conn = connection()
		if request.method == "POST":
			#Be carefule!! Must use [] to quote thwart(request.form['username']), otherwise it will
			#prompt a warning like: "not all arguments converted during string formatting"
			c.execute("select * from users where username = (%s)", [thwart(request.form['username'])])
			#get the password of first record
			pwd_in_db = c.fetchone()[2]
			
			#get the auth_type_db of logged in user
			c.execute("select * from users where username = (%s)", [thwart(request.form['username'])])
			auth_type_db = c.fetchone()[5]
			
			#check if password matches
			if sha256_crypt.verify(request.form['password'], pwd_in_db):
				session['logged_in'] = True
				session['username'] = request.form['username']
				session['auth_type_db'] = auth_type_db
				
				write_log_info('login')  #do the logging
				flash("You are now logged in!")
				
				#redirect to the exact url I want to access
				# return redirect(session["want_url"])
				
				return redirect(url_for('homepage'))

				
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
		set_cn_encoding()	
		
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

				
				write_log_info('register') #do the logging
				
				return redirect(url_for('homepage'))
		
		return render_template("register.html", title=u'注册', form=form)
		
	except Exception as e:
		return(str(e))


		
	
if __name__ == "__main__":
	app.run()