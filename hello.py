from flask import Flask
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.config['SECRET_KEY'] = 'Fianna'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:jxlgood@localhost/h3cblog' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)


# class H3cuser(db.Model):
		# id=db.Column(db.Integer,primary_key=True) 
		# username=db.Column(db.String(80),unique=True)
		# role=db.Column(db.String(10))
		# updates=db.relationship('Updates',backref='author',lazy='dynamic')

# class Update(db.Model):
		# id=db.Column(db.Integer,primary_key=True)
		# update_week_date=db.Column(db.String(20),unique=True)
		# day6_am=db.Column(db.Text)
		# day6_pm=db.Column(db.Text)
		# day7_am=db.Column(db.Text)
		# day7_pm=db.Column(db.Text)
		# day1_am=db.Column(db.Text)
		# day1_pm=db.Column(db.Text)
		# day2_am=db.Column(db.Text)
		# day2_pm=db.Column(db.Text)
		# day3_am=db.Column(db.Text)
		# day3_pm=db.Column(db.Text)
		# day4_am=db.Column(db.Text)
		# day4_pm=db.Column(db.Text)
		# day5_am=db.Column(db.Text)
		# day5_pm=db.Column(db.Text)		
		# user_id=db.Column(db.Integer,db.ForeignKey('h3cuser.id'))

class H3c_user(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usrname = db.Column(db.String(30), unique=True)
    role = db.Column(db.String(20))
    weekly_update = db.relationship('Weekly_update', backref='user', lazy='dynamic')

    def __init__(self, username, role):
        self.usrname = username
        self.role = role

class Weekly_update(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    update_week_date=db.Column(db.String(20),unique=True)
    day6_am=db.Column(db.Text)
    day6_pm=db.Column(db.Text)
    day7_am=db.Column(db.Text)
    day7_pm=db.Column(db.Text)
    day1_am=db.Column(db.Text)
    day1_pm=db.Column(db.Text)
    day2_am=db.Column(db.Text)
    day2_pm=db.Column(db.Text)
    day3_am=db.Column(db.Text)
    day3_pm=db.Column(db.Text)
    day4_am=db.Column(db.Text)
    day4_pm=db.Column(db.Text)
    day5_am=db.Column(db.Text)
    day5_pm=db.Column(db.Text)
    userId = db.Column(db.Integer, db.ForeignKey('h3c_user.id'))

    def __init__(self, update_week_date, day6_am,day6_pm,day7_am,day7_pm,day1_am,day1_pm,day2_am,day2_pm,day3_am,day3_pm,day4_am,day4_pm,day5_am,day5_pm):
        self.userId = userId
        self.update_week_date = update_week_date
        sellf.day6_am = day6_am
        sellf.day6_pm = day6_pm
        sellf.day7_am = day7_am
        sellf.day7_pm = day7_pm
        sellf.day1_am = day1_am
        sellf.day1_pm = day1_pm
        sellf.day2_am = day2_am
        sellf.day2_pm = day2_pm
        sellf.day3_am = day3_am
        sellf.day3_pm = day3_pm
        sellf.day4_am = day4_am
        sellf.day4_pm = day4_pm
        sellf.day5_am = day5_am
        sellf.day5_pm = day5_pm
		
		