from hello import db, app

class User_h3c(db.Model):
		id=db.Column(db.Integer,primary_key=True) 
		username=db.Column(db.String(80),unique=True)
		role=db.Column(db.String(10))
		posts=db.relationship('Weekly_update',backref='author',lazy='dynamic')

class Weekly_update(db.Model):
		id=db.Column(db.Integer,primary_key=True)
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
		user_id=db.Column(db.Integer,db.ForeignKey('user_h3c.id'))