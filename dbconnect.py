import MySQLdb

def connection():
	conn = MySQLdb.connect(host="localhost", user="root", passwd="jxlgood", db="h3cblog")
	c = conn.cursor()
	return c, conn