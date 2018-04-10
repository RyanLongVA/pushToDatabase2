#!/usr/bin/python
# Filename: mysqlfunc.py
# Purpose: All the mysql functions 

# Database errors
import MySQLdb
from MySQLdb import Error
#All the variables for paths
from variables import *

def create_dbConnection():
    try:
        # trying to create a connection with the proceeding connection
        a = MySQLdb.connect(user=databaseUser, passwd=databasePasswd, db=databaseName, unix_socket="/opt/lampp/var/mysql/mysql.sock")
        return a
    except Error as e:
        print(e)
    return None

def sqlExeCommit(conn, statem):
    cur = conn.cursor()
    cur.execute(statem)
    conn.commit()

def sqlCommit(conn):
    conn.commit()

# Only execute 
def sqlExe(cur, statem):
    cur.execute(statem)


# Grab all the domains from a program
def grabDomains(conn, program):
    cur = conn.cursor()
    cur.execute('SELECT Domain FROM %s_liveWebApp'%(program))
    domainsSQL = cur.fetchall()
    domainsList = []
    for a in domainsSQL:
        domainsList.append(str(a).split("'")[1])
    return domainsList
