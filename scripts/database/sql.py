import mysql.connector as mysql
import json
import datetime


def getConfig(company):

    f = open('config/dbConfig.json')
    data = json.load(f)
    f.close()
    return(data[company])


def insert(data, company, type):

    config = getConfig(company)
    timeStamp = datetime.datetime.now()

    db = mysql.connect(
        host=config['host'],
        user=config['user'],
        passwd=config['password'],
        database=config['database']
    )

    cursor = db.cursor()
    if type == "assets":
        query = "INSERT INTO assetInventory (data, timeStamp) VALUES (%s, %s)"
    elif type == "dangling":
        query = "INSERT INTO danglingDomain (data, timeStamp) VALUES (%s, %s)"
    values = (data, str(timeStamp))
    cursor.execute(query, values)
    db.commit()


def getData(company):
    config = getConfig(company)

    db = mysql.connect(
        host=config['host'],
        user=config['user'],
        passwd=config['password'],
        database=config['database']
    )

    cursor = db.cursor()
    query = "SELECT * FROM assetInventory ORDER BY id DESC LIMIT 1"
    cursor.execute(query)
    data = cursor.fetchall()

    return(data)
