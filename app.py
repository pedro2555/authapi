#!/bin/bash/python3
# -*- coding: utf-8 -*-
from flask import Flask
from flask import request
import os
import base64
import pymysql

app = Flask(__name__)

app.config.update(
    FSD_HOST = os.environ.get('FSD_HOST', ''),
    FSD_PORT = os.environ.get('FSD_PORT', 3306),
    FSD_USER = os.environ.get('FSD_USER', ''),
    FSD_PASS = os.environ.get('FSD_PASS', ''),
    FSD_DB = os.environ.get('FSD_DB', ''))

if 'PORT' in os.environ:
    port = os.environ.get('PORT')
    debug = False
else:
    port = 5000
    debug = True

def decode_auth_header(headers):
    if 'Authorization' not in headers:
        return None

    authorization = headers['Authorization']
    if len(authorization) < 5 or authorization[:5] != 'Basic':
        return None

    return base64.b64decode(authorization[5:]).decode().split(':', 1)

def validate_credentials(username, password):
    db = pymysql.connect(host=app.config['FSD_HOST'],
                         port=app.config['FSD_PORT'],
                         user=app.config['FSD_USER'],
                         passwd=app.config['FSD_PASS'],
                         db=app.config['FSD_DB'])
    cursor = db.cursor()
    command = """
        SELECT `realname`
        FROM `users`
        WHERE `cid`='%s' AND `cpassword`='%s'
    """ % (username, password)

    try:
        loggedin = cursor.execute(command)
    except Exception as err:
        loggedin = 0
        raise err
    finally:
        cursor.close()
        db.close()

    return 'authorized' if loggedin > 0 else None

@app.route('/login')
def login():
    authorization = decode_auth_header(request.headers)
    if not authorization:
        return 'authorization required', 400

    user = validate_credentials(*authorization)
    if not user:
        return 'invalid credentials', 401

    return '4700', 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=port, debug=debug)
