#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask_cors import CORS
from flask import Flask, jsonify, make_response, session
from flask_sqlalchemy import SQLAlchemy #comunicacao com o banco

from config import Config

app = Flask(__name__,static_folder="../build",static_url_path="/")
app.config.from_object(Config)

CORS(app,origins='*')
db = SQLAlchemy(app)

@app.route('/')
def hello():
    return 'Oi'
    
@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return make_response(jsonify({'error': 'Internal Server Error2'}), 500)

from controllers import *
