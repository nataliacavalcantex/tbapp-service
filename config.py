#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os

def get_env_variable(name):
    try:
        return os.environ[name]
    except KeyError:
        message = "Expected environment variable '{}' not set.".format(name)
        raise Exception(message)

class Config(object):

    DEBUG = True
    SECRET_KEY ='tbapp'
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    SQLALCHEMY_DATABASE_URI = 'postgres://postgres:123@localhost:5555/tbapp'
    # SQLALCHEMY_DATABASE_URI = 'postgres://postgres:qcyxiyaqc@localhost/db_tbapp'

    # app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://ueasistemas:ueasistemas@localhost/ueasistemas'
    # app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
    # app.config['SECRET_KEY'] = 'ueasempre'
