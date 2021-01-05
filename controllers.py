#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import re
import jwt
import datetime
import hashlib
from flask_cors import CORS
from werkzeug.utils import secure_filename
from flask import Flask, jsonify, request, make_response, send_file, session,render_template
from functools import wraps
from flask_sqlalchemy import SQLAlchemy #comunicacao com o banco
import smtplib
import secrets
import time 
from datetime import datetime
import webbrowser 
from models import *
from app import app, db
from functools import wraps


CORS(app,origins='*')
##decorators##

#API KEY
def require_appkey(view_function):
    @wraps(view_function)
    # the new, post-decoration function. Note *args and **kwargs here.
    def decorated_function(*args, **kwargs):
        with open('api.key', 'r') as apikey:
            key=apikey.read().replace('\n', '')
        #if request.args.get('key') and request.args.get('key') == key:
        if request.headers.get('x-api-key') and request.headers.get('x-api-key') == key:
            return view_function(*args, **kwargs)
        else:
            response = make_response(jsonify({'message': 'Não autorizado'}), 401)
            return response
    return decorated_function

#USER TOKEN
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            response = make_response(jsonify({'message': 'Token is missing!'}), 401)
            response.headers['Access-Control-Allow-Origin'] = '*'
            return response

        try:
            data = jwt.decode(token, 'tbapp')
            
            current_user = Paciente.query.filter_by(paciente_id=data['paciente_id']).first()
        except:
            response = make_response(jsonify({'message': 'Token is missing!'}), 401)
            response.headers['Access-Control-Allow-Origin'] = '*'
            return response
        # print(current_user)
        return f(current_user, *args, **kwargs)
        
    return decorated
# alarm

##routes##
#LOGIN
@app.route('/login')
@require_appkey
def login():
    auth = request.authorization
    erro = None

    if ((not auth) or (not auth.username) or (not auth.password)):
        erro = 'Login required.'

    paciente = Paciente.query.filter_by(paciente_cpf = auth.username).first()
    print(paciente)
    
    if (not paciente):
        erro = 'cpf não cadastrado no sistema.'
    
    elif (not (paciente.paciente_senha == auth.password)):
        erro = 'Senha Incorreta'

    if (erro is None):
        token = jwt.encode({'paciente_id': paciente.paciente_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, 'tbapp')
        response = make_response(jsonify({'token': token.decode('UTF-8'), 'canLogin':True}))
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response

    response = make_response(jsonify({'erro':erro}), 401)
    response.headers['WWW-Authenticate'] = 'Basic realm={}'.format(erro)
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

#CADASTRO
@app.route('/register', methods=['POST'])
@require_appkey
def create_paciente():
    
    data = request.get_json()

    if(db.session.query(Paciente.paciente_id).filter_by(paciente_cpf=data['cpf']).scalar() is not None):
        response = make_response(jsonify({'message': 'cpf ja cadastrado!'}), 401)
        return response

    regexName = re.compile(r'^([A-ZÁ-ÚÂ-Ûã-ũa-zá-úâ-ûã-ũ]*\s)+([A-ZÁ-ÚÂ-Ûã-ũa-zá-úâ-ûã-ũ]*)$')
    if regexName.match(data['name']) is not None:
        nome = data['name']
    else:
        response = make_response(jsonify({'message': 'Nome inválido'}), 500)
        return response
    regexEmail = re.compile(r'^[a-zA-Z0-9][^@<>={}()]*@[^@]*\.[^@]*$')
    if regexEmail.match(data['email']) is not None:
        email = data['email']
    else:
        response = make_response(jsonify({'message': 'Link de email inválido'}), 500)
        return response
    regexPassword = re.compile(r'[A-Za-z0-9@#$%^&+=]{8,}$')
    if regexPassword.match(data['password']) is not None:
        password = data['password']
    else:
        response = make_response(jsonify({'message': 'Senha inválida'}), 500)
        return response

    # # regexTelefone = re.compile(r'^\(\w{2}\)\w{5}-\w{4}$')
    # if regexTelefone.match(data['telefone']) is not None:
    #     telefone = data['telefone']
    # else:
    #     response = make_response(jsonify({'message': 'Link telefone'}), 500)
    #     return response

    novo_paciente = Paciente(
    paciente_id = hashlib.md5((data['cpf']+datetime.datetime.utcnow().isoformat(' ')).encode('utf-8')).hexdigest(),
    paciente_cpf=data['cpf'],
    paciente_nome=nome,
    paciente_email=data['email'],
    paciente_senha=data['password'],
    paciente_peso=data['peso'],
    paciente_altura=data['altura'],
    paciente_cep=data['cep'],
    paciente_telefone=data['telefone'],
    paciente_endereco=data['endereco'],
    paciente_sexo=data['sexo'],
    paciente_nome_mae=data['nome_mae'],
    paciente_horario_medicacao=data['horarioMed'])

    print(novo_paciente.paciente_cpf)
    db.session.add(novo_paciente)
    db.session.commit()
    response = make_response(jsonify({'message': 'Paciente Cadastrado!', 'cpf':novo_paciente.paciente_cpf}))
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

#EDITAR CADASTRO
@app.route('/editprofile', methods=['PUT'])
@token_required
@require_appkey
def update_aluno(current_user):
    data = request.get_json()
    paciente = Paciente.query.filter_by(paciente_id=current_user.paciente_id).first()

    
    regexName = re.compile(r'^([A-ZÁ-ÚÂ-Ûã-ũa-zá-úâ-ûã-ũ]*\s)+([A-ZÁ-ÚÂ-Ûã-ũa-zá-úâ-ûã-ũ]*)$')
    if regexName.match(data['name']) is not None:
        nome = data['name']
    else:
        response = make_response(jsonify({'message': 'Nome inválido'}), 500)
        return response

    regexEmail = re.compile(r'^[a-zA-Z0-9][^@<>={}()]*@[^@]*\.[^@]*$')
    if regexEmail.match(data['email']) is not None:
        email = data['email']
    else:
        response = make_response(jsonify({'message': 'Link de email inválido'}), 500)
        return response
    
    regexPassword = re.compile(r'^^([0-9A-Za-z]{6,})$')
    if regexPassword.match(data['password']) is not None:
        password = data['password']
    else:
        
        response = make_response(jsonify({'message': 'Nome inválido'}), 500)
        return response


    regexTelefone = re.compile(r'^[0-9]*$')
    if regexTelefone.match(data['telefone']) is not None:
        telefone = data['telefone']
    else:
        response = make_response(jsonify({'message': 'Numero de telefone'}), 500)
        return response

    paciente.paciente_email=data['email']
    paciente.paciente_nome=nome
    paciente.paciente_peso=data['peso']
    paciente.paciente_telefone=telefone
    paciente.paciente_endereco=data['endereco']
    paciente.paciente_senha=password
    paciente.paciente_horario_medicacao=data['horaMed']

    

    db.session.add(paciente)
    db.session.commit()

    response = make_response(jsonify({'message': 'paciente Cadastrado!', 'id':paciente.paciente_id}))
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

#OBTER PERFIL-
@app.route('/paciente', methods=['GET'])
@require_appkey
@token_required
def paciente(current_user):
    paciente = Paciente.query.filter_by(paciente_id=current_user.paciente_id).first()
    print('paciente',paciente)
    if(paciente == None):
        return 'Usuário não encontrado!'
        
    output = {
 
        'cpf': paciente.paciente_cpf, 
        'nome':paciente.paciente_nome,
        'peso':paciente.paciente_peso
        }

    response = make_response(jsonify(output))
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

#PERFIL COM LOGIN- my profile
@app.route('/profile', methods=['GET'])
@token_required
@require_appkey
def perfilpaciente(current_user):
 
    output = {
        'cpf': current_user.paciente_cpf, 
        'name': current_user.paciente_nome,
        'email': current_user.paciente_email, 
        'peso': current_user.paciente_peso,
        'cep': current_user.paciente_cep,
        'telefone' : current_user.paciente_telefone, 
        'sexo' : current_user.paciente_sexo, 
        'altura':current_user.paciente_altura,
        'peso':current_user.paciente_peso,
        'endereco' : current_user.paciente_endereco,
        'nomeMae' : current_user.paciente_nome_mae, 
        'horarioMed' : current_user.paciente_horario_medicacao,
        'inicio':current_user.paciente_data_inicio,
        'fim':current_user.paciente_data_fim,
    }

    response = make_response(jsonify(output))
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

# MODIFICAR A SENHA
@app.route('/forgotPassword', methods=['POST'])
@require_appkey
def forgot_password():
    data = request.get_json()
    
    # verifica se há um email no sistema
    paciente = Paciente.query.filter_by(paciente_email = (data['email'])).first()
    
    erro = None
    if (paciente == None):
        
        erro = 'O email não está cadastrado'
        response = make_response(jsonify({'message': erro}))    
    else:    
        token = hashlib.md5(os.urandom(20)).hexdigest()
        
        print('TOKEN::',token)
        print('EMAIL::',data["email"])
        # envio do email
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login("","") #muda isso aqui
        message ="Subject: Tbapp - Recuperar a senha\n\nVocê solicitou a recuperação de sua senha de acesso ao sistema Tbapp.\nClique no link abaixo para cadastrar uma nova senha:\nhttp://localhost:3000/#/ueasempre/ResetPasswordPage/"+token+""

        server.sendmail(
	        '', #muda isso aqui
	        data["email"],
	        message.encode('utf-8')
        )

        server.quit()

        paciente.paciente_resetPasswordToken = token
        paciente.paciente_resetPasswordExpires = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)

        db.session.add(paciente)
        db.session.commit()
        response = make_response(jsonify({'message': "enviado com sucesso"}))
        print("enviou o email")

    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

@app.route("/verifyPasswordToken", methods=['POST'])
def verifyTokenPassword():
    data = request.get_json()
    print(data["token"])
    
    paciente = Paciente.query.filter_by(paciente_resetPasswordToken = (data['token'])).first()
    if (paciente is None):
        erro = 'Token não encontrado'
        response = make_response(jsonify({'message': erro}))   
    else:
        if(paciente.paciente_resetPasswordExpires< datetime.datetime.utcnow()):
            erro = 'Token expirou, envie o email novamente'
            response = make_response(jsonify({'message': erro}))   
        else:
            
            output = {
                'nome': paciente.paciente_nome, 
                'email': paciente.paciente_email, 
                'cpf': paciente.paciente_id, 
            }
            response = make_response(jsonify({"paciente":output,'message': "token correto"}))
    
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

@app.route("/updatePasswordViaEmail",methods=['PUT'])
@require_appkey
def updatePasswordViaEmail():
    data = request.get_json()
    print(data['password'])
    paciente = Paciente.query.filter_by(paciente_id=data["cpf"]).first()
    if(paciente==None):
        response = make_response(jsonify({'message': "aluno não encontrado"}))
    else:
        paciente.paciente_senha = data['password']
        paciente.paciente_resetPasswordExpires = None
        paciente.paciente_resetPasswordToken = None
        db.session.add(paciente)
        db.session.commit()
        response = make_response(jsonify({'message': "senha alterada com sucesso"}))
        
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

#registrar tratamento na  agenda

@app.route('/register/tratamento',methods=['POST'])
@token_required
def register_tratamento(current_user):
    data = request.get_json()
    current_tratamento=Tratamento.query.filter_by(tratamento_paciente=current_user.paciente_id).first()
    
    print(current_tratamento)
    
    novo_tratamento=Tratamento(tratamento_id=hashlib.md5((current_user.paciente_cpf+datetime.datetime.utcnow().isoformat(' ')).encode('utf-8')).hexdigest(),tratamento_receita=5,tratamento_ingestao=data['ingestao'],tratamento_dia=data['dia'],tratamento_paciente=current_user.paciente_id)
   
    db.session.add(novo_tratamento)
    db.session.commit()


    response = make_response(jsonify({'message': 'Tratamento Cadastrado!', 'id':novo_tratamento.tratamento_id}))
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response
@app.route('/tratamento/<string:dia>',methods=['GET'])
@token_required
@require_appkey
def get_tratamento(current_user,dia):
    
    tratamentos = Tratamento.query.filter_by(tratamento_paciente=current_user.paciente_id).filter_by(tratamento_dia=dia).order_by(Tratamento.tratamento_ingestao.desc()).first()
    
    print(tratamentos)
    if not (tratamentos.tratamento_ingestao):
        tratamentos.tratamento_ingestao=0
    output={
            'Ingestao':tratamentos.tratamento_ingestao,
            'Receita':tratamentos.tratamento_receita,
            
    }
        
    response = make_response(jsonify(output))
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response


@app.route('/getalarme') 
@require_appkey
@token_required
def getalarme(current_user):
    paciente = Paciente.query.filter_by(paciente_id=current_user.paciente_id).first()
    Set_Alarm = paciente.paciente_horario_medicacao
   
    response = make_response(jsonify({'message': 'Alarme Tocado ','Set_Alarm':Set_Alarm}))
    return response

@app.route('/datas/<string:dates>', methods=['GET'])
@require_appkey
@token_required
def all_dates(current_user,dates):

    tratamentos = Tratamento.query.filter_by(tratamento_paciente=(current_user.paciente_id)).filter(Tratamento.tratamento_dia.like('%'+dates+'%')).order_by(Tratamento.tratamento_ingestao.desc()).all()
    print(tratamentos)
    output = []
    for tratamento in tratamentos:
        d = {
            'dias': tratamento.tratamento_dia,
            'ingestao':tratamento.tratamento_ingestao
            
        }

        output.append(d)
    
    return jsonify(output)
    # return 'foi'

@app.route('/uploads', methods=['POST'])
def upload():
    target=os.path.join('imgs/uploads')
    # print(target)
    if not os.path.isdir(target):
        os.mkdir(target)
    file = request.files['file']

    filename = request.form['filename']
    # print(file.content_type)
    destination="/".join([target, filename])
    # print(destination)
    if os.path.isfile(destination):
        os.remove(destination)
    file.save(destination)
    session['uploadFilePath']=destination
    response = make_response(jsonify({'message': destination}))
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

static_file_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'static')

#PEGAR FOTO SALVO
@app.route('/imgs/uploads/<string:path>', methods=['GET'])

def serve_file_in_dir(path):
    if(os.path.isfile('imgs/uploads/' + path)):
        return send_file('imgs/uploads/' + path)
    else:
        response = make_response(jsonify({'message': 'File not found!'}), 404)
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response