from app import db
from sqlalchemy import DateTime
import datetime
class Paciente(db.Model):
    __tablename__ = 'db_paciente'
    paciente_id = db.Column(db.String(32), primary_key=True)
    paciente_cpf= db.Column(db.String(16), unique=True)
    paciente_nome = db.Column(db.String(200),nullable=False)
    paciente_telefone = db.Column(db.String(200),nullable=True)
    paciente_cep = db.Column(db.String(100))
    paciente_endereco= db.Column(db.String(200), nullable=False)
    paciente_nome_mae = db.Column(db.String(200), nullable=False)
    paciente_sexo = db.Column(db.Integer, nullable=False)
    paciente_altura= db.Column(db.String(3))
    paciente_peso = db.Column(db.String(3),nullable=False)
    # paciente_agravo= db.Column(db.Integer,nullable=False)
    paciente_email=db.Column(db.String(200),nullable=False)
    paciente_senha = db.Column(db.Text, nullable=False)
    paciente_horario_medicacao = db.Column(db.String(8))
    paciente_resetPasswordToken = db.Column(db.String(200))
    paciente_data_inicio = db.Column(db.DateTime,default=datetime.datetime.utcnow)
    paciente_data_fim = db.Column(db.DateTime,nullable=True)
    paciente_resetPasswordExpires = db.Column(DateTime, default=datetime.datetime.utcnow)

    tratamento = db.relationship('Tratamento', backref='Paciente', lazy=True)
    agenda = db.relationship('Agenda', backref='Paciente', lazy=True)
class Tratamento(db.Model):
    __tablename__= 'db_tratamento'
    tratamento_id= db.Column(db.String(32), primary_key=True)
    tratamento_receita=db.Column(db.Integer, nullable=False)
    tratamento_ingestao=db.Column(db.Integer, nullable=False)
    tratamento_dia=db.Column(db.String(50), nullable=False)


    tratamento_paciente=db.Column(db.String(32), db.ForeignKey('db_paciente.paciente_id'),nullable=False)

    agenda = db.relationship('Agenda', backref='Tratamento', lazy=True)
class Agenda(db.Model):
    __tablename__='db_agenda'
    agenda_id=db.Column(db.String(32),primary_key=True)
    agenda_status=db.Column(db.Integer,nullable=False)
    agenda_horario_tomado=db.Column(DateTime, default=datetime.datetime.utcnow)

    agenda_tratamento=db.Column(db.String(32), db.ForeignKey('db_tratamento.tratamento_id'),nullable=False)
    agenda_paciente=db.Column(db.String(32), db.ForeignKey('db_paciente.paciente_id'),nullable=False)

if __name__== "__main__":
    db.create_all()