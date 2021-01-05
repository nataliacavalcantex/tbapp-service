[index]: http://flask.pocoo.org/docs/1.0/_images/flaskr_index.png
[login]: http://flask.pocoo.org/docs/1.0/_images/flaskr_login.png
[update]: http://flask.pocoo.org/docs/1.0/_images/flaskr_edit.png
[path]: https://pt.wikipedia.org/wiki/Vari%C3%A1vel_de_ambiente

Fapeam Laboratórios API
============

O aplicativo básico de blog construído no [tutorial](http://flask.pocoo.org/docs/tutorial/) do Flask .

![Alt Imagem da página inicial][index]

Instalar
-------

    # clone the repository
    git clone https://github.com/LUDUSLab/FapeamLabAPI.git
    cd FapeamLabAPI

Crie um virtualenv e ative-o:

    python3 -m venv venv
    source venv/bin/activate

Instale as dependências:

    pip3 install -r requirements.txt
    
Criar o Bando de Dados
-------------

Crei o bando de dados pelo Postgres e atribua as informações de usuário, senha e nome do banco na [variável de ambiente][path] **DATABASE_URL**.

Para criar as tabelas:

```sh
$ python3 -c 'from app import db; db.create_all()'
```

Para excluir as tabelas:

```sh
$ python3 -c 'from app import db; db.drop_all()'
```

Run
---

Definir as veriáveis de ambiente **SECRET_KEY** e **DATABASE**:

    export SECRET_KEY='key'
    export DATABASE_URL='postgresql://username:password@host:port/database'
    export FLASK_ENV=development
    flask run

Open http://127.0.0.1:5000 in a browser.