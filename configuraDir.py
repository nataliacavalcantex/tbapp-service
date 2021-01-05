import os

if not(os.path.exists('img')):
    os.makedirs('img/uploads')
    print("Criando diretorio img/uploads")

print('ok')