import os
from app import app, db

def criar_banco():
    """Cria o banco de dados e todas as tabelas."""
    with app.app_context():
        db.create_all()
    print("Banco de dados criado com sucesso!")

def excluir_banco():
    """Exclui o banco de dados."""
    db_path = os.path.join(app.instance_path, 'users.db')  # Caminho para o banco de dados
    if os.path.exists(db_path):
        os.remove(db_path)
        print("Banco de dados excluído com sucesso!")
    else:
        print("Banco de dados não encontrado.")

def atualizar_banco():
    """Atualiza o banco de dados (útil para migrações)."""
    with app.app_context():
        db.create_all()  # Recria as tabelas se necessário
    print("Banco de dados atualizado com sucesso!")

if __name__ == "__main__":
    # Menu de opções
    print("Escolha uma opção:")
    print("1 - Criar banco de dados")
    print("2 - Excluir banco de dados")
    print("3 - Atualizar banco de dados")
    opcao = input("Digite o número da opção: ")

    if opcao == "1":
        criar_banco()
    elif opcao == "2":
        excluir_banco()
    elif opcao == "3":
        atualizar_banco()
    else:
        print("Opção inválida.")