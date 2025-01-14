from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import os
import logging

# Configuração do Flask
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'supersecretkey')  # Chave secreta para sessões

# Configuração do banco de dados
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Banco de dados SQLite
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Configuração do Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Página de login

# Configuração de logs
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Desativa o cache de templates durante o desenvolvimento
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Modelo de usuário para banco de dados (SQLAlchemy)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Senha criptografada
    token = db.Column(db.String(200), nullable=False)
    queue_slug = db.Column(db.String(100), nullable=False)
    environment = db.Column(db.String(10), nullable=False)  # 'homolog' ou 'prod'

    def __repr__(self):
        return f"<User {self.email}>"

# Carregar o usuário a partir do banco de dados
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Rota de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Verifica se o usuário existe e se a senha está correta
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):  # Verifica a senha criptografada
            login_user(user)
            logger.info(f"Usuário {user.email} fez login.")
            return redirect(url_for('create_ticket'))  # Redireciona para a criação de ticket

        # Caso de erro
        logger.warning(f"Tentativa de login falhou para o e-mail: {email}")
        return render_template('login.html', error_message="Usuário ou senha inválidos!")

    return render_template('login.html')

# Rota de logout
@app.route('/logout')
def logout():
    logout_user()
    logger.info("Usuário fez logout.")
    return redirect(url_for('login'))

# Rota para registro (Cadastro de usuário)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['new_email']
        password = request.form['new_password']
        token = request.form['token']
        queue_slug = request.form['queue_slug']
        environment = request.form['environment']  # Captura o ambiente escolhido

        # Verifica se o usuário já existe
        if User.query.filter_by(email=email).first():
            logger.warning(f"Tentativa de registro com e-mail já existente: {email}")
            return render_template('login.html', error_message="Usuário já existe!")

        # Criptografa a senha antes de salvar
        hashed_password = generate_password_hash(password)

        # Cria o novo usuário e adiciona ao banco de dados
        new_user = User(
            email=email,
            password=hashed_password,
            token=token,
            queue_slug=queue_slug,
            environment=environment  # Salva o ambiente
        )
        db.session.add(new_user)
        db.session.commit()

        # Realiza o login do novo usuário
        login_user(new_user)
        logger.info(f"Novo usuário registrado: {email}")
        return redirect(url_for('create_ticket'))

    return render_template('register.html')

# Rota para criar ticket (agora com autenticação)
@app.route('/', methods=['GET', 'POST'])
@login_required
def create_ticket():
    user = User.query.get(current_user.id)  # Acessa o usuário com o ID correto
    token = user.token
    queue_slug = user.queue_slug
    environment = user.environment  # Obtém o ambiente do usuário

    # Define a URL base com base no ambiente
    if environment == 'homolog':
        base_url = "https://homolog.atendeaqui.com.br/api/tickets/"
    else:
        base_url = "https://atendeaqui.com.br/api/tickets/"

    if request.method == 'POST':
        ticket_data = {
            "title": request.form['title'],
            "description": request.form['description'],
            "submitter": {
                "full_name": request.form['full_name'],
                "email": request.form['email'],
                "phone": request.form['phone'],
            },
            "is_finished": False,
        }

        url = f"{base_url}{queue_slug}/"  # Usa a URL correta
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        try:
            response = requests.post(url, json=ticket_data, headers=headers)
            response.raise_for_status()
            logger.info(f"Ticket criado com sucesso para o usuário {user.email}.")
            return render_template('index.html', success_message="Ticket criado com sucesso!")
        except requests.exceptions.RequestException as e:
            error_message = f"Erro ao criar o ticket: {str(e)}"
            if hasattr(e, 'response') and e.response:
                error_message += f" | Resposta da API: {e.response.text}"
            logger.error(f"Erro ao criar ticket: {error_message}")
            return render_template('index.html', error_message=error_message)

    return render_template('index.html', token=token, queue_slug=queue_slug)

# Rota para editar o token, slug da fila e ambiente
@app.route('/edit_credentials', methods=['GET', 'POST'])
@login_required
def edit_credentials():
    user = User.query.get(current_user.id)  # Acessa o usuário com o ID correto

    if request.method == 'POST':
        # Recuperando os dados do formulário
        new_email = request.form.get('email')
        new_password = request.form.get('password')
        new_token = request.form.get('token')
        new_queue_slug = request.form.get('queue_slug')
        new_environment = request.form.get('environment')  # Captura o novo ambiente

        # Verifica se houve alteração no e-mail, senha, token, slug ou ambiente
        if new_email:
            user.email = new_email

        if new_password:
            hashed_password = generate_password_hash(new_password)
            user.password = hashed_password

        if new_token:
            user.token = new_token

        if new_queue_slug:
            user.queue_slug = new_queue_slug

        if new_environment:
            user.environment = new_environment  # Atualiza o ambiente

        # Salva as alterações no banco de dados
        db.session.commit()
        logger.info(f"Credenciais do usuário {user.email} atualizadas.")
        return redirect(url_for('create_ticket'))  # Redireciona para a criação de ticket

    # Exibe o formulário com os valores atuais do token, slug, e-mail, senha e ambiente
    return render_template('edit_credentials.html', token=user.token, queue_slug=user.queue_slug, email=user.email, environment=user.environment)

if __name__ == '__main__':
    # Cria o banco de dados se não existir, dentro do contexto da aplicação
    with app.app_context():
        db.create_all()

    app.run(host="0.0.0.0", port=5000, debug=True)