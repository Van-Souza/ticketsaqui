from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import requests

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Defina uma chave secreta para sessões

# Configuração do Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Página de login

# Configuração da API
API_BASE_URL = "https://homolog.atendeaqui.com.br/api/tickets/"
API_TOKEN = "d0a5a3257169dacffc503c8d8149f6b7381e30ad"
queue_slug = 'avc'

# Mock de banco de dados de usuários (deve ser substituído por um banco real)
users = {'user@example.com': {'password': 'password123'}}

# Modelo de usuário para Flask-Login
class User(UserMixin):
    def __init__(self, id):
        self.id = id

# Carregar o usuário a partir do banco de dados (exemplo simples)
@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# Rota de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Verifica se o usuário e senha são válidos
        if email in users and users[email]['password'] == password:
            user = User(email)
            login_user(user)
            return redirect(url_for('create_ticket'))  # Redireciona para a criação de ticket

        # Caso de erro
        return render_template('login.html', error_message="Usuário ou senha inválidos!")

    return render_template('login.html')

# Rota de logout
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

# Rota para criar ticket (agora com autenticação)
@app.route('/', methods=['GET', 'POST'])
@login_required
def create_ticket():
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

        url = f"{API_BASE_URL}{queue_slug}/"
        headers = {
            "Authorization": f"Bearer {API_TOKEN}",
            "Content-Type": "application/json"
        }
        try:
            response = requests.post(url, json=ticket_data, headers=headers)
            response.raise_for_status()

            return render_template('index.html', success_message="Ticket criado com sucesso!")
        except requests.exceptions.RequestException as e:
            return render_template('index.html', error_message="Falha ao criar o ticket. Tente novamente.")

    return render_template('index.html')

if __name__ == '__main__':
        app.run(host="0.0.0.0", port=5000, debug=True)

