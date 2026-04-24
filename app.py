# ==================================================
# IMPORTS
# ==================================================
import os
import re
import smtplib
import mysql.connector

from flask import Flask, render_template, request, redirect, session, url_for
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from functools import wraps
from email.mime.text import MIMEText
from werkzeug.security import generate_password_hash, check_password_hash


# ==================================================
# CONFIGURAÇÃO DA APP
# ==================================================
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")


# ==================================================
# CONFIGURAÇÃO DO LOGIN GOOGLE
# ==================================================
oauth = OAuth(app)

google = oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"}
)


# ==================================================
# BASE DE DADOS
# ==================================================
def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("MYSQLHOST"),
        port=os.getenv("MYSQLPORT"),
        user=os.getenv("MYSQLUSER"),
        password=os.getenv("MYSQLPASSWORD"),
        database=os.getenv("MYSQLDATABASE")
    )

# ==================================================
# FUNÇÕES AUXILIARES
# ==================================================
def detectar_tipo_utilizador(email):
    email = email.strip().lower()

    if email == "schooleventsadm@gmail.com":
        return "admin"

    if re.match(r"^[A-Za-z0-9]+profschoolevents@gmail\.com$", email):
        return "professor"

    if re.match(r"^[A-Za-z0-9]+schoolevents@gmail\.com$", email):
        return "aluno"

    return None


def enviar_email(destinatario, assunto, mensagem):
    try:
        remetente = os.getenv("EMAIL_REMETENTE")
        senha = os.getenv("EMAIL_SENHA")

        if not remetente or not senha:
            print("EMAIL_REMETENTE ou EMAIL_SENHA não definidos no .env")
            return False

        msg = MIMEText(mensagem, "plain", "utf-8")
        msg["Subject"] = assunto
        msg["From"] = remetente
        msg["To"] = destinatario

        servidor = smtplib.SMTP("smtp.gmail.com", 587)
        servidor.starttls()
        servidor.login(remetente, senha)
        servidor.send_message(msg)
        servidor.quit()

        print(f"Email enviado com sucesso para {destinatario}")
        return True

    except Exception as e:
        print("Erro ao enviar email:", e)
        return False


# ==================================================
# DECORADORES DE ACESSO
# ==================================================
def login_required(tipo):
    def wrapper(func):
        @wraps(func)
        def decorated(*args, **kwargs):
            if "email" not in session:
                return redirect(url_for("select_login"))

            if session.get("tipo") != tipo:
                return "Acesso negado"

            return func(*args, **kwargs)
        return decorated
    return wrapper


def role_required(*roles):
    def wrapper(func):
        @wraps(func)
        def decorated(*args, **kwargs):
            if "email" not in session:
                return redirect(url_for("select_login"))

            if session.get("tipo") not in roles:
                return "Acesso negado"

            return func(*args, **kwargs)
        return decorated
    return wrapper


# ==================================================
# AUTENTICAÇÃO
# ==================================================

# ---------------- LOGIN MANUAL ----------------
@app.route("/", methods=["GET", "POST"])
def select_login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")

        tipo = detectar_tipo_utilizador(email)

        if not tipo:
            return render_template("login.html", erro="Email não autorizado.")

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT * FROM Utilizador
            WHERE email = %s
        """, (email,))
        utilizador = cursor.fetchone()

        cursor.close()
        conn.close()

        if not utilizador:
            return render_template("login.html", erro="Utilizador não encontrado.")

        if not utilizador["senha_hash"]:
            return render_template("login.html", erro="Esta conta ainda não tem palavra-passe local definida.")

        if not check_password_hash(utilizador["senha_hash"], senha):
            return render_template("login.html", erro="Senha incorreta.")

        session["email"] = utilizador["email"]
        session["user_id"] = utilizador["id"]
        session["tipo"] = utilizador["tipo_utilizador"]

        return redirect(f"/painel_{utilizador['tipo_utilizador']}")

    return render_template("login.html")


# ---------------- CRIAR CONTA ----------------
@app.route("/criar_conta", methods=["GET", "POST"])
def criar_conta():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")

        tipo = detectar_tipo_utilizador(email)

        if not tipo:
            return render_template("criar_conta.html", erro="Email não autorizado.")

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM Utilizador WHERE email = %s", (email,))
        utilizador_existente = cursor.fetchone()

        senha_hash = generate_password_hash(senha)

        if utilizador_existente:
            if utilizador_existente["auth_provider"] == "google":
                cursor.execute("""
                    UPDATE Utilizador
                    SET senha_hash = %s,
                        auth_provider = 'ambos'
                    WHERE email = %s
                """, (senha_hash, email))
                conn.commit()

                cursor.close()
                conn.close()
                return redirect(url_for("select_login"))

            cursor.close()
            conn.close()
            return render_template("criar_conta.html", erro="Email já existe.")

        cursor.execute("""
            INSERT INTO Utilizador (email, senha_hash, auth_provider, tipo_utilizador)
            VALUES (%s, %s, 'local', %s)
        """, (email, senha_hash, tipo))

        conn.commit()
        cursor.close()
        conn.close()

        return redirect(url_for("select_login"))

    return render_template("criar_conta.html")


# ---------------- LOGIN GOOGLE ----------------
@app.route("/login")
def login():
    return google.authorize_redirect(url_for("authorize", _external=True))


@app.route("/authorize")
def authorize():
    token = google.authorize_access_token()
    user = token["userinfo"]
    email = user["email"].strip().lower()
    google_id = user.get("sub")

    tipo = detectar_tipo_utilizador(email)

    if not tipo:
        return render_template("nao_autorizado.html")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM Utilizador WHERE email = %s", (email,))
    utilizador = cursor.fetchone()

    if not utilizador:
        cursor.execute("""
            INSERT INTO Utilizador (email, senha_hash, google_id, auth_provider, tipo_utilizador)
            VALUES (%s, NULL, %s, 'google', %s)
        """, (email, google_id, tipo))
        conn.commit()

        cursor.execute("SELECT * FROM Utilizador WHERE email = %s", (email,))
        utilizador = cursor.fetchone()

    else:
        novo_provider = utilizador["auth_provider"]

        if utilizador["auth_provider"] == "local":
            novo_provider = "ambos"
        elif utilizador["auth_provider"] == "google":
            novo_provider = "google"
        elif utilizador["auth_provider"] == "ambos":
            novo_provider = "ambos"

        cursor.execute("""
            UPDATE Utilizador
            SET google_id = %s,
                auth_provider = %s
            WHERE email = %s
        """, (google_id, novo_provider, email))
        conn.commit()

        cursor.execute("SELECT * FROM Utilizador WHERE email = %s", (email,))
        utilizador = cursor.fetchone()

    cursor.close()
    conn.close()

    session["email"] = utilizador["email"]
    session["user_id"] = utilizador["id"]
    session["tipo"] = utilizador["tipo_utilizador"]

    return redirect(f"/painel_{utilizador['tipo_utilizador']}")


# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("select_login"))


# ==================================================
# ROTAS DO ALUNO
# ==================================================

# ---------------- PAINEL ALUNO ----------------
@app.route("/painel_aluno")
@login_required("aluno")
def painel_aluno():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT p.*, 
               u.email AS professor_email,
               (
                   SELECT COUNT(*)
                   FROM Inscricoes
                   WHERE projeto_id = p.id
                     AND aluno_id = %s
               ) AS inscrito
        FROM ProjetosEscolares p
        JOIN Utilizador u ON p.professor_id = u.id
        WHERE p.estado = 'aprovado'
    """, (session["user_id"],))

    eventos = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "painel_aluno.html",
        nome_aluno=session.get("email"),
        eventos=eventos
    )


# ---------------- INSCREVER EM PROJETO ----------------
@app.route("/inscrever/<int:projeto_id>")
@login_required("aluno")
def inscrever_evento(projeto_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO Inscricoes (projeto_id, aluno_id)
            VALUES (%s, %s)
        """, (projeto_id, session["user_id"]))
        conn.commit()
    except mysql.connector.Error:
        pass

    cursor.close()
    conn.close()

    return redirect("/painel_aluno")


# ---------------- DESINSCREVER DE PROJETO ----------------
@app.route("/desinscrever/<int:projeto_id>", methods=["POST"])
@login_required("aluno")
def desinscrever_evento(projeto_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM Inscricoes
        WHERE projeto_id = %s AND aluno_id = %s
    """, (projeto_id, session["user_id"]))

    conn.commit()

    cursor.close()
    conn.close()

    return redirect("/painel_aluno")


# ---------------- ENVIAR DÚVIDA ----------------
@app.route("/enviar_duvida/<int:projeto_id>", methods=["POST"])
@login_required("aluno")
def enviar_duvida(projeto_id):
    pergunta = request.form.get("pergunta")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        INSERT INTO Duvidas (projeto_id, aluno_id, pergunta)
        VALUES (%s, %s, %s)
    """, (projeto_id, session["user_id"], pergunta))
    conn.commit()

    cursor.execute("""
        SELECT u.email AS professor_email, p.titulo_proj
        FROM ProjetosEscolares p
        JOIN Utilizador u ON p.professor_id = u.id
        WHERE p.id = %s
    """, (projeto_id,))
    professor = cursor.fetchone()

    if professor and professor["professor_email"]:
        enviar_email(
            professor["professor_email"],
            "Nova dúvida enviada por um aluno",
            f"Recebeste uma nova dúvida sobre o projeto '{professor['titulo_proj']}':\n\n{pergunta}\n\nAluno: {session['email']}"
        )

    cursor.close()
    conn.close()

    return redirect("/painel_aluno")

# ---------------- DÚVIDA ALUNO ----------------
@app.route("/minhas_duvidas")
@login_required("aluno")
def minhas_duvidas():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT d.*, p.titulo_proj
        FROM Duvidas d
        JOIN ProjetosEscolares p ON d.projeto_id = p.id
        WHERE d.aluno_id = %s
        ORDER BY d.data_envio DESC
    """, (session["user_id"],))

    duvidas = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("duvidas.html", duvidas=duvidas)


# ==================================================
# ROTAS DO PROFESSOR
# ==================================================

# ---------------- PAINEL PROFESSOR ----------------
@app.route("/painel_professor")
@login_required("professor")
def painel_professor():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT p.*, COUNT(i.id) AS total_inscritos
        FROM ProjetosEscolares p
        LEFT JOIN Inscricoes i ON p.id = i.projeto_id
        WHERE p.professor_id = %s
        GROUP BY p.id
        ORDER BY p.id DESC
    """, (session["user_id"],))
    meus_eventos = cursor.fetchall()

    cursor.execute("""
        SELECT p.*, u.email AS professor_email, COUNT(i.id) AS total_inscritos
        FROM ProjetosEscolares p
        JOIN Utilizador u ON p.professor_id = u.id
        LEFT JOIN Inscricoes i ON p.id = i.projeto_id
        WHERE p.professor_id <> %s
          AND p.estado = 'aprovado'
        GROUP BY p.id
        ORDER BY p.id DESC
    """, (session["user_id"],))
    eventos_outros = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "painel_professor.html",
        nome_professor=session.get("email"),
        eventos=meus_eventos,
        eventos_outros=eventos_outros
    )


# ---------------- CRIAR EVENTO ----------------
@app.route("/criar_evento", methods=["GET", "POST"])
@login_required("professor")
def criar_evento():
    if request.method == "POST":
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO ProjetosEscolares
            (titulo_proj, descricao_proj, data_proj, horario_proj, local_proj, professor_id, estado)
            VALUES (%s, %s, %s, %s, %s, %s, 'pendente')
        """, (
            request.form["titulo"],
            request.form["descricao"],
            request.form["data"],
            request.form["horario"],
            request.form["local"],
            session["user_id"]
        ))

        conn.commit()
        cursor.close()
        conn.close()

        return redirect("/painel_professor")

    return render_template("criar_evento.html")


# ---------------- VER DÚVIDAS ----------------
@app.route("/projeto/<int:id>/duvidas", methods=["GET", "POST"])
@login_required("professor")
def ver_duvidas(id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == "POST":
        resposta = request.form.get("resposta")
        duvida_id = request.form.get("duvida_id")

        cursor.execute("""
            UPDATE Duvidas
            SET resposta = %s
            WHERE id = %s
        """, (resposta, duvida_id))
        conn.commit()

        cursor.execute("""
            SELECT u.email
            FROM Duvidas d
            JOIN Utilizador u ON d.aluno_id = u.id
            WHERE d.id = %s
        """, (duvida_id,))
        aluno = cursor.fetchone()

        if aluno:
            enviar_email(
                aluno["email"],
                "Resposta à sua dúvida",
                f"O professor respondeu à sua dúvida:\n\n{resposta}"
            )

    cursor.execute("""
        SELECT d.*, u.email
        FROM Duvidas d
        JOIN Utilizador u ON d.aluno_id = u.id
        WHERE d.projeto_id = %s
    """, (id,))

    duvidas = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("ver_duvidas.html", duvidas=duvidas)


# ==================================================
# ROTAS PARTILHADAS POR PROFESSOR E ADMIN
# ==================================================

# ---------------- VER INSCRITOS ----------------
@app.route("/projeto/<int:id>/inscritos")
@role_required("professor", "admin")
def ver_inscritos(id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT u.email
        FROM Inscricoes i
        JOIN Utilizador u ON i.aluno_id = u.id
        WHERE i.projeto_id = %s
    """, (id,))

    alunos = cursor.fetchall()

    cursor.close()
    conn.close()

    role = session.get("tipo")
    return render_template("ver_inscritos.html", alunos=alunos, role=role)


# ---------------- EDITAR EVENTO ----------------
@app.route("/projeto/<int:id>/alterar", methods=["GET", "POST"])
@role_required("professor", "admin")
def editar_evento(id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == "POST":
        cursor.execute("""
            UPDATE ProjetosEscolares
            SET titulo_proj = %s,
                descricao_proj = %s,
                data_proj = %s,
                horario_proj = %s,
                local_proj = %s
            WHERE id = %s
        """, (
            request.form["titulo"],
            request.form["descricao"],
            request.form["data"],
            request.form["horario"],
            request.form["local"],
            id
        ))

        conn.commit()
        cursor.close()
        conn.close()

        if session.get("tipo") == "admin":
            return redirect("/painel_admin")
        return redirect("/painel_professor")

    cursor.execute("SELECT * FROM ProjetosEscolares WHERE id = %s", (id,))
    evento = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template("editar_evento.html", evento=evento)


# ---------------- APAGAR EVENTO ----------------
@app.route("/apagar_evento_professor/<int:id>", methods=["POST"])
@role_required("professor", "admin")
def apagar_evento_professor(id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM ProjetosEscolares WHERE id = %s", (id,))
    conn.commit()

    cursor.close()
    conn.close()

    if session.get("tipo") == "admin":
        return redirect("/painel_admin")
    return redirect("/painel_professor")


# ==================================================
# ROTAS DO ADMIN
# ==================================================

# ---------------- PAINEL ADMIN ----------------
@app.route("/painel_admin")
@login_required("admin")
def painel_admin():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT p.*, u.email AS professor_email
        FROM ProjetosEscolares p
        JOIN Utilizador u ON p.professor_id = u.id
        WHERE p.estado IN ('pendente', 'aprovado')
        ORDER BY p.estado = 'pendente' DESC, p.id DESC
    """)
    eventos = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("painel_admin.html", eventos=eventos)


# ---------------- LISTAGEM DE PROJETOS ----------------
@app.route("/listagem_projetos")
@login_required("admin")
def listagem_projetos():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT p.*, u.email AS professor_email
        FROM ProjetosEscolares p
        LEFT JOIN Utilizador u ON p.professor_id = u.id
        ORDER BY p.id DESC
    """)
    projetos = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("listagem_projetos.html", projetos=projetos)


# ---------------- LISTAGEM DE UTILIZADORES ----------------
@app.route("/listagem_utilizadores")
@login_required("admin")
def listagem_utilizadores():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT id, email, tipo_utilizador, auth_provider
        FROM Utilizador
        ORDER BY tipo_utilizador, id
    """)
    utilizadores = cursor.fetchall()

    for utilizador in utilizadores:
        utilizador["tipo_utilizador"] = (utilizador.get("tipo_utilizador") or "").strip().lower()
        utilizador["auth_provider"] = (utilizador.get("auth_provider") or "").strip().lower()

    cursor.close()
    conn.close()

    return render_template("listagem_utilizadores.html", utilizadores=utilizadores)


# ---------------- APROVAR PROJETO ----------------
@app.route("/aprovar_projeto/<int:id>")
@login_required("admin")
def aprovar_projeto(id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT u.email
        FROM ProjetosEscolares p
        JOIN Utilizador u ON p.professor_id = u.id
        WHERE p.id = %s
    """, (id,))
    professor = cursor.fetchone()

    cursor.execute("""
        UPDATE ProjetosEscolares
        SET estado = 'aprovado'
        WHERE id = %s
    """, (id,))
    conn.commit()

    if professor:
        enviar_email(
            professor["email"],
            "Projeto aprovado",
            "O seu projeto escolar foi aprovado pelo administrador e já está disponível para os alunos."
        )

    cursor.close()
    conn.close()

    return redirect("/painel_admin")


# ---------------- REJEITAR PROJETO ----------------
@app.route("/rejeitar_projeto/<int:id>")
@login_required("admin")
def rejeitar_projeto(id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT u.email
        FROM ProjetosEscolares p
        JOIN Utilizador u ON p.professor_id = u.id
        WHERE p.id = %s
    """, (id,))
    professor = cursor.fetchone()

    cursor.execute("""
        UPDATE ProjetosEscolares
        SET estado = 'rejeitado'
        WHERE id = %s
    """, (id,))
    conn.commit()

    if professor:
        enviar_email(
            professor["email"],
            "Projeto rejeitado",
            "O seu projeto escolar foi rejeitado pelo administrador."
        )

    cursor.close()
    conn.close()

    return redirect("/painel_admin")


# ==================================================
# EXECUÇÃO
# ==================================================
if __name__ == "__main__":
    app.run(debug=True)