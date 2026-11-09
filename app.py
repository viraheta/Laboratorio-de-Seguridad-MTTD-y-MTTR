from flask import Flask, render_template, request
import sqlite3

import re 
from werkzeug.security import generate_password_hash, check_password_hash

from datetime import datetime

app = Flask(__name__)

@app.route("/")

def inicio():
    return "Laboratorio de Ciberseguridad"

def validar_usuario(usuario):
    return re.fullmatch(r"[A-Za-z0-9_]{4,20}", usuario) is not None


def validar_correo(correo):
    return re.fullmatch(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        correo
    ) is not None


def validar_password(password):
    return len(password) >= 8


def registrar_evento(tipo,usuario):
    fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open ("eventos.log","a",encoding="utf-8") as archivo:
        archivo.write(f"{fecha},{tipo},{usuario}\n")



@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip()
        correo = request.form.get("correo", "").strip()
        password = request.form.get("password", "")

        if not validar_usuario(usuario):
            return "USUARIO INVÁLIDO"
        if not validar_correo(correo):
            return "CORREO ELECTRÓNICO INVÁLIDO"
        if not validar_password(password):
            return "LA CONTRASEÑA DEBE DE CONTENER MAS DE 8 CARACTERES"
        

        conexion = sqlite3.connect("usuarios.db")
        cursor = conexion.cursor()

        cursor.execute(
            "SELECT id FROM usuarios WHERE usuario = ? OR correo = ?",
            (usuario,correo)
        )

        existente = cursor.fetchone()

        if existente:
            conexion.close()
            return "EL USUARIO O CORREO YA ESTA REGISTRADO"

        password_hash = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO usuarios (usuario, correo, password) VALUES (?, ?, ?)",
            (usuario, correo, password_hash)
        )

        conexion.commit()
        conexion.close()
        return "Usuario registrado"

    return render_template("registro.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        usuario = request.form["usuario"]
        password = request.form["password"]

        conexion = sqlite3.connect("usuarios.db")
        cursor = conexion.cursor()

        cursor.execute(
            "SELECT * FROM usuarios WHERE usuario = ?",
            (usuario,)
        )

        resultado = cursor.fetchone()

        conexion.close()
        
        if resultado and check_password_hash(resultado[3],password):
            registrar_evento("LOGIN_CORRECTO", usuario)
            return "INICIO DE SESIÓN CORRECTO"
        else:
            registrar_evento("LOGIN_FALLIDO", usuario)

            return "CREDENCIALES INCORRECTAS"


    return render_template("login.html")

if __name__=="__main__":
    app.run(debug=True)