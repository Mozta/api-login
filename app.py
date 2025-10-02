import os
from datetime import timedelta, datetime
from email_validator import validate_email, EmailNotValidError

from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    get_jwt_identity, jwt_required
)
from models import db, User
from dotenv import load_dotenv

load_dotenv()

jwt = JWTManager()
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#Expiraciones
access_minutes = int(os.getenv('ACCESS_TOKEN_EXPIRES', 15))
refresh_days = int(os.getenv('REFRESH_TOKEN_EXPIRES_DAYS', 7))

app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET_KEY', 'super-secret')  # Cambia esto en producción
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=access_minutes)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=refresh_days)

db.init_app(app)
# migrate = Migrate(app, db)
jwt.init_app(app)

with app.app_context():
    db.create_all()

# Validaciones
def _normalize_email(email:str) -> str:
    try:
        valid = validate_email(email, check_deliverability=False)
        return valid.normalized
    except EmailNotValidError as e:
        return ValueError(str(e))
    
def _require_json(keys):
    data = request.get_json()
    missing = [key for key in keys if key not in data or data[key] in [None, ""]]
    if missing:
        return jsonify({"error": f"Campos faltantes: {', '.join(missing)}"}), 400
    return data, None, None

@app.post('/auth/register')
def register():
    data, err_rsp, code = _require_json(['username', 'email', 'password'])
    if err_rsp:
        return err_rsp, code

    try:
        email = _normalize_email(data['email'])
    except ValueError as e:
        return jsonify({"error": f"Email inválido: {str(e)}"}), 400
    
    password = data['password']
    if len(password) < 6:
        return jsonify({"error": "La contraseña debe tener al menos 6 caracteres."}), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "El email ya está registrado."}), 400
    
    user = User(username=data['username'], email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    access_token = create_access_token(identity=user.id, additional_claims={"email": user.email})
    refresh_token = create_refresh_token(identity=user.id)
    return jsonify({
        "message": "Usuario registrado exitosamente.",
        "user": user.to_dict(),
        "access_token": access_token,
        "refresh_token": refresh_token,
    }), 201

@app.post("/auth/login")
def login():
    data, err_rsp, code = _require_json(["email", "password"])
    if err_rsp: return err_rsp, code

    try:
        email = _normalize_email(data["email"])
    except ValueError as ve:
        return jsonify({"error": f"Email inválido: {ve}"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(data["password"]):
        # No revelar si el email existe
        return jsonify({"error": "Credenciales inválidas."}), 401

    access_token = create_access_token(identity=str(user.id), additional_claims={"email": user.email})
    refresh_token = create_refresh_token(identity=str(user.id))
    return jsonify({
        "message": "Login exitoso.",
        "access_token": access_token,
        "refresh_token": refresh_token
    }), 200

@app.post("/auth/refresh")
@jwt_required(refresh=True)
def refresh():
    uid = get_jwt_identity()
    # Re-emitimos un access token corto
    access_token = create_access_token(identity=str(uid))
    return jsonify({"access_token": access_token}), 200

@app.get("/profile")
@jwt_required()
def profile():
    uid = get_jwt_identity()
    user = User.query.get(uid)
    if not user:
        return jsonify({"error": "Usuario no encontrado."}), 404
    return jsonify({"user": user.to_dict()}), 200



if __name__ == '__main__':
    app.run(debug=True)