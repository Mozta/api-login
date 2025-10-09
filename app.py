import os
from datetime import timedelta, datetime
from email_validator import validate_email, EmailNotValidError
from functools import wraps

from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    get_jwt_identity, jwt_required, verify_jwt_in_request, get_jwt
)
from models import db, User
from dotenv import load_dotenv

load_dotenv()

jwt = JWTManager()
app = Flask(__name__)

# Configuración CORS
CORS(app, 
     origins=['http://localhost:3000', 'http://localhost:5173', 'http://127.0.0.1:3000', 'http://127.0.0.1:5173'],
     allow_headers=['Content-Type', 'Authorization'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
     supports_credentials=True
)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Expiraciones
access_minutes = int(os.getenv('ACCESS_TOKEN_EXPIRES', 15))
refresh_days = int(os.getenv('REFRESH_TOKEN_EXPIRES_DAYS', 7))

app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET_KEY', 'super-secret')  # Cambia esto en producción
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=access_minutes)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=refresh_days)

db.init_app(app)
migrate = Migrate(app, db)
jwt.init_app(app)

with app.app_context():
    db.create_all()

# --------------------------
# Validaciones y utilidades
# --------------------------
def _normalize_email(email: str) -> str:
    try:
        valid = validate_email(email, check_deliverability=False)
        return valid.normalized
    except EmailNotValidError as e:
        raise ValueError(str(e))

def _require_json(keys):
    data = request.get_json()
    if not data:
        return None, (jsonify({"error": "Se requiere JSON en el cuerpo de la petición."}), 400)
    missing = [key for key in keys if key not in data or data[key] in [None, ""]]
    if missing:
        return None, (jsonify({"error": f"Campos faltantes: {', '.join(missing)}"}), 400)
    return data, None

def role_required(*roles):
    # Decorador para forzar rol en el JWT
    def wrapper(fn):
        @wraps(fn)
        def decorated(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt() or {}
            role = claims.get('role')
            if role not in roles:
                return jsonify({
                    "error": "Forbidden",
                    "detail": "Rol insuficiente para acceder a este recurso.",
                    "required_roles": roles,
                    "current_role": role
                }), 403
            return fn(*args, **kwargs)
        return decorated
    return wrapper

@app.route('/')
def index():
    return jsonify({"message": "API de autenticación con Flask, JWT y PostgreSQL"}), 200
# --------------------------
# Rutas de autenticación
# --------------------------
@app.post('/auth/register')
def register():
    data, error_response = _require_json(['username', 'email', 'password'])
    if error_response:
        return error_response

    try:
        email = _normalize_email(data['email'])
    except ValueError as e:
        return jsonify({"error": f"Email inválido: {str(e)}"}), 400

    password = data['password']
    if len(password) < 6:
        return jsonify({"error": "La contraseña debe tener al menos 6 caracteres."}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "El email ya está registrado."}), 400

    # Rol opcional en el registro; por defecto 'user' y validado
    role = data.get('role', 'user')
    if role not in ('admin', 'user'):
        role = 'user'

    user = User(username=data['username'], email=email, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    claims = {"email": user.email, "role": user.role}
    access_token = create_access_token(identity=str(user.id), additional_claims=claims)
    refresh_token = create_refresh_token(identity=str(user.id))
    return jsonify({
        "message": "Usuario registrado exitosamente.",
        "user": user.to_dict(),
        "access_token": access_token,
        "refresh_token": refresh_token,
    }), 201

@app.post("/auth/login")
def login():
    data, error_response = _require_json(["email", "password"])
    if error_response:
        return error_response

    try:
        email = _normalize_email(data["email"])
    except ValueError as ve:
        return jsonify({"error": f"Email inválido: {ve}"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(data["password"]):
        # No revelar si el email existe
        return jsonify({"error": "Credenciales inválidas."}), 401

    claims = {"email": user.email, "role": user.role}
    access_token = create_access_token(identity=str(user.id), additional_claims=claims)
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
    # Reconstituimos claims actuales (por si el rol cambió desde la emisión anterior)
    user = User.query.get(int(uid)) if uid is not None else None
    if not user:
        return jsonify({"error": "Usuario no encontrado."}), 404
    claims = {"email": user.email, "role": user.role}
    access_token = create_access_token(identity=str(uid), additional_claims=claims)
    return jsonify({"access_token": access_token}), 200

# --------------------------
# Endpoints protegidos y públicos
# --------------------------
@app.get("/profile")
@jwt_required()
def profile():
    uid = get_jwt_identity()
    user = User.query.get(int(uid))
    if not user:
        return jsonify({"error": "Usuario no encontrado."}), 404
    return jsonify({"user": user.to_dict()}), 200

@app.get("/admin/stats")
@role_required('admin')  # Solo ADMIN
def admin_stats():
    total_users = User.query.count()
    total_admins = User.query.filter_by(role='admin').count()
    total_regular = User.query.filter_by(role='user').count()
    return jsonify({
        "users_total": total_users,
        "users_by_role": {
            "admin": total_admins,
            "user": total_regular
        }
    }), 200


if __name__ == '__main__':
    app.run(debug=True, port=8000)
