import hashlib
import os
import sqlite3
import time
import uuid
from datetime import datetime, timedelta
from loguru import logger

from app.config import config

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
AUTH_DB_DIR = os.path.join(ROOT_DIR, "storage", "auth")
os.makedirs(AUTH_DB_DIR, exist_ok=True)
DB_PATH = os.path.join(AUTH_DB_DIR, "auth.db")

DEFAULT_ADMIN_USER = "giantucchi"


def _get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def init_db():
    """Inicializar las tablas de autenticación e invitaciones y registrar al superusuario giantucchi."""
    try:
        with _get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS invitations (
                    id TEXT PRIMARY KEY,
                    token TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    used INTEGER DEFAULT 0,
                    created_by TEXT DEFAULT 'giantucchi'
                )
                """
            )

            # Obtener contraseña del administrador desde .env o usar valor por defecto
            admin_pass = (
                os.getenv("WEBUI_PASSWORD")
                or os.getenv("AUTH_PASSWORD")
                or os.getenv("ADMIN_PASSWORD")
                or config.app.get("webui_password", "")
                or "giantucchi"
            ).strip()

            admin_pass_hash = _hash_password(admin_pass)

            # Asegurar que el usuario giantucchi siempre exista y esté actualizado
            cursor.execute("SELECT id FROM users WHERE username = ?", (DEFAULT_ADMIN_USER,))
            row = cursor.fetchone()
            if not row:
                cursor.execute(
                    "INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)",
                    (str(uuid.uuid4()), DEFAULT_ADMIN_USER, admin_pass_hash, "admin"),
                )
                logger.info(f"Initialized main admin user '{DEFAULT_ADMIN_USER}' in auth database.")
            else:
                cursor.execute(
                    "UPDATE users SET password_hash = ? WHERE username = ?",
                    (admin_pass_hash, DEFAULT_ADMIN_USER),
                )

            conn.commit()
    except Exception as e:
        logger.error(f"Failed to initialize auth DB: {e}")


def create_invitation_token(created_by: str = DEFAULT_ADMIN_USER, expires_in_seconds: int = 3600) -> str:
    """Generar un token único de invitación con expiración de 1 hora."""
    init_db()
    token = uuid.uuid4().hex
    now = datetime.utcnow()
    expires_at = now + timedelta(seconds=expires_in_seconds)

    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO invitations (id, token, created_at, expires_at, used, created_by) VALUES (?, ?, ?, ?, 0, ?)",
            (str(uuid.uuid4()), token, now.isoformat(), expires_at.isoformat(), created_by),
        )
        conn.commit()

    logger.info(f"Created invitation token: {token} (expires at {expires_at.isoformat()})")
    return token


def validate_invitation_token(token: str) -> dict:
    """Validar si el token de invitación existe, no ha sido usado y no ha expirado."""
    init_db()
    if not token or not isinstance(token, str):
        return {"valid": False, "reason": "invalid_token"}

    token = token.strip()
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM invitations WHERE token = ?", (token,))
        row = cursor.fetchone()

        if not row:
            return {"valid": False, "reason": "not_found"}

        if row["used"] == 1:
            return {"valid": False, "reason": "already_used"}

        expires_at_str = row["expires_at"]
        try:
            expires_at = datetime.fromisoformat(expires_at_str)
        except ValueError:
            return {"valid": False, "reason": "invalid_date"}

        if datetime.utcnow() > expires_at:
            return {"valid": False, "reason": "expired"}

        return {"valid": True, "token": token, "created_at": row["created_at"], "expires_at": expires_at_str}


def register_user_with_token(token: str, username: str, password: str) -> dict:
    """Registrar un nuevo usuario consumiendo un token de invitación válido."""
    validation = validate_invitation_token(token)
    if not validation.get("valid"):
        return {"success": False, "error": validation.get("reason")}

    username = (username or "").strip()
    password = (password or "").strip()

    if not username or len(username) < 3:
        return {"success": False, "error": "username_too_short"}

    if not password or len(password) < 4:
        return {"success": False, "error": "password_too_short"}

    pass_hash = _hash_password(password)

    with _get_connection() as conn:
        cursor = conn.cursor()
        # Comprobar si el nombre de usuario ya existe
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return {"success": False, "error": "user_exists"}

        # Crear usuario
        user_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, 'user')",
            (user_id, username, pass_hash),
        )

        # Marcar invitación como usada
        cursor.execute("UPDATE invitations SET used = 1 WHERE token = ?", (token,))
        conn.commit()

    logger.info(f"User '{username}' registered successfully using token {token}")
    return {"success": True, "username": username}


def authenticate_user(username: str, password: str) -> bool:
    """Autenticar credenciales del usuario contra la base de datos."""
    init_db()
    username = (username or "").strip()
    password = (password or "").strip()

    if not username or not password:
        return False

    pass_hash = _hash_password(password)

    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row and row["password_hash"] == pass_hash:
            return True

    return False


def get_user_role(username: str) -> str:
    """Obtener el rol del usuario ('admin' o 'user')."""
    init_db()
    if username == DEFAULT_ADMIN_USER:
        return "admin"

    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row:
            return row["role"]

    return "user"


# Inicializar DB al importar
init_db()
