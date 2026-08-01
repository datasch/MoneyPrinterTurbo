import uuid
import pytest
from app.services import pocketbase_auth


def test_main_admin_restoration():
    """Verificar que el usuario principal giantucchi se restaura correctamente."""
    pocketbase_auth.init_db()
    pocketbase_auth.restore_main_admin("giantucchi_password_123")

    # Debe ser posible autenticarse con las nuevas credenciales del admin principal
    assert pocketbase_auth.authenticate_user("giantucchi", "giantucchi_password_123") is True
    assert pocketbase_auth.get_user_role("giantucchi") == "admin"


def test_user_creation_and_listing():
    """Verificar el flujo de invitaciones, registro de usuarios y listado."""
    uname = f"test_user_{uuid.uuid4().hex[:8]}"
    token = pocketbase_auth.create_invitation_token(created_by="giantucchi")
    assert token is not None

    val = pocketbase_auth.validate_invitation_token(token)
    assert val.get("valid") is True

    res = pocketbase_auth.register_user_with_token(token, uname, "pass1234")
    assert res.get("success") is True

    users = pocketbase_auth.list_users()
    usernames = [u["username"] for u in users]
    assert uname in usernames
    assert "giantucchi" in usernames

    # Limpiar usuario de prueba
    pocketbase_auth.delete_user(uname)


def test_user_deletion_and_session_invalidation():
    """Verificar que eliminar un usuario destruye sus sesiones y revoca su acceso."""
    uname = f"test_user_{uuid.uuid4().hex[:8]}"
    token = pocketbase_auth.create_invitation_token()
    pocketbase_auth.register_user_with_token(token, uname, "beta_pass")

    session_token = pocketbase_auth.create_session(uname)
    assert pocketbase_auth.validate_session(session_token) == uname

    # Intentar eliminar al admin principal giantucchi debe fallar
    del_admin_res = pocketbase_auth.delete_user("giantucchi")
    assert del_admin_res.get("success") is False
    assert del_admin_res.get("error") == "cannot_delete_main_admin"

    # Eliminar al usuario secundario
    del_user_res = pocketbase_auth.delete_user(uname)
    assert del_user_res.get("success") is True

    # La sesión del usuario eliminado ya no debe ser válida
    assert pocketbase_auth.validate_session(session_token) is None
    # Tampoco debe poder iniciar sesión
    assert pocketbase_auth.authenticate_user(uname, "beta_pass") is False


def test_invitation_revocation():
    """Verificar la revocación de enlaces de invitación."""
    token = pocketbase_auth.create_invitation_token()
    revoked = pocketbase_auth.revoke_invitation(token)
    assert revoked is True

    val = pocketbase_auth.validate_invitation_token(token)
    assert val.get("valid") is False
    assert val.get("reason") == "already_used"
