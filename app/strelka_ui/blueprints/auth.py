"""
Authentication controller with flask_oidc support
"""
from datetime import datetime, timedelta
from random import choice
from string import ascii_letters, digits

from flask import Blueprint, current_app, jsonify, request, session, redirect, url_for
from flask_oidc import OpenIDConnect
from jsonschema import ValidationError, validate

from strelka_ui.database import db
from strelka_ui.models import ApiKey, User
from strelka_ui.services.auth import auth_required, check_credentials

auth = Blueprint("auth", __name__, url_prefix="/auth")

# Initialize OpenIDConnect
oidc = OpenIDConnect()

loginSchema = {
    "type": "object",
    "properties": {
        "username": {"type": "string", "minLength": 2},
        "password": {"type": "string", "minLength": 3},
    },
    "required": ["username", "password"],
}

def init_app(app):
    """Initialize OpenIDConnect with the Flask app"""
    oidc.init_app(app)

@auth.route("/apikey", methods=["GET"])
@auth_required
def get_api_key(user):
    dbUser = db.session.query(User).filter_by(user_cn=user.user_cn).first()
    if not dbUser:
        return jsonify({"error": "User not found"}), 404
    existing_key = db.session.query(ApiKey).filter_by(user_cn=user.user_cn).first()
    if existing_key:
        if existing_key.expiration > datetime.now():
            return jsonify({"api_key": existing_key.key}), 200
        else:
            db.session.delete(existing_key)
            db.session.commit()
    key = "".join(choice(ascii_letters + digits) for _ in range(32))
    expiration = datetime.now() + timedelta(
        days=int(current_app.config["API_KEY_EXPIRATION"])
    )
    api_key = ApiKey(key=key, user_cn=user.user_cn, expiration=expiration)
    db.session.add(api_key)
    db.session.commit()
    return jsonify({"api_key": key}), 201


@auth.route("/logout")
@oidc.require_login
def logout():
    """Clears user session and returns logout message"""
    session.clear()
    if current_app.config.get("ENABLE_OPENID", False):
        oidc.logout()
    return jsonify({"message": "successfully logged out"}), 200


@auth.route("/login", methods=["GET", "POST"])
def login():
    """Login handler to authenticate and create user session"""
    if request.method == "GET" and current_app.config.get("ENABLE_OPENID", False):
        return redirect(url_for("auth.oidc_login"))

    # Existing username/password authentication
    username = request.form.get("username")
    password = request.form.get("password")

    try:
        validate(
            instance={"username": username, "password": password},
            schema=loginSchema
        )
    except ValidationError as err:
        # current_app.logger.error("Failed login validation: %s", err)
        return jsonify({"error": "Failed to validate username/password"}), 400

    # current_app.logger.info("received login attempt for user %s", username)
    success, ldapUser = check_credentials(username, password)
    if not success:
        return jsonify({"error": "incorrect username/password combination"}), 401

    return process_login(ldapUser)

@auth.route("/oidc-login")
@oidc.require_login
def oidc_login():
    """Handle OpenID Connect login"""
    if not current_app.config.get("ENABLE_OPENID", False):
        return jsonify({"error": "OpenID authentication not enabled"}), 400

    info = oidc.user_getinfo(['sub', 'given_name', 'family_name'])
    user_data = {
        "user_cn": info.get("sub"),
        "first_name": info.get("given_name", ""),
        "last_name": info.get("family_name", ""),
    }
    return process_login(user_data)

def process_login(user_data):
    """Common login processing for both auth methods"""
    session["user_cn"] = user_data["user_cn"]
    session["first_name"] = user_data["first_name"]
    session["last_name"] = user_data["last_name"]

    # upsert the user record with the new last logged in time
    try:
        dbUser = db.session.query(User).filter_by(user_cn=session["user_cn"]).first()
        loginTime = str(datetime.utcnow())
        if dbUser is not None:
            dbUser.last_login = loginTime
            dbUser.login_count += 1
        else:
            dbUser = User(
                session["user_cn"],
                session["first_name"],
                session["last_name"],
                loginTime,
                1,
                0,
            )
            db.session.add(dbUser)
        db.session.commit()
        db.session.flush()

        # stored in the session and used to map submissions to users
        # without a lookup on the user submitting it.
        session["user_id"] = dbUser.id
        session["logged_in"] = True

    except Exception as err:
        # current_app.logger.error("Failed connection to database: %s", err)
        return jsonify({"error": "Failed to connect to database"}), 400

    return (
        jsonify(
            {
                "user_name": session["user_cn"],
                "authenticated": True,
            }
        ),
        200,
    )
