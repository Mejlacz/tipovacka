"""
extensions.py
Sdílené Flask extensions – inicializované BEZ app (app factory pattern).
Importuj odsud `db`, `login_manager`, `csrf` – NIKDY je neinicializuj znovu jinde.
"""
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
