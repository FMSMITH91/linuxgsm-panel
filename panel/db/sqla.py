"""The panel's one SQLAlchemy object.

Its own module so the model files can share it without importing each other: panel/db/models.py and
panel/db/website_models.py both take `db` from here, and every other module still imports it from
models.py as before.
"""
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
