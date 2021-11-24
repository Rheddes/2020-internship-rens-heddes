import json
import os

from sqlalchemy import create_engine
from dotenv import load_dotenv


ENV = {}
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
CLONE_DIR = os.path.join(BASE_DIR, 'repos')
OUT_DIR = os.path.join(BASE_DIR, 'out')

if os.path.exists(os.path.join(BASE_DIR, '.env')):
    load_dotenv(os.path.join(BASE_DIR, '.env'))


def get_env(key):
    if key in os.environ:
        return os.environ[key]
    return None


def get_repo_dir_for(project):
    return CLONE_DIR + '/' + project


def get_out_dir_for(project, path=None):
    if path:
        return os.path.join(OUT_DIR, project, path)
    return os.path.join(OUT_DIR, project)


def get_db_connection():
    db_connection_str = 'mysql+mysqlconnector://vulnerability-history:secret@localhost:33062/vulnerability-history'
    return create_engine(db_connection_str)
