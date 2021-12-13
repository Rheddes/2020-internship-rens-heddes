import json
import os

from sqlalchemy import create_engine
from dotenv import load_dotenv


ENV = {}
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
CLONE_DIR = os.path.join(BASE_DIR, 'repos')
OUT_DIR = os.path.join(BASE_DIR, 'out')

SHORT_NAME_REGEX = r'([a-zA-Z0-9\-]+)-[0-9\.a-zA-Z\-]+(?=-reduced\.json)'

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


def ensure_path(path):
    if not os.path.exists(os.path.join(BASE_DIR, path)):
        os.mkdir(os.path.join(BASE_DIR, path))


def get_db_credentials():
    return {
        'host': os.environ.get('UPDATES_DB_HOST'),
        'port': os.environ.get('UPDATES_DB_PORT'),
        'user': os.environ.get('UPDATES_DB_USER'),
        'password': os.environ.get('UPDATES_DB_PASSWORD'),
        'database': os.environ.get('UPDATES_DB_NAME'),
    }


def get_db_connection():
    db_connection_str = 'mysql+mysqlconnector://{user}:{password}@{host}:{port}/{database}'.format(**get_db_credentials())
    return create_engine(db_connection_str)
