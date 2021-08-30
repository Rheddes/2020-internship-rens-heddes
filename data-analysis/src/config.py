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
    if not ENV:
        with open(os.path.join(BASE_DIR, 'http-client.private.env.json'), 'r') as f:
            for k, v in json.load(f).items():
                ENV[k] = v
    return ENV['dev'][key]


def get_repo_dir_for(project):
    return CLONE_DIR + '/' + project


def get_out_dir_for(project, path=None):
    if path:
        return os.path.join(OUT_DIR, project, path)
    return os.path.join(OUT_DIR, project)


def http_params_paginated(page=1):
    return {
        'per_page': 30,
        'page': page,
        'api_key': get_env('API_KEY')
    }


def get_db_connection():
    db_connection_str = 'mysql+mysqlconnector://vulnerability-history:secret@localhost:33062/vulnerability-history'
    return create_engine(db_connection_str)

http_params = {
    'api_key': get_env('API_KEY')
}
