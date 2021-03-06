import os
from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
CLONE_DIR = os.path.join(BASE_DIR, 'repos')
OUT_DIR = os.path.join(BASE_DIR, 'out')
CVSS_SCORE_VERSION = 'scoreCVSS3'

if os.path.exists(os.path.join(BASE_DIR, '.env')):
    load_dotenv(os.path.join(BASE_DIR, '.env'))

SHORT_NAME_REGEX = r'([a-zA-Z0-9\-]+)-[0-9\.a-zA-Z\-]+(?=-reduced\.json)'

def get_db_credentials():
    return {
        'host': os.environ.get('UPDATES_DB_HOST'),
        'port': os.environ.get('UPDATES_DB_PORT'),
        'user': os.environ.get('UPDATES_DB_USER'),
        'password': os.environ.get('UPDATES_DB_PASSWORD'),
        'database': os.environ.get('UPDATES_DB_NAME'),
    }
