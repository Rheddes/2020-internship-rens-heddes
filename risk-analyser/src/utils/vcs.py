import os
import shutil

from git import Git, Repo

from utils.config import CLONE_DIR


def ensure_repo_dir():
    if not os.path.exists(CLONE_DIR):
        os.mkdir(CLONE_DIR)


def rm_r(path):
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path)
    elif os.path.exists(path):
        os.remove(path)


def clone_repository(project_full_name):
    ensure_repo_dir()
    if not os.path.exists(CLONE_DIR + '/'):
        os.mkdir(CLONE_DIR)
    repo_path = CLONE_DIR + '/' + project_full_name[project_full_name.index('/'):]
    if os.path.exists(repo_path):
        rm_r(repo_path)
    Git(CLONE_DIR).clone('https://github.com/{}.git'.format(project_full_name))
    return Repo(repo_path)


def delete_clone(project_full_name):
    repo_path = CLONE_DIR + '/' + project_full_name[project_full_name.index('/'):]
    if os.path.exists(repo_path):
        rm_r(repo_path)
