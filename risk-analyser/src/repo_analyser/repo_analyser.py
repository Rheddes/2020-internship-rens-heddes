import logging
import os
import sys

import config
from config import BASE_DIR
from utils.vcs import clone_repository
import xml.etree.ElementTree as ET
import subprocess


def _add_rapid_plugin_to_pom(pom_path):
    ET.register_namespace('', 'http://maven.apache.org/POM/4.0.0')
    tree = ET.parse(pom_path)
    packaging_node = tree.find('{http://maven.apache.org/POM/4.0.0}packaging')
    if packaging_node:
        packaging_node.text = 'jar'
    build_plugins_node = tree.find('{http://maven.apache.org/POM/4.0.0}build/{http://maven.apache.org/POM/4.0.0}plugins')
    if not build_plugins_node:
        build_plugins_node = ET.Element('{http://maven.apache.org/POM/4.0.0}plugins')
        build_node = tree.find('{http://maven.apache.org/POM/4.0.0}build')
        if not build_node:
            build_node = ET.Element('{http://maven.apache.org/POM/4.0.0}build')
            tree.getroot().append(build_node)
        build_node.append(build_plugins_node)
    maven_plugin = ET.parse(os.path.join(BASE_DIR, 'resources', 'rapid-integration-tools.xml'))
    build_plugins_node.append(maven_plugin.getroot())
    with open(pom_path, 'wb') as f:
        tree.write(f)


def _find_root_pom(current_dir, current_root):
    if current_dir == config.CLONE_DIR:
        return current_root
    parent = os.path.abspath(os.path.join(current_dir, os.pardir))
    if os.path.exists(os.path.join(current_dir, 'pom.xml')):
        return _find_root_pom(parent, current_dir)
    return _find_root_pom(parent, current_root)


def _generate_call_graphs(workdir, pom_path):
    if pom_path != 'pom.xml' and pom_path.endswith('pom.xml'):
        workdir = os.path.join(workdir, pom_path.split('/pom.xml')[0])
    with open(os.path.join(workdir, 'mvn.log'), 'wb') as f:
        process = subprocess.Popen(['mvn', '-T', '4', 'rapid-generate-graphs'], cwd=workdir, stdout=f)
    exit_code = process.wait()
    if exit_code != 0:
        logging.getLogger().warning('Some problems occurred with: {}'.format(workdir))
        logging.getLogger().warning('See mvn.log for details')


class RepoAnalyser:
    def __init__(self, repo_name, fix_commit_hash, pom_path='pom.xml'):
        self.repo_name = repo_name
        self.fix_commit_hash = fix_commit_hash
        self.pom_path = pom_path

    def run(self):
        repo = clone_repository(self.repo_name)
        # unpatched_commit_hash = repo.git.rev_list('--parents', '-n', '1', self.fix_commit_hash).split(' ')[1]
        # repo.git.checkout(unpatched_commit_hash)
        repo.git.checkout(self.fix_commit_hash)
        _add_rapid_plugin_to_pom(os.path.join(repo.working_dir, self.pom_path))
        _generate_call_graphs(repo.working_dir, self.pom_path)


if __name__ == '__main__':
    repo_analyser = RepoAnalyser('acorado/keycloak', '157afd7bb1ed67dd688e9b6d7a6dee4e50960eff')
    repo_analyser.run()
