import glob
import logging
import os
import sys
from datetime import datetime

import numpy as np
import pandas as pd
from git import Repo

import config
from config import BASE_DIR
from risk_engine.graph import RiskGraph, parse_JSON_file, _combine_scores
from utils.vcs import clone_repository
import xml.etree.ElementTree as ET
import subprocess
import networkx as nx
import seaborn as sns
import matplotlib.pyplot as plt


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
        process_clean = subprocess.Popen(['mvn', 'clean'], cwd=workdir, stdout=f)
        process_clean.wait()
        process = subprocess.Popen(['mvn', '-T', '4', 'rapid-generate-graphs'], cwd=workdir, stdout=f)
    exit_code = process.wait()
    if exit_code != 0:
        logging.getLogger().warning('Some problems occurred with: {}'.format(workdir))
        logging.getLogger().warning('See mvn.log for details')


def _calculate_risk(repo_name, repo_path):
    logging.getLogger().info('Caclulating risk for: {}'.format(repo_name))
    if not os.path.exists(os.path.join(repo_path, 'target')):
        logging.getLogger().warning('No root target folder for {}'.format(repo_name))

    for call_graph in glob.glob(os.path.join(repo_path, 'target', 'callgraphs', '*-reduced.json')):
        logging.getLogger().info('Call graph found for {} - {}'.format(repo_name, call_graph))
        enriched_graph = RiskGraph.create(*parse_JSON_file(call_graph))
        enriched_graph.remove_edges_from(nx.selfloop_edges(enriched_graph))
        if len(enriched_graph.nodes()) == 0:
            continue
        start_time = datetime.now()
        percentile = 0.995
        coreachability = {node_id: len(nx.algorithms.dag.ancestors(enriched_graph, node_id)) for node_id in
                          enriched_graph.nodes.keys()}
        sum_coreachability = sum(coreachability.values())
        max_coreachability = pd.Series(list(coreachability.values())).quantile(percentile)

        normalised_coreachability = {node_id: value/sum_coreachability for node_id, value in coreachability.items()}
        relative_coreachability = {node_id: min(1, value/max_coreachability) for node_id, value in coreachability.items()}
        betweenness = nx.algorithms.centrality.betweenness_centrality(enriched_graph, endpoints=True, k=round(len(enriched_graph.nodes()) / 10))
        sum_betweenness = sum(betweenness.values())
        normalised_betweenness = {node_id: value/sum_betweenness for node_id, value in betweenness.items()}
        max_betweenness = pd.Series(list(betweenness.values())).quantile(percentile)
        relative_betweenness = {k: min(1, v / max_betweenness) for k, v in betweenness.items()}

        risks = {}
        enriched_graph.centrality_score_function = lambda x: normalised_coreachability[x]
        enriched_graph.propagation_function = lambda x: sum(x)
        risks['A'] = enriched_graph.propagation_function([enriched_graph.get_intrinsic_risk_for(k) for k in enriched_graph.get_vulnerable_nodes().keys()])
        enriched_graph.reset_cache()
        enriched_graph.centrality_score_function = lambda x: relative_coreachability[x]
        enriched_graph.propagation_function = _combine_scores
        risks['B'] = enriched_graph.propagation_function([enriched_graph.get_intrinsic_risk_for(k) for k in enriched_graph.get_vulnerable_nodes().keys()])
        enriched_graph.reset_cache()
        enriched_graph.centrality_score_function = lambda x: normalised_betweenness[x]
        enriched_graph.propagation_function = lambda x: sum(x)
        risks['C'] = enriched_graph.propagation_function([enriched_graph.get_intrinsic_risk_for(k) for k in enriched_graph.get_vulnerable_nodes().keys()])
        enriched_graph.reset_cache()
        enriched_graph.centrality_score_function = lambda x: relative_betweenness[x]
        enriched_graph.propagation_function = _combine_scores
        risks['D'] = enriched_graph.propagation_function([enriched_graph.get_intrinsic_risk_for(k) for k in enriched_graph.get_vulnerable_nodes().keys()])

        logging.info('Calculated centralities, elapsed time = %s', str(datetime.now() - start_time))

        plotting_ecdfs = False
        if plotting_ecdfs:
            sns.ecdfplot(np.array(list(relative_betweenness.values())))
            plt.title('CDF relative centrality scores\n{}'.format(repo_name))
            plt.show()
        # entrypoints = [x for x in enriched_graph.nodes() if enriched_graph.out_degree(x) >= 0 and enriched_graph.in_degree(x) == 0 and enriched_graph.nodes[x].get('metadata', {}).get('application_node', False)]
        logging.getLogger().debug('Risks for {} - {}'.format(repo_name, risks))
        print('Risk for {} is {}'.format(repo_name, risks))
        return risks


class RepoAnalyser:
    def __init__(self, repo_name, fix_commit_hash, pom_path='pom.xml'):
        self.repo_name = repo_name
        self.fix_commit_hash = fix_commit_hash
        self.pom_path = pom_path

    def run(self):
        repo_short_name = self.repo_name[self.repo_name.index('/')+1:]
        if os.path.exists(os.path.join(config.CLONE_DIR, repo_short_name)):
            repo = Repo(os.path.join(config.CLONE_DIR, repo_short_name))
        else:
            repo = clone_repository(self.repo_name)
        if not glob.glob(os.path.join(repo.working_dir, 'target', 'callgraphs', '*-reduced.json')):
            repo.git.reset('--hard')
            repo.git.checkout(self.fix_commit_hash)
            unpatched_commit_hash = repo.git.rev_list('--parents', '-n', '1', self.fix_commit_hash).split(' ')[1]
            repo.git.checkout(unpatched_commit_hash)

            _add_rapid_plugin_to_pom(os.path.join(repo.working_dir, self.pom_path))
            _generate_call_graphs(repo.working_dir, self.pom_path)
        return _calculate_risk(repo_short_name, repo.working_dir)

