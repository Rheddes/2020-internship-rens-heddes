import difflib
import glob
import operator
import os

import jgrapht.convert
import numpy as np
import pandas as pd
import config
from risk_engine.graph import RiskGraph, parse_JSON_file
from utils.graph_sampling import ff_sample_subgraph
import networkx as nx

from itertools import chain, product, starmap
from functools import partial
from copy import deepcopy
import heapq
from scipy.sparse import csr_matrix



from datetime import datetime

import signal

class timeout:
    def __init__(self, seconds=1, error_message='Timeout'):
        self.seconds = seconds
        self.error_message = error_message
    def handle_timeout(self, signum, frame):
        raise TimeoutError(self.error_message)
    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)
    def __exit__(self, type, value, traceback):
        signal.alarm(0)

chaini = chain.from_iterable

callgraphs = [
    # 'org.testingisdocumenting.webtau.webtau-core-1.22-SNAPSHOT-reduced.json',
    'net.optionfactory.hibernate-json-3.0-SNAPSHOT-reduced.json',
    # 'com.flipkart.zjsonpatch.zjsonpatch-0.4.10-SNAPSHOT-reduced.json',
    # 'org.mandas.docker-client-2.0.0-SNAPSHOT-reduced.json',
]


def exhaustive_based_risk(graph: RiskGraph, all_paths=None):
    if all_paths is None:
        all_paths = calculate_all_execution_paths(graph)

    exhaustive_centrality = {key: 0.0 for key in graph.nodes.keys()}
    for path in all_paths:
        for node in path:
            exhaustive_centrality[node] += 1
    max_value = max(exhaustive_centrality.values(), default=0)
    if max_value > 0:
        exhaustive_centrality = {key: value/max_value for key, value in exhaustive_centrality.items()}
    graph.reset_cache()
    graph.centrality_score_function = lambda x: exhaustive_centrality[x]
    return {n: graph.get_inherent_risk_for(n) for n in graph.nodes.keys()}


def calculate_all_execution_paths(sg: RiskGraph):
    roots = (v for v, d in sg.in_degree() if d == 0)
    leaves = (v for v, d in sg.out_degree() if d == 0)
    all_paths = partial(nx.all_simple_paths, sg)
    jgrapht_sg = jgrapht.convert.from_nx(sg)
    jgrapht.types.MultiObjectiveSingleSourcePaths

    return list(chaini(starmap(all_paths, product(roots, leaves))))


def hong_system_risk(graph: RiskGraph, all_paths):
    return max([sum([max(graph.get_impact_scores_for(node).values(), default=0) for node in path]) for path in all_paths], default=0)


def hong_exhaustive_search(graph: RiskGraph, all_paths=None):
    current_graph = deepcopy(graph)
    if all_paths is None:
        all_paths = calculate_all_execution_paths(current_graph)
    current_risk = hong_system_risk(current_graph, all_paths)

    print('nodes: ', len(current_graph))
    print('vulnerabilities: ', len(current_graph.get_vulnerabilities()))
    print('paths: ', len(all_paths))
    risk_list = [current_risk]
    fix_list = []
    while current_risk > 0:
        vuln_list = list(current_graph.get_vulnerabilities())
        node_list = list(current_graph)

        A = np.array([
            [
                [
                    current_graph.get_impact_scores_for(node).get(vuln, 0.0) if vuln != vulnerability_to_skip else 0.0 for node in node_list
                ] for vuln in vuln_list
            ] for vulnerability_to_skip in vuln_list
        ])

        B = csr_matrix(np.array([[1 if node in path else 0 for node in node_list] for path in all_paths]).T)
        max_vulnerabilities = csr_matrix(A.max(initial=0.0, axis=1))
        # system_risks_per_missing_vulnerability = np.matmul(max_vulnerabilities, B).max(initial=0.0, axis=1)
        system_risks_per_missing_vulnerability = max_vulnerabilities * B
        system_risks_per_missing_vulnerability = system_risks_per_missing_vulnerability.max(axis=1)

        fix_vulnerability = vuln_list[system_risks_per_missing_vulnerability.argmin()]
        current_risk = system_risks_per_missing_vulnerability.min()
        fix_list.append(fix_vulnerability)
        risk_list.append(current_risk)
        current_graph.remove_vulnerability(fix_vulnerability)
    return fix_list, risk_list


def hong_risk(graph: RiskGraph, alpha=0.5):
    CV_vul = lambda n, v: alpha * graph.centrality_score_function(n) + (1 - alpha) * graph.get_impact_scores_for(n)[v]
    risks = {}
    for node, attributes in graph.get_vulnerable_nodes().items():
        for vulnerability in attributes['metadata']['vulnerabilities'].keys():
            risks[(node, vulnerability)] = CV_vul(node, vulnerability)
    return risks

def calculate_risk_from_tuples(hongrisk, index=0):
    risks = {key: 0.0 for key in set([key_tuple[index] for key_tuple in hongrisk])}
    for key_tuple, score in hongrisk.items():
        risks[key_tuple[index]] += score
    return risks


def sort_dict(x):
    return {k: v for k, v in sorted(x.items(), key=lambda item: item[1], reverse=True)}


def proportional_risk(sg: RiskGraph, risk_scores):
    proportional_risks = {}
    total_risk = sum(risk_scores.values())
    proportional_cvss = lambda n, v: sg.get_severity_scores_for(n)[v] / sum(sg.get_severity_scores_for(n).values())
    for vulnerability, nodes in sg.get_vulnerabilities().items():
        proportional_risks[vulnerability] = sum([proportional_cvss(node, vulnerability) * risk_scores[node]/total_risk for node in nodes])
    return sort_dict(proportional_risks)


# def risk_over_time(graph: RiskGraph, prioritised_list_of_vulnerabilities, risk_function):
#     current_graph = deepcopy(graph)
#     risk_scores = [risk_function(current_graph)]
#     for vulnerability in prioritised_list_of_vulnerabilities:
#         current_graph.remove_vulnerability(vulnerability)
#         risk_scores.append(risk_function(current_graph))
#     return risk_scores


if __name__ == '__main__':
    list_of_lists = []
    for file in glob.glob(os.path.join(config.BASE_DIR, 'reduced_callgraphs', '**', '*-reduced.json'), recursive=True):
    # for file in [os.path.join(config.BASE_DIR, 'repos', callgraph) for callgraph in callgraphs]:
        name = file.split('/')[-1]
        print('[{}] Reading: {}'.format(datetime.now(), name))
        graph = RiskGraph.create(*parse_JSON_file(file), auto_update=False)
        if not len(graph.get_vulnerable_nodes()):
            print('[{}] Skipping: {}'.format(datetime.now(), name))
            continue

        all_execution_paths = None
        for retry in range(2):
            try:
                print('[{}] Processing (attempt {}): {}'.format(datetime.now(), retry, name))
                with timeout(seconds=1000):
                    subgraph = ff_sample_subgraph(graph, graph.get_vulnerable_nodes().keys(), min(120, len(graph.nodes)))  # math.floor(len(graph) * 0.15))
                    all_execution_paths = calculate_all_execution_paths(subgraph)
                break
            except TimeoutError:
                pass
        if all_execution_paths is None:
            print('[{}] Unable to do exhaustive search: {}'.format(datetime.now(), name))


        hong_exhaustive_fix_list, hong_exhaustive_risk_over_time = hong_exhaustive_search(subgraph, all_execution_paths)
        exhaustive_risks = exhaustive_based_risk(subgraph, all_execution_paths)
        subgraph.configure_for_model('d')
        betweenness_risks = {n: subgraph.get_inherent_risk_for(n) for n in subgraph.nodes.keys()}

        hong_risks = hong_risk(subgraph)
        hong_node_risks = calculate_risk_from_tuples(hong_risks)

        betweenness_top_nodes = heapq.nlargest(10, betweenness_risks, key=betweenness_risks.get)
        exhausitve_risks_top_nodes = heapq.nlargest(10, exhaustive_risks, key=exhaustive_risks.get)
        hong_risks_top_nodes = heapq.nlargest(10, hong_node_risks, key=hong_node_risks.get)

        model_top_vulnerabilities = list(proportional_risk(subgraph, betweenness_risks).keys())
        exhaustive_top_vulnerabilities = list(proportional_risk(subgraph, exhaustive_risks).keys())
        hong_top_vulnerabilities = list(sort_dict(calculate_risk_from_tuples(hong_risks, 1)).keys())

        similarities = {
            'hong-exhaustive_centrality': difflib.SequenceMatcher(None, hong_top_vulnerabilities, exhaustive_top_vulnerabilities).ratio(),
            'model_d-exhaustive_centrality': difflib.SequenceMatcher(None, model_top_vulnerabilities, exhaustive_top_vulnerabilities).ratio(),
            'hong-exhaustive_paths': difflib.SequenceMatcher(None, hong_top_vulnerabilities, hong_exhaustive_fix_list).ratio(),
            'model_d-exhaustive_paths': difflib.SequenceMatcher(None, model_top_vulnerabilities, hong_exhaustive_fix_list).ratio(),
        }
        print('-------------------BEGIN RESULTS-------------------')
        print('Call-graph: ', name)
        print('Current time: ', datetime.now())
        print('----------ORDERED LIST OF VULNERABILITIES----------')
        print('Exhaustive centrality: ', exhaustive_top_vulnerabilities)
        print('Exhaustive paths:      ', hong_exhaustive_fix_list)
        print('Hong et al:            ', hong_top_vulnerabilities)
        print('Model D:               ', model_top_vulnerabilities)
        print('------------------SIMILARITIES---------------------')
        print('similarity Hong et al - exhaustive centrality: ', similarities['hong-exhaustive_centrality'])
        print('similarity Model D    - exhaustive centrality: ', similarities['model_d-exhaustive_centrality'])
        print('similarity Hong et al - exhaustive paths:      ', similarities['hong-exhaustive_paths'])
        print('similarity Model D    - exhaustive paths:      ', similarities['model_d-exhaustive_paths'])
        print('--------------------END RESULTS--------------------')

        list_of_lists.append([
            name,
            len(subgraph.nodes),
            similarities['hong-exhaustive_centrality'],
            similarities['model_d-exhaustive_centrality'],
            similarities['hong-exhaustive_paths'],
            similarities['model_d-exhaustive_paths'],
            exhaustive_top_vulnerabilities,
            hong_exhaustive_fix_list,
            hong_top_vulnerabilities,
            model_top_vulnerabilities,
        ])
    df = pd.DataFrame(list_of_lists, columns=['callgraph', 'no_nodes', 'sim_hong-ex_cen', 'sim_model-ex_cen', 'sim_hong-ex_path', 'sim_model-ex_path', 'ex_cen_vuln', 'ex_path_vuln', 'hong_vuln', 'model_vuln'])
    df.to_csv('results.csv', index=False)
