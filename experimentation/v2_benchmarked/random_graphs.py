import random

import jgrapht
import networkx as nx
import pickle
import numpy as np
from os import path

import constants
from v2_benchmarked.util.graph_factory import get_color
from v2_benchmarked.util.risk_engine import VulnerabilityRiskEngine

GRAPH_PATH = '/random_graph_100_130_10.p'
NO_NODES = 100
NO_EDGES = 80
NO_VULNERABLE_NODES = 10


def build_centrality_measure_function(centrality_measure, graph):
    def get_centrality_measure_for(node_id):
        return getattr(nx.algorithms.centrality, centrality_measure)(graph)[node_id]

    return get_centrality_measure_for


def build_random_graph(nodes, edges, vulnerable_nodes, cvss_distribution):
    graph = nx.generators.random_graphs.gnm_random_graph(nodes, edges, directed=True)
    attributes = {note_id: {'metadata': {}} for note_id in graph.nodes.keys()}
    for vulnerable_node_id in random.sample(range(nodes), vulnerable_nodes):
        cvss_score = np.random.choice(cvss_distribution, 1)[0]
        attributes[vulnerable_node_id] = {'metadata': {'vulnerabilities': {'CVE-106': {'scoreCVSS3': cvss_score}}}}
        # YES incorrect because it is actually cvss v2
    nx.set_node_attributes(graph, attributes)
    return graph


if __name__ == '__main__':
    if GRAPH_PATH is None or not path.exists(constants.DATA_DIR + GRAPH_PATH):
        distribution = pickle.load(open(constants.DATA_DIR + '/distribution.p', 'br'))
        nx_graph = build_random_graph(NO_NODES, NO_EDGES, NO_VULNERABLE_NODES, distribution)
        pickle.dump(nx_graph, open(constants.DATA_DIR + GRAPH_PATH, 'wb'))
    else:
        nx_graph = pickle.load(open(constants.DATA_DIR + GRAPH_PATH, 'br'))
    jgrapht_g = jgrapht.convert.from_nx(nx_graph)
    nx_graph_reverse = nx_graph.reverse()

    centrality_measure_functions = [
        build_centrality_measure_function('betweenness_centrality', nx_graph_reverse),
        build_centrality_measure_function('closeness_centrality', nx_graph),
        build_centrality_measure_function('load_centrality', nx_graph_reverse),
        lambda node_id: 1,
    ]

    for centrality_function in centrality_measure_functions:
        risk_engine_weighted = VulnerabilityRiskEngine({
            'low': constants.CVSS_RISK_LOW_RANGE,
            'moderate': constants.CVSS_RISK_MODERATE_RANGE,
            'high': constants.CVSS_RISK_HIGH_RANGE,
            'very high': constants.CVSS_RISK_VERY_HIGH_RANGE,
        }, centrality_function)

        print(risk_engine_weighted.calculate_risk(jgrapht_g.vertices, jgrapht_g))

    colors = [get_color(attributes) for attributes in nx_graph.nodes.values()]
