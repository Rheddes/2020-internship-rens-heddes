import jgrapht
import networkx as nx
import matplotlib.pyplot as plt
import numpy as np

import constants
from v2_benchmarked.util.graph_factory import EnrichedCallGraph, create_from_definition
from v2_benchmarked.util.risk_engine import VulnerabilityRiskEngine
from v2_benchmarked.util.risk_profile import RiskLevel, plot_risk_profiles

score = 7.5
base_case_graphs = {
    'two-unconnected': {'nodes': {0: None, 1: None}, 'edges': []},
    'two-connected': {'nodes': {0: None, 1: None}, 'edges': [(0, 1)]},
    'two-connected-with-vulnerability': {'nodes': {0: None, 1: score}, 'edges': [(0, 1)]},
    'split-with-vulnerable-leaf': {'nodes': {0: None, 1: None, 2: score, 3: None}, 'edges': [(0, 1), (1, 2), (1, 3)]},
    'split-with-vulnerable-middle': {'nodes': {0: None, 1: score, 2: None, 3: None}, 'edges': [(0, 1), (1, 2), (1, 3)]},
    'chain-with-vulnerable-end': {'nodes': {0: None, 1: None, 2: None, 3: score}, 'edges': [(0, 1), (1, 2), (2, 3)]},
    'chain-with-vulnerable-middle': {'nodes': {0: None, 1: score, 2: None, 3: None}, 'edges': [(0, 1), (1, 2), (2, 3)]},
    'diamond-with-vulnerable-leaf': {'nodes': {0: None, 1: None, 2: score, 3: None}, 'edges': [(0, 1), (0, 3), (1, 2), (3, 2)]},
    'diamond-with-vulnerable-middle': {'nodes': {0: None, 1: score, 2: None, 3: None}, 'edges': [(0, 1), (0, 3), (1, 2), (3, 2)]},
    # 'example': {'nodes': {0: None, 1: 2.5, 2: 4.5, 3: 5.4, 4: 7.5}, 'edges': [(0, 1), (1, 2), (2, 3), (3, 4)]},
}


def build_centrality_measure_function(centrality_measure, graph):
    def get_centrality_measure_for(node_id):
        return getattr(nx.algorithms.centrality, centrality_measure)(graph)[node_id]

    return get_centrality_measure_for


if __name__ == '__main__':
    print('------Risk scores------')
    for graph_name, graph_definition in base_case_graphs.items():
        graph = create_from_definition(graph_definition)
        graph.draw()

        jgrapht_g = jgrapht.convert.from_nx(graph)
        nx_graph_reverse = graph.reverse()

        centrality_measure_functions = {
            'betweenness_centrality': build_centrality_measure_function('betweenness_centrality', nx_graph_reverse),
            'closeness_centrality': build_centrality_measure_function('closeness_centrality', graph),
            'load_centrality': build_centrality_measure_function('load_centrality', nx_graph_reverse),
            'page_rank': lambda node_id: jgrapht.algorithms.scoring.pagerank(jgrapht_g)[node_id],
            'equal_weight': lambda node_id: 1,
        }
        results = {}

        for centrality, centrality_function in centrality_measure_functions.items():
            risk_engine_weighted = VulnerabilityRiskEngine({
                'low': constants.CVSS_RISK_LOW_RANGE,
                'moderate': constants.CVSS_RISK_MODERATE_RANGE,
                'high': constants.CVSS_RISK_HIGH_RANGE,
                'very high': constants.CVSS_RISK_VERY_HIGH_RANGE,
            }, centrality_function)
            results[centrality] = risk_engine_weighted.calculate_risk_profile(jgrapht_g.vertices, jgrapht_g)

        plot_risk_profiles(results, graph_name)
