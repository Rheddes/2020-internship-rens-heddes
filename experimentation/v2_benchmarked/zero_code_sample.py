import operator
import pickle
from math import floor

import latextable
import networkx as nx
from networkx import Graph as NxGraph, DiGraph

import matplotlib.pyplot as plt
import numpy as np
from jgrapht.types import Graph as JGraph
from texttable import Texttable

import constants
from v2_benchmarked.util.core import get_method_name_from, coords_from_gexf
from v2_benchmarked.util.graph_factory import EnrichedCallGraph, sub_graph_from_node_set, create_graph_from_json
from v2_benchmarked.util.graph_sampling import bfs_sample_subgraph, subsample_graphs
from v2_benchmarked.util.json_parser import JSONParser
import jgrapht
import re
import random

from v2_benchmarked.util.risk_engine import VulnerabilityRiskEngine
from v2_benchmarked.util.risk_profile import RiskLevel, plot_risk_profiles

CVSS_SCORE_DISTRIBUTION = pickle.load(open(constants.DATA_DIR + '/distribution.p', 'br'))
VULNERABLE_NODE_RATIO = 0.2
EXPERIMENTATION_CVSS_SCORES = {'none': None, 'low': 3.0, 'medium': 4.5, 'high': 6.0, 'very high': 7.5}
VULNERABILITIES = {1539: 10.0, 1641: 7.6, 496: 7.1, 1403: 8.5}


def assign_vulnerabilities_and_labels(sg, vulns, coords, use_cvss_color_map=False):
    for node_id, node in sg.nodes.items():
        sg.nodes[node_id]['cvss'] = ''
        sg.nodes[node_id]['label'] = '{} - {}'.format(node_id, get_method_name_from(node['uri']))
        sg.nodes[node_id]['method'] = get_method_name_from(node['uri'])
        sg.nodes[node_id]['label_cvss'] = '{} - {} - None'.format(node_id, get_method_name_from(node['uri']))
        if node_id in vulns:
            sg.add_vulnerability(node_id, vulns[node_id])
        if sg.has_vulnerability(node_id):
            cvss = max(sg.get_severity_scores_for(node_id))
            sg.nodes[node_id]['cvss'] = cvss
            sg.nodes[node_id]['label_cvss'] = '{} - {} - {}'.format(node_id, get_method_name_from(node['uri']), cvss)
        if node_id in coords:
            sg.nodes[node_id]['viz'] = {
                'size': 5.0,
                'position': coords[node_id],
                'color': {'r': 10, 'g': 200, 'b': 0, 'a': 0},
            }
            if use_cvss_color_map:
                cmap = plt.get_cmap('RdYlGn_r')
                def to_gephi_color(plt_color):
                    return int(floor(plt_color*255))
                colors = list(map(to_gephi_color, cmap(max(sg.get_severity_scores_for(node_id))/10)))
                sg.nodes[node_id]['viz']['color'] = {'r': colors[0], 'g': colors[1], 'b': colors[2], 'a': 0}


def create_risk_engine_with_centrality_function(cf):
    return VulnerabilityRiskEngine({
        'low': constants.CVSS_RISK_LOW_RANGE,
        'moderate': constants.CVSS_RISK_MODERATE_RANGE,
        'high': constants.CVSS_RISK_HIGH_RANGE,
        'very high': constants.CVSS_RISK_VERY_HIGH_RANGE,
    }, cf)


def generate_vulnerabilities(graph: NxGraph, centrality_scores):
    nodes_to_investigate = set()
    for scores in centrality_scores.values():
        sorted_by_centrality = sorted(scores.items(), key=operator.itemgetter(1), reverse=True)
        nodes_to_investigate.update([node_id for (node_id, score) in sorted_by_centrality[:3]])

    generated_vulnerabilities = {}
    for node in graph.nodes.keys():
        if node not in nodes_to_investigate:
            if random.random() < VULNERABLE_NODE_RATIO:
                generated_vulnerabilities[node] = np.random.choice(CVSS_SCORE_DISTRIBUTION, 1)[0]
    return generated_vulnerabilities


def calculate_risk_profiles(graph: EnrichedCallGraph, centrality_scores):
    for centrality_measure, scores in centrality_scores.items():
        sorted_by_centrality = sorted(scores.items(), key=operator.itemgetter(1), reverse=True)
        print('------START: {} ------'.format(centrality_measure))
        for (node_id, centrality) in sorted_by_centrality[0:3]:
            print('Node id: {}, with score: {}'.format(node_id, centrality))
            print(graph.nodes[node_id]['label'])
            print(graph.nodes[node_id]['uri'])
        print('------END------')
        results = {}
        for i in range(3):
            for level, cvss_score in EXPERIMENTATION_CVSS_SCORES.items():
                most_central_node_id = sorted_by_centrality[i][0]

                risk_engine_weighted = create_risk_engine_with_centrality_function(lambda node_id: scores[node_id])
                if cvss_score:
                    graph.add_vulnerability(most_central_node_id, cvss_score)
                temp_graph = jgrapht.convert.from_nx(graph)

                results['{}_{}'.format(level, i+1)] = risk_engine_weighted.calculate_risk_profile(temp_graph.vertices, temp_graph)
                graph.remove_vulnerability(most_central_node_id)
        plot_risk_profiles(results, centrality_measure)


def risk_scores_for_metrics(sub_graph, scores_for_centralities, centrality_metrics):
    for centrality_metric in centrality_metrics:
        scores_for_centrality = scores_for_centralities[centrality_metric]
        sum_scores = sum(scores_for_centrality.values())
        intrinsic_risk_scores = {node_id: (score * max(sub_graph.get_severity_scores_for(node_id)) / sum_scores) for node_id, score in scores_for_centrality.items()}

        def risk_for_counting_vulnerabilities_double(n):
            return intrinsic_risk_scores[n] + sum([risk_for_counting_vulnerabilities_double(neighbor) for neighbor in sub_graph.neighbors(n)])

        def risk_for_singular(n):
            return intrinsic_risk_scores[n] + sum([intrinsic_risk_scores[pred] for pred in sub_graph.reachable_by(n)])

        risk_scores = {node_id: risk_for_singular(node_id) for node_id in sub_graph.nodes.keys()}

        for node_id, node in sub_graph.nodes.items():
            sub_graph.nodes[node_id]['label_risk_{}'.format(centrality_metric)] = '{} - {} - {:.1f}'.format(node_id, get_method_name_from(node['uri']), risk_scores[node_id])
            sub_graph.nodes[node_id]['risk_{}'.format(centrality_metric)] = risk_scores[node_id]
            sub_graph.nodes[node_id]['centrality_{}'.format(centrality_metric)] = scores_for_centrality[node_id]


def build_table(centrality_scores, graph):
    rows = [
        ['Node id', 'Function', 'Betweenness', 'Closeness', 'PageRank', 'Coreachability'],
    ]
    for node_id, node in graph.nodes.items():
        rows.append([
            node_id,
            get_method_name_from(node['uri']),
            centrality_scores['betweenness_centrality'][node_id],
            centrality_scores['closeness_centrality'][node_id],
            centrality_scores['page_rank'][node_id],
            centrality_scores['coreachability'][node_id],
        ])
    return rows


def build_table_normalized(centrality_scores, graph):
    rows = [
        ['Node id', 'Function', 'Betweenness', 'Closeness', 'PageRank', 'Coreachability (sum)', 'Coreachability (nodecount)'],
    ]
    centrality_sums = {metric: sum(scores_for_metric.values()) for metric, scores_for_metric in centrality_scores.items()}
    centrality_sums['coreachability_no_nodes'] = len(graph.nodes.items())
    for node_id, node in graph.nodes.items():
        rows.append([
            node_id,
            get_method_name_from(node['uri']),
            centrality_scores['betweenness_centrality'][node_id] / centrality_sums['betweenness_centrality'],
            centrality_scores['closeness_centrality'][node_id] / centrality_sums['closeness_centrality'],
            centrality_scores['page_rank'][node_id] / centrality_sums['page_rank'],
            centrality_scores['coreachability'][node_id] / centrality_sums['coreachability'],
            centrality_scores['coreachability'][node_id] / centrality_sums['coreachability_no_nodes'],
        ])
    return rows


if __name__ == '__main__':
    nx_graph, j_graph = create_graph_from_json('/data/zero-code-call-graph.json')

    # subsample_graphs(nx_graph, 20)
    selected_nodes = {1408, 1409, 515, 1539, 906, 1307, 1321, 1328, 1329, 1332, 86, 87, 1641, 1642, 492, 496, 887, 376, 1403, 1404}
    sub_graph = sub_graph_from_node_set(nx_graph, selected_nodes)
    # Generate representative sub graph and set method name as label
    # selected_node_id = 735
    # sub_graph = bfs_sample_subgraph(nx_graph, selected_node_id)

    sub_graph_j = jgrapht.convert.from_nx(sub_graph)
    sub_graph_reversed_j = jgrapht.convert.from_nx(sub_graph.reverse())
    centrality_metrics = {
        'betweenness_centrality': dict(nx.algorithms.centrality.betweenness_centrality(sub_graph)),
        'load_centrality': dict(nx.algorithms.centrality.load_centrality(sub_graph)),
        'closeness': dict(nx.algorithms.centrality.closeness_centrality(sub_graph)),
        'page_rank': dict(jgrapht.algorithms.scoring.pagerank(sub_graph_j)),
        'page_rank_reversed': dict(jgrapht.algorithms.scoring.pagerank(sub_graph_reversed_j)),
        'harmonic_centrality_reversed': dict(jgrapht.algorithms.scoring.harmonic_centrality(sub_graph_reversed_j)),
        'coreachability': {node_id: len(nx.algorithms.dag.ancestors(sub_graph, node_id))/len(sub_graph.nodes.keys()) for node_id in sub_graph.nodes.keys()}
    }

    # Generate vulnerabilities
    vulnerabilities = VULNERABILITIES if VULNERABILITIES else generate_vulnerabilities(sub_graph, centrality_metrics)
    assign_vulnerabilities_and_labels(sub_graph, vulnerabilities, coords_from_gexf(constants.BASE_DIR + '/test-export.gexf'), True)
    risk_scores_for_metrics(sub_graph, centrality_metrics, ['closeness', 'coreachability'])
    nx.write_gexf(sub_graph, 'zerocode_subgraph_ff_all_nodes.gexf')
    # calculate_risk_profiles(sub_graph, centrality_metrics)

    # table = Texttable()
    # table.set_cols_align(["c"] * 6)
    # table.set_deco(Texttable.HEADER | Texttable.VLINES)
    # table.add_rows(build_table(centrality_metrics, sub_graph))
    # print(latextable.draw_latex(table, 'Centrality scores'))
    #
    # table = Texttable()
    # table.set_cols_align(["c"] * 7)
    # table.set_deco(Texttable.HEADER | Texttable.VLINES)
    # table.add_rows(build_table_normalized(centrality_metrics, sub_graph))
    # print(latextable.draw_latex(table, 'Normalised centrality scores'))
# 735

