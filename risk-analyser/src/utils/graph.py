import itertools
import json
import logging
from datetime import datetime
from typing import Tuple, List

import ijson as ijson
import jgrapht
import jgrapht.algorithms.shortestpaths as sp
from jgrapht.algorithms import scoring
from jgrapht.types import Graph
import pandas as pd


def parse_JSON_file(filename: str) -> Tuple[List, List, pd.DataFrame]:

    start_time = datetime.now()

    data_rows = []
    node_ids = []

    with open(filename) as f:
        objects = ijson.items(f, 'nodes.item')

        for o in objects:
            node_id = int(o['id'])
            node_ids.append(node_id)

            q_dict = json.loads(o['metadata'])

            has_vulnerabilities = 'vulnerabilities' in q_dict.keys()

            score_v2 = None
            score_v3 = None
            if has_vulnerabilities:
                max_score_v2 = 0.0
                max_score_v3 = 0.0
                for vulnerability in q_dict['vulnerabilities'].values():
                    if type(vulnerability['scoreCVSS3']) == int or float:
                        max_score_v3 = max(max_score_v3, vulnerability.get('scoreCVSS3'), 0.0)
                    max_score_v2 = max(max_score_v2, vulnerability.get('scoreCVSS2'), 0.0)
                score_v2 = max_score_v2
                score_v3 = max_score_v3

            data_rows.append([node_id, o['application_node'], o['uri'], score_v2, score_v3])
        df = pd.DataFrame(data_rows, columns=['id', 'application_node', 'uri', 'cvss_v2', 'cvss_v3'])

        f.seek(0)
        e_objects = ijson.items(f, 'edges.item')
        all_edges = [list((int(o['source']), int(o['target']))) for o in e_objects]

        # remove self-loop i.e. tuples where elements are the same
        edges = list(filter(lambda x: x[0] != x[1], all_edges))

    logging.info("Total number of edges in call graph = %s", str(len(all_edges)))
    logging.info("Removed self-loops in graph, number of edges to be used: %s", str(len(edges)))

    logging.info("Parsed JSON into DataFrame, elapsed time = %s", str(datetime.now() - start_time))

    return node_ids, edges, df


def create_graphs(node_ids, edges) -> Tuple[Graph, Graph, pd.DataFrame]:
    start_time = datetime.now()

    call_graph = jgrapht.create_graph(directed=True, weighted=False, allowing_self_loops=False,
                                      allowing_multiple_edges=True, any_hashable=True)

    call_graph.add_vertices_from(node_ids)
    call_graph.add_edges_from(edges)

    logging.info('Created CallGraph, elapsed time= %s', str(datetime.now() - start_time))
    start_time = datetime.now()

    reverse_graph = jgrapht.views.as_edge_reversed(call_graph)

    logging.info('Created reversed CallGraph, elapsed time= %s', str(datetime.now() - start_time))
    start_time = datetime.now()

    df_graph_measures = calculate_centrality_measures(call_graph, reverse_graph, node_ids)

    logging.info('Calculated centrality measures, elapsed time = %s', str(datetime.now() - start_time))

    return call_graph, reverse_graph, df_graph_measures


def calculate_centrality_measures(call_graph, reverse_graph, node_list: list) -> pd.DataFrame:
    # Calculate centrality measures for the callGraph
    pagerank = scoring.pagerank(call_graph)
    # closeness_centrality = scoring.closeness_centrality(callGraph)
    # harmonic_centrality = scoring.harmonic_centrality(callGraph)

    # Calculate centrality measures of the reversedGraph
    reverse_pagerank = scoring.pagerank(reverse_graph)
    # reverse_closeness_centrality = scoring.closeness_centrality(reverseGraph)
    # reverse_harmonic_centrality = scoring.harmonic_centrality(reverseGraph)

    data_rows = []

    for node in node_list:
        in_degree = call_graph.indegree_of(node)
        out_degree = call_graph.outdegree_of(node)
        node_ranking = pagerank[node]

        reverse_in_degree = reverse_graph.indegree_of(node)
        reverse_out_degree = reverse_graph.outdegree_of(node)
        reverse_node_ranking = reverse_pagerank[node]

        data_rows.append([node, in_degree, out_degree, node_ranking, reverse_in_degree, reverse_out_degree, reverse_node_ranking])

    df = pd.DataFrame(data_rows, columns=['id', 'in_degree', 'out_degree', 'ranking', 'in_degree_reverse', 'out_degree_reverse', 'ranking_reverse'])

    return df


def get_total_vulnerability_coverage(reverse_graph: Graph, vulnerable_nodes: list, application_nodes: list) -> list:
    reachable_nodes = set()
    for source, target in itertools.product(vulnerable_nodes, application_nodes):
        path = sp.dijkstra(reverse_graph, source, target)
        if path is not None:
            reachable_nodes.update({target})
    return list(reachable_nodes)
