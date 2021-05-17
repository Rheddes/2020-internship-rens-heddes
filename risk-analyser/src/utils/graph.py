from __future__ import annotations
import itertools
import json
import logging
import numbers
from datetime import datetime
from typing import Tuple, List, Dict

import ijson as ijson
import jgrapht
import jgrapht.algorithms.shortestpaths as sp
import networkx as nx
from jgrapht.algorithms import scoring
from jgrapht.types import Graph
import pandas as pd
from networkx import DiGraph

import config


def parse_JSON_file(filename: str) -> Tuple[List, List, Dict, pd.DataFrame]:

    start_time = datetime.now()

    data_rows = []
    node_ids = []
    vulnerabilities = {}
    with open(filename) as f:
        objects = ijson.items(f, 'nodes.item')

        for o in objects:
            node_id = int(o['id'])
            node_ids.append(node_id)

            q_dict = json.loads(o['metadata'])

            has_vulnerabilities = 'vulnerabilities' in q_dict.keys()

            score_v2 = None
            score_v3 = None
            no_vulnerabilities = 0
            if has_vulnerabilities:
                vulnerabilities[node_id] = q_dict['vulnerabilities']
                no_vulnerabilities = len(q_dict['vulnerabilities'].values())
                max_score_v2 = 0.0
                max_score_v3 = 0.0
                for vulnerability in q_dict['vulnerabilities'].values():
                    if 'scoreCVSS3' in vulnerability and isinstance(vulnerability['scoreCVSS3'], numbers.Number):
                        max_score_v3 = max(max_score_v3, vulnerability.get('scoreCVSS3'), 0.0)
                    if 'scoreCVSS2' in vulnerability and isinstance(vulnerability['scoreCVSS2'], numbers.Number):
                        max_score_v2 = max(max_score_v2, vulnerability.get('scoreCVSS2'), 0.0)
                score_v2 = max_score_v2
                score_v3 = max_score_v3

            data_rows.append([node_id, o['application_node'], o['uri'], score_v2, score_v3, no_vulnerabilities])
        df = pd.DataFrame(data_rows, columns=['id', 'application_node', 'uri', 'cvss_v2', 'cvss_v3', 'number_of_vulnerabilities'])

        f.seek(0)
        e_objects = ijson.items(f, 'edges.item')
        all_edges = [list((int(o['source']), int(o['target']))) for o in e_objects]

        # remove self-loop i.e. tuples where elements are the same
        edges = list(filter(lambda x: x[0] != x[1], all_edges))

    logging.info("Total number of edges in call graph = %s", str(len(all_edges)))
    logging.info("Removed self-loops in graph, number of edges to be used: %s", str(len(edges)))

    logging.info("Parsed JSON into DataFrame, elapsed time = %s", str(datetime.now() - start_time))

    return node_ids, edges, vulnerabilities, df


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


def get_total_vulnerability_coverage(reverse_graph: Graph, vulnerable_nodes: dict, application_nodes: list) -> dict:
    reachable_nodes = {}
    for source, target in itertools.product(vulnerable_nodes.keys(), application_nodes):
        path = sp.dijkstra(reverse_graph, source, target)
        if path is not None:
            if target not in reachable_nodes:
                reachable_nodes[target] = {}
            reachable_nodes[target] = {**reachable_nodes[target], **vulnerable_nodes[source]}
    return reachable_nodes


class EnrichedCallGraph(DiGraph):
    def __init__(self, **attr):
        self._reachable_by_cache = {}
        super().__init__(**attr)

    @staticmethod
    def create(nodes: list, edges: list, vulnerable_nodes: dict) -> EnrichedCallGraph:
        nx_graph = EnrichedCallGraph()
        for node_id in nodes:
            nx_graph.add_node(node_id)
        nx_graph.add_edges_from(edges)
        nx_graph.remove_edges_from(nx.selfloop_edges(nx_graph))
        for node_id, vulnerabilities in vulnerable_nodes.items():
            for cve, vulnerability in vulnerabilities.items():
                if config.CVSS_SCORE_VERSION in vulnerability:
                    nx_graph.add_vulnerability(node_id, vulnerability[config.CVSS_SCORE_VERSION], cve)
        return nx_graph

    def add_node(self, node_for_adding, **attr):
        super().add_node(node_for_adding, **attr)
        self.nodes[node_for_adding]['metadata'] = {'vulnerabilities': {}}

    def add_vulnerability(self, node_with_vulnerability, cvss_score, cve_id):
        if 'vulnerabilities' not in self.nodes[node_with_vulnerability]['metadata']:
            self.nodes[node_with_vulnerability]['metadata']['vulnerabilities'] = {}
        self.nodes[node_with_vulnerability]['metadata']['vulnerabilities'][cve_id] = {
            config.CVSS_SCORE_VERSION: cvss_score
        }

    def remove_vulnerability(self, node_with_vulnerability, cve=None):
        if cve:
            del self.nodes[node_with_vulnerability]['metadata']['vulnerabilities']['cve']
        self.nodes[node_with_vulnerability]['metadata']['vulnerabilities'] = {}

    def get_severity_scores_for(self, node):
        if self.has_vulnerability(node):
            return [cve[config.CVSS_SCORE_VERSION] for cve in self.nodes[node]['metadata']['vulnerabilities'].values()]
        return [0.0]

    def has_vulnerability(self, node):
        return len(self.nodes[node]['metadata']['vulnerabilities']) > 0

    def reachable_by(self, n):
        if n not in self._reachable_by_cache:
            self._reachable_by_cache[n] = set(nx.predecessor(self, n).keys()) - {n}
        return self._reachable_by_cache[n]
