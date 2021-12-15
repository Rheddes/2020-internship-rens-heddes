from __future__ import annotations
import itertools
import json
import logging
import re
import time

import matplotlib.patheffects as path_effects
import matplotlib.pyplot as plt
import numbers
from datetime import datetime
from typing import Tuple, List, Dict, Set

import ijson as ijson
import jgrapht
import jgrapht.algorithms.shortestpaths as sp
import networkx as nx
from jgrapht.algorithms import scoring
from jgrapht.types import Graph
import pandas as pd
from networkx import DiGraph
from texttable import Texttable
from cvss import CVSS3
from cvss.cvss3 import round_up
import numpy as np

from utils import config
from utils.general import sort_dict


def parse_JSON_file(filename: str) -> Tuple[List, List, Dict, pd.DataFrame, Set]:

    start_time = datetime.now()

    data_rows = []
    node_ids = []
    vulnerable_nodes = {}
    vulnerabilities = set()
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
                vulnerable_nodes[node_id] = q_dict['vulnerabilities']
                no_vulnerabilities = len(q_dict['vulnerabilities'].values())
                max_score_v2 = 0.0
                max_score_v3 = 0.0
                for id, vulnerability in q_dict['vulnerabilities'].items():
                    if id not in vulnerabilities:
                        vulnerabilities.add(id)
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

    logging.info('Total number of edges in call graph = %s', str(len(all_edges)))
    logging.info('Removed self-loops in graph, number of edges to be used: %s', str(len(edges)))

    logging.info('Parsed JSON into DataFrame, elapsed time = %s', str(datetime.now() - start_time))

    return node_ids, edges, vulnerable_nodes, df, vulnerabilities


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


def proportional_risk(sg: RiskGraph, risk_scores):
    proportional_risks = {}
    total_risk = sum(risk_scores.values())
    proportional_cvss = lambda n, v: sg.get_severity_scores_for(n)[v] / sum(sg.get_severity_scores_for(n).values())
    for vulnerability, nodes in sg.get_vulnerabilities().items():
        proportional_risks[vulnerability] = sum([proportional_cvss(node, vulnerability) * risk_scores[node]/total_risk for node in nodes])
    return sort_dict(proportional_risks)


def _combine_scores(scores: list) -> float:
    scores = np.array(scores)
    return 10 * (1-np.product(1-(scores/10)))


class RiskGraph(DiGraph):
    def __init__(self, **attr):
        self._reachable_by_cache = {}
        self._propagated_risk_cache = {}
        self._centrality_cache = {}
        self.cvss_combination_function = _combine_scores
        self.propagation_function = _combine_scores
        self.centrality_score_function = None
        self._model = 'd'
        self._auto_update = True
        super().__init__(**attr)

    @staticmethod
    def create(nodes: list, edges: list, vulnerable_nodes: dict, metadata: pd.DataFrame, vulnerabilities=None, auto_update=True) -> RiskGraph:
        logging.info('Creating call-graph with %s nodes, %s edges', len(nodes), len(edges))
        start_time = time.perf_counter()
        nx_graph = RiskGraph()
        nx_graph._auto_update = auto_update
        for index, row in metadata.iterrows():
            nx_graph.add_node(row['id'], row.to_dict())
        nx_graph.add_edges_from(edges)
        nx_graph.remove_edges_from(nx.selfloop_edges(nx_graph))
        for node_id, vulnerabilities in vulnerable_nodes.items():
            nx_graph.add_vulnerabilities(node_id, vulnerabilities)
            # for cve, vulnerability in vulnerabilities.items():
            #     if config.CVSS_SCORE_VERSION in vulnerability:
            #         nx_graph.add_vulnerability(node_id, vulnerability[config.CVSS_SCORE_VERSION], cve)
        if auto_update:
            nx_graph.configure_for_model(nx_graph._model)
        logging.info('Created call-graph, elapsed time = %s seconds', time.perf_counter()-start_time)
        return nx_graph

    def configure_for_model(self, model):
        self.reset_cache()
        coreachability = {node_id: len(nx.algorithms.dag.ancestors(self, node_id)) for node_id in self.nodes.keys()}
        betweenness = nx.algorithms.centrality.betweenness_centrality(self, endpoints=True)

        if model == 'a':
            self.centrality_score_function = lambda x: coreachability[x]/sum(coreachability.values())
            self.propagation_function = lambda x: sum(x)
            self._model = model
        elif model == 'b':
            self.centrality_score_function = lambda x: coreachability[x]/max(coreachability.values())
            self.propagation_function = lambda x: _combine_scores(x)
            self._model = model
        elif model == 'c':
            self.centrality_score_function = lambda x: betweenness[x]/sum(betweenness.values())
            self.propagation_function = lambda x: sum(x)
            self._model = model
        elif model == 'd':
            self.centrality_score_function = lambda x: betweenness[x]/max(betweenness.values())
            self.propagation_function = lambda x: _combine_scores(x)
            self._model = model
        else:
            raise Exception('Model not defined')

    def add_node(self, node_for_adding, metadata=None, **attr):
        if metadata is None:
            metadata = {}
        super().add_node(node_for_adding, **attr)
        self.nodes[node_for_adding]['infected'] = 0
        self.nodes[node_for_adding]['metadata'] = {'vulnerabilities': {}, **metadata}
        if self.has_vulnerability(node_for_adding):
            self.nodes[node_for_adding]['infected'] = 1
        if self._auto_update:
            self.configure_for_model(self._model)

    def get_vulnerabilities(self):
        vulnerabilities = {}
        for node, attributes in self.get_vulnerable_nodes().items():
            for vulnerability in attributes['metadata']['vulnerabilities'].keys():
                vulnerabilities[vulnerability] = vulnerabilities.get(vulnerability, []) + [node]
        return vulnerabilities

    def add_vulnerability(self, node_with_vulnerability, cvss_score, cve_id):
        if 'vulnerabilities' not in self.nodes[node_with_vulnerability]['metadata']:
            self.nodes[node_with_vulnerability]['metadata']['vulnerabilities'] = {}
            self.nodes[node_with_vulnerability]['infected'] = 1
        self.nodes[node_with_vulnerability]['metadata']['vulnerabilities'][cve_id] = {
            'id': cve_id,
            config.CVSS_SCORE_VERSION: cvss_score,
        }
        if self._auto_update:
            self.configure_for_model(self._model)

    def add_vulnerabilities(self, node_with_vulnerabilities, vulnerabilities):
        self.nodes[node_with_vulnerabilities]['metadata']['vulnerabilities'] = {
            **self.nodes[node_with_vulnerabilities]['metadata']['vulnerabilities'], **vulnerabilities
        }
        if self._auto_update:
            self.configure_for_model(self._model)

    def remove_vulnerability_from_node(self, node_with_vulnerability, cve=None):
        if cve:
            del self.nodes[node_with_vulnerability]['metadata']['vulnerabilities'][cve]
        else:
            self.nodes[node_with_vulnerability]['metadata']['vulnerabilities'] = {}
        if self._auto_update:
            self.configure_for_model(self._model)

    def remove_vulnerability(self, cve):
        for node in self.get_vulnerabilities().get(cve, []):
            self.remove_vulnerability_from_node(node, cve)

    def get_severity_scores_for(self, node):
        return {cve['id']: cve.get(config.CVSS_SCORE_VERSION, 0.0) for cve in self.nodes[node]['metadata']['vulnerabilities'].values()}

    def get_impact_scores_for(self, node):
        return {cve['id']: float(round_up(CVSS3(cve['vectorCVSS3']).isc)) if 'vectorCVSS3' in cve else 0.0 for cve in self.nodes[node]['metadata']['vulnerabilities'].values()}

    def get_inherent_risk_for(self, node):
        return self.cvss_combination_function(list(self.get_severity_scores_for(node).values())) * self.centrality_score_function(node)

    def reset_cache(self):
        self._reachable_by_cache = {}
        self._propagated_risk_cache = {}
        self._centrality_cache = {}

    def get_propagated_risk_for(self, node, use_cache=True):
        if not use_cache or node not in self._propagated_risk_cache:
            self._propagated_risk_cache[node] = self.propagation_function([self.get_inherent_risk_for(n) for n in {*self.reachable_by(node, use_cache), *{node}}])
        return self._propagated_risk_cache[node]

    def get_app_risk(self):
        risks = {k: self.get_inherent_risk_for(k) for k in self.get_vulnerable_nodes().keys()}
        return self.propagation_function(list(risks.values()))

    def reachable_by(self, n, use_cache=True):
        if n not in self._reachable_by_cache or not use_cache:
            self._reachable_by_cache[n] = set(nx.predecessor(self, n).keys()) - {n}
        return self._reachable_by_cache[n]

    def reachable_by_application(self):
        reachable = set()
        for node in self.get_application_nodes().keys():
            reachable = reachable.union(set(sum(list(nx.algorithms.bfs_tree(self, node).edges()), ())))
        return reachable

    def has_vulnerability(self, node):
        return len(self.nodes[node]['metadata']['vulnerabilities']) > 0

    def get_vulnerable_nodes(self):
        vulnerable_nodes = {}
        for node_id, node_data in self.nodes.items():
            if node_data['metadata']['vulnerabilities']:
                vulnerable_nodes[node_id] = node_data
        return vulnerable_nodes

    def get_application_nodes(self):
        application_nodes = {}
        for node_id, node_data in self.nodes.items():
            if node_data['metadata']['application_node']:
                application_nodes[node_id] = node_data
        return application_nodes

    def sub_graph_from_node_ids(self, node_ids, auto_update=True, make_dag=False) -> RiskGraph:
        sub_graph = RiskGraph()
        sub_graph.add_nodes_from((n, self.nodes[n]) for n in node_ids)
        for (u, v, dd) in (
            (n, neighbour, d)
            for n, neighbours in self.adj.items() if n in node_ids
            for neighbour, d in neighbours.items() if neighbour in node_ids
        ):
            sub_graph.add_edge(u, v, **dd)
            if make_dag and not nx.is_directed_acyclic_graph(sub_graph):
                logging.debug('Edge (%s, %s) introduces cycle (removed)', u, v)
                sub_graph.remove_edge(u, v)
        sub_graph.graph.update(self.graph)
        if auto_update:
            sub_graph.configure_for_model(self._model)
        return sub_graph

    def to_table_scores(self):
        rows = [[node_id, self.get_severity_scores_for(node_id), self.cvss_combination_function(list(self.get_severity_scores_for(node_id).values())), self.get_inherent_risk_for(node_id), self.get_propagated_risk_for(node_id)] for node_id in self.nodes.keys()]
        table = Texttable()
        table.set_cols_align(['l', 'l', 'l', 'l', 'l'])
        table.set_cols_valign(['b', 'b', 'b', 'b', 'b'])
        table.set_precision(2)
        table.add_rows([['Node id', 'CVSS', 'Combined', 'Intrinsic risk', 'Propagated risk'], *rows])
        return table

    def to_table(self):
        def get_method_name_from(uri):
            return re.search(r'/[a-zA-Z0-9_.]+/[a-zA-Z0-9_$%]+\.([a-zA-Z0-9_%$]+)\(', uri).group(1)
        rows = [[node_id, get_method_name_from(self.nodes[node_id]['metadata']['uri']), self.get_severity_scores_for(node_id)] for node_id in self.nodes.keys()]
        table = Texttable()
        table.set_cols_align(['l', 'l', 'l'])
        table.set_cols_valign(['b', 'b', 'b'])
        table.set_precision(2)
        table.add_rows([['Node id', 'Method', 'CVSS Scores'], *rows])
        return table

    def draw(self, pos=None, title=None, legend=True, cvss_table=True, legend_outside=True):

        plt.subplots(figsize=(7, 9))
        if pos is None:
            pos = nx.nx_pydot.pydot_layout(self, prog='dot')
        sm = plt.cm.ScalarMappable(cmap=plt.get_cmap('RdYlGn_r'),
                                   norm=plt.Normalize(vmin=0, vmax=10))

        node_sizes = [100 + 500 * self.centrality_score_function(n) for n in self]
        node_color = [sm.cmap(sm.norm(self.get_propagated_risk_for(n))) for n in self]
        sorted_centralities = sorted([self.centrality_score_function(n) for n in self])

        plt.colorbar(sm, ticks=range(11), label='Associated propagated risk score')
        sc = nx.draw_networkx_nodes(self, pos=pos, node_size=node_sizes, node_color=node_color,
                                    cmap=plt.get_cmap('RdYlGn_r'))
        nx.draw_networkx_edges(self, pos=pos, node_size=max(node_sizes))
        text_items = nx.draw_networkx_labels(self, pos=pos, font_weight='bold')
        for text_item in text_items.values():
            text_item.set_path_effects([path_effects.Stroke(linewidth=1.5, foreground='white'),
                                        path_effects.Normal()])

        if legend:
            sizes = sc.legend_elements('sizes', num=len(node_sizes))
            median = sorted_centralities[len(sorted_centralities) // 2]
            unique_sorted_centralities = np.unique(sorted_centralities)
            idx = [0, np.where(unique_sorted_centralities == median)[0][0], -1]
            legend_node_sizes = list(np.array(sizes[0])[idx])
            legend_labels = ['{:.2f}'.format(x) for x in
                             [unique_sorted_centralities[0], median, unique_sorted_centralities[-1]]]
            if legend_outside:
                plt.legend(legend_node_sizes, legend_labels, title='Centrality measures\n(min, median, max)', labelspacing=2,
                           bbox_to_anchor=(-0.04, 1.02), loc='upper right', borderpad=1)
            else:
                plt.legend(legend_node_sizes, legend_labels, title='Scored centrality\n(min, median, max)',
                           labelspacing=2, borderpad=1, loc='upper left')

        if cvss_table:
            text = [[node_id, self.get_severity_scores_for(node_id)] for node_id in self if self.has_vulnerability(node_id)]
            table_height = min((len(text)+1) * 0.05, 0.55)
            plt.table(cellText=text, colLabels=['node', 'CVSS scores'],
                      bbox=(-0.61, 0, 0.55, table_height), label='LABEL')

        if title:
            plt.title(title)
        plt.tight_layout()
