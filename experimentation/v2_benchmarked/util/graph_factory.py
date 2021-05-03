import jgrapht
from networkx import DiGraph, nx
import matplotlib.pyplot as plt
import numpy as np

import constants
from v2_benchmarked.util.json_parser import JSONParser
from v2_benchmarked.util.risk_profile import RiskLevel


class EnrichedCallGraph(DiGraph):
    def add_node(self, node_for_adding, **attr):
        super().add_node(node_for_adding, **attr)
        self.nodes[node_for_adding]['metadata'] = {'vulnerabilities': {}}

    def add_vulnerability(self, node_with_vulnerability, cvss_score, cve_id='CVE-001'):
        if 'vulnerabilities' not in self.nodes[node_with_vulnerability]['metadata']:
            self.nodes[node_with_vulnerability]['metadata']['vulnerabilities'] = {}
        self.nodes[node_with_vulnerability]['metadata']['vulnerabilities'][cve_id] = {
            constants.CVSS_SCORE_VERSION: cvss_score
        }

    def remove_vulnerability(self, node_with_vulnerability):
        self.nodes[node_with_vulnerability]['metadata']['vulnerabilities'] = {}

    def get_severity_scores_for(self, node):
        if self.has_vulnerability(node):
            return [cve[constants.CVSS_SCORE_VERSION] for cve in self.nodes[node]['metadata']['vulnerabilities'].values()]
        return [0.0]

    def has_vulnerability(self, node):
        return len(self.nodes[node]['metadata']['vulnerabilities']) > 0

    def reachable_by(self, n):
        return set(nx.predecessor(self, n).keys()) - {n}

    def draw(self):
        fig, ax = plt.subplots()
        color_map = get_color_map(ax)
        colors = [get_color_from_map(attributes, color_map) for attributes in self.nodes.values()]
        nx.draw_shell(self, with_labels=True, node_color=colors, ax=ax)
        ax.legend(ncol=len(RiskLevel.list()), bbox_to_anchor=(0, 1), loc='lower left', fontsize='small')
        plt.show()


def create_graph_from_json(json_file):
    [classes, nodes, edges] = JSONParser().parseCGOpalGraph(constants.BASE_DIR + json_file)
    nx_graph = EnrichedCallGraph()
    for node_id, attributes in nodes.items():
        nx_graph.add_node(node_id, **attributes)
    nx_graph.add_edges_from(edges)
    nx_graph.remove_edges_from(nx.selfloop_edges(nx_graph))
    j_graph = jgrapht.convert.from_nx(nx_graph)
    return nx_graph, j_graph


def create_from_definition(graph_definition):
    graph = EnrichedCallGraph()
    for node_id, cvss_score in graph_definition['nodes'].items():
        graph.add_node(node_id)
        if cvss_score is not None:
            graph.add_vulnerability(node_id, cvss_score)

    graph.add_edges_from(graph_definition['edges'])
    return graph


def sub_graph_from_node_set(graph: DiGraph, node_set) -> EnrichedCallGraph:
    # Create a subgraph SG based on a (possibly multigraph) G
    sub_graph = EnrichedCallGraph()
    sub_graph.add_nodes_from((n, graph.nodes[n]) for n in node_set)
    sub_graph.add_edges_from(
        (n, nbr, d)
        for n, nbrs in graph.adj.items() if n in node_set
        for nbr, d in nbrs.items() if nbr in node_set
    )
    sub_graph.graph.update(graph.graph)
    return sub_graph


def get_color_map(ax=None):
    category_colors = plt.get_cmap('RdYlGn_r')(np.linspace(0.15, 0.85, len(RiskLevel.list())))
    if ax is not None:
        # make empty plot with correct color and label for each group
        for (risk_level, color) in zip(RiskLevel.list(), category_colors):
            ax.scatter([], [], color=color, label=risk_level)
    return category_colors


def get_color_from_map(attributes, color_map):
    if 'vulnerabilities' not in attributes['metadata'].keys() or not attributes['metadata']['vulnerabilities']:
        return color_map[0]
    highest_score = max([
        float(vulnerability[constants.CVSS_SCORE_VERSION]) for vulnerability in attributes['metadata']['vulnerabilities'].values()
    ])
    if constants.CVSS_RISK_LOW_RANGE['low'] < highest_score <= constants.CVSS_RISK_LOW_RANGE['high']:
        return color_map[1]
    elif constants.CVSS_RISK_MODERATE_RANGE['low'] < highest_score <= constants.CVSS_RISK_MODERATE_RANGE['high']:
        return color_map[2]
    elif constants.CVSS_RISK_HIGH_RANGE['low'] < highest_score <= constants.CVSS_RISK_HIGH_RANGE['high']:
        return color_map[3]
    elif constants.CVSS_RISK_VERY_HIGH_RANGE['low'] < highest_score <= constants.CVSS_RISK_VERY_HIGH_RANGE['high']:
        return color_map[4]
