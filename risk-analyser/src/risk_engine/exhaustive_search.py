import logging
import time
from functools import partial
from itertools import starmap, product, chain

import jgrapht
import numpy as np
import networkx as nx
import igraph
from tqdm import tqdm

from risk_engine.graph import RiskGraph


def calculate_all_execution_paths(sg: RiskGraph):
    roots = [str(v) for v, d in sg.in_degree() if d == 0]
    leaves = [str(v) for v, d in sg.out_degree() if d == 0]
    logging.info('Calculating all paths for %s roots and %s leaves', len(roots), len(leaves))

    g = igraph.Graph(directed=True)
    g.add_vertices(map(str, sg.nodes))
    g.add_edges([(str(u), str(v)) for (u, v) in sg.edges])
    all_igraph_paths = []
    for root in tqdm(roots):
        all_igraph_paths += [[int(g.vs[n]['name']) for n in path] for path in g.get_all_simple_paths(root, leaves)]
    return all_igraph_paths


def _construct_matrices(graph: RiskGraph, all_paths, vulnerability_score_function=None):
    """
    Constructs the matrices used in exhaustive risk calculations.
    This method ensures the correct indices of vulnerabilities, nodes are used across all matrices.
    :param graph: A risk graph
    :param all_paths: All execution paths in the supplied graph
    :return: (vulnerabilities (v), vulnerability_scores_per_node (v*n), path_matrix (n*p), base_vulnerability_mask (v*v*v))
    """
    if vulnerability_score_function is None:
        vulnerability_score_function = lambda node, vuln: graph.get_impact_scores_for(node).get(vuln, 0.0)
    node_list = list(graph)
    vulnerabilities = np.array(list(graph.get_vulnerabilities()))
    no_vulns = vulnerabilities.shape[0]

    path_matrix = np.array([[1 if node in path else 0 for node in node_list] for path in all_paths]).T

    vulnerability_scores_per_node_matrix = np.array([
        [vulnerability_score_function(node, vuln) for node in node_list] for vuln in vulnerabilities
    ])

    base_vulnerability_mask = np.zeros((no_vulns, no_vulns, no_vulns))
    idx = np.arange(no_vulns)
    base_vulnerability_mask[:, idx, idx] = 1.0
    base_vulnerability_mask[idx, idx, :] = 0.0

    return vulnerabilities, vulnerability_scores_per_node_matrix, path_matrix, base_vulnerability_mask


def _calculate_risks(vulnerability_scores_nodes, path_matrix):
    vuln_to_remove, vulnerabilities, nodes = vulnerability_scores_nodes.shape
    assert nodes == path_matrix.shape[0], 'Something is wrong with your matrices.'
    logging.debug('Calculating risks')
    logging.debug('Considering {} vulnerabilities'.format(vuln_to_remove))
    logging.debug('Vulnerability matrix\n' + vulnerability_scores_nodes.__repr__())

    return (vulnerability_scores_nodes.max(axis=1) @ path_matrix).max(axis=1)


def _remove_vulnerability(remove_index, vulnerabilities, mask, vulnerability_scores_nodes):
    removed_vulnerability = vulnerabilities[remove_index]
    vulnerability_scores_nodes = mask[remove_index, :, :] @ vulnerability_scores_nodes
    mask = np.delete(mask, remove_index, 0)
    vulnerabilities = np.delete(vulnerabilities, remove_index, 0)
    return removed_vulnerability, vulnerabilities, mask, vulnerability_scores_nodes


def hong_exhaustive_search(graph: RiskGraph, all_paths=None, vulnerability_score_function=None):
    logging.info('nodes: %s', len(graph))
    logging.info('edges: %s', len(graph.edges))
    logging.info('vulnerabilities: %s', len(graph.get_vulnerabilities()))
    if all_paths is None:
        all_paths = calculate_all_execution_paths(graph)
    logging.info('paths: %s', len(all_paths))

    vulnerabilities, vulnerability_scores_per_node_matrix, path_matrix, vulnerability_mask = _construct_matrices(
        graph, all_paths, vulnerability_score_function
    )
    current_risk = _calculate_risks(np.array([vulnerability_scores_per_node_matrix]), path_matrix)[0]
    risk_list = [current_risk]
    fix_list = []
    while current_risk > 0:
        logging.info('Start loop with %s vulnerabilities left', vulnerabilities.shape[0])
        logging.debug(vulnerabilities)
        start = time.perf_counter()
        risk_layers = np.stack([vulnerability_scores_per_node_matrix] * vulnerabilities.shape[0])
        system_risks_per_missing_vulnerability = _calculate_risks(vulnerability_mask @ risk_layers, path_matrix)

        fix_vulnerability, vulnerabilities, vulnerability_mask, vulnerability_scores_per_node_matrix = _remove_vulnerability(
            system_risks_per_missing_vulnerability.argmin(), vulnerabilities, vulnerability_mask, vulnerability_scores_per_node_matrix)
        current_risk = system_risks_per_missing_vulnerability.min()
        fix_list.append(fix_vulnerability)
        risk_list.append(current_risk)
        logging.info('Looptime %s', time.perf_counter()-start)
    return fix_list, risk_list


if __name__ == '__main__':
    G = RiskGraph()
    G.add_node(1)
    G.add_node(2)
    G.add_node(3)
    G.add_node(6)
    G.add_edges_from([(1, 2), (1, 3), (1, 6), (3, 6)])
    G.add_vulnerability(2, 5.0, 'v1')
    G.add_vulnerability(6, 5.0, 'v1')
    G.add_vulnerability(3, 7.0, 'v2')
    G.add_vulnerability(6, 4.0, 'v3')
    G.add_vulnerability(3, 4.0, 'v3')
    logging.basicConfig(level=logging.INFO, format='[%(asctime)s][%(levelname)s] %(message)s', datefmt='%m-%d %H:%M')

    print(hong_exhaustive_search(G, vulnerability_score_function=lambda node, vuln: G.get_severity_scores_for(node).get(vuln, 0.0)))
