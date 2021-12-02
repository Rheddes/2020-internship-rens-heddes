import difflib
import glob
import operator
import os
import re

import logging
import pandas as pd 
import config
from risk_engine.exhaustive_search import calculate_all_execution_paths
from risk_engine.graph import RiskGraph, parse_JSON_file
from utils.graph_sampling import ff_sample_subgraph
import networkx as nx


from datetime import datetime

from scipy.stats import spearmanr
import numpy as np

from utils.timelimit import run_with_limited_time

callgraphs = [
    'org.testingisdocumenting.webtau.webtau-core-1.22-SNAPSHOT-reduced.json',
    'net.optionfactory.hibernate-json-3.0-SNAPSHOT-reduced.json',
    'com.genersoft.wvp-1.5.10.RELEASE-reduced.json',
    # 'com.flipkart.zjsonpatch.zjsonpatch-0.4.10-SNAPSHOT-reduced.json',
    # 'org.mandas.docker-client-2.0.0-SNAPSHOT-reduced.json',
]

logging.basicConfig(level=logging.INFO, format='[%(asctime)s][%(levelname)s] %(message)s', datefmt='%m-%d %H:%M')


def exhaustive_centrality(graph: RiskGraph, all_paths=None):
    if all_paths is None:
        all_paths = calculate_all_execution_paths(graph)

    exhaustive_centrality = {key: 0.0 for key in graph.nodes.keys()}
    for path in all_paths:
        for node in path:
            exhaustive_centrality[node] += 1
    max_value = max(exhaustive_centrality.values(), default=0)
    if max_value > 0:
        exhaustive_centrality = {key: value/max_value for key, value in exhaustive_centrality.items()}
    return exhaustive_centrality


def calculate_centralities(subgraph: RiskGraph, all_paths=None):
    exhaustive = exhaustive_centrality(subgraph, all_paths)
    betweenness = nx.algorithms.centrality.betweenness_centrality(subgraph, endpoints=True)
    coreachability = {node_id: len(nx.algorithms.dag.ancestors(subgraph, node_id)) for node_id in subgraph.nodes.keys()}

    return {node: (exhaustive[node], betweenness[node], coreachability[node]) for node in subgraph}


def compose(g, f):
    def h(x):
        return g(f(x))
    return h


def calculate_correlations(g, name, n=100):
    all_execution_paths = None
    for retry in range(3):
        try:
            print('[{}] Processing (attempt {}): {}'.format(datetime.now(), retry, name))
            subgraph = ff_sample_subgraph(g, g.get_vulnerable_nodes().keys(), min(n, len(g.nodes)))
            all_execution_paths = run_with_limited_time(calculate_all_execution_paths, (subgraph, ), {'only_attack_paths': False}, timeout=20, throws=True)[0]
            break
        except TimeoutError:
            pass
    if all_execution_paths is None:
        return (0, 0), (0, 0)

    centralities = calculate_centralities(subgraph, all_execution_paths)
    exhaustive, betweenness, coreachability = map(compose(np.array, list), zip(*centralities.values()))
    return (spearmanr(betweenness, exhaustive), spearmanr(coreachability, exhaustive))


def main():
    list_of_lists = []
    for file in glob.glob(os.path.join(config.BASE_DIR, 'reduced_callgraphs', '**', '*-reduced.json'), recursive=True):
        # for file in [os.path.join(config.BASE_DIR, 'repos', callgraph) for callgraph in callgraphs]:
        name = file.split('/')[-1]
        if name == 'pl.edu.icm.unity.unity-server-parent-3.3.0-SNAPSHOT-reduced.json' or name == 'cn.vertxup.vertx-gaia-0.5.3-SNAPSHOT-reduced.json':
            continue
        print('[{}] Reading: {}'.format(datetime.now(), name))
        graph = RiskGraph.create(*parse_JSON_file(file), auto_update=False)
        if not len(graph.get_vulnerable_nodes()):
            print('[{}] Skipping: {}'.format(datetime.now(), name))
            continue

        (correlation_between, p_value_between), (correlation_co, p_value_co) = calculate_correlations(graph, name)
        retries = 0
        while retries < 50 and (correlation_between < 0 or correlation_co < 0):
            (correlation_between, p_value_between), (correlation_co, p_value_co) = calculate_correlations(graph, name)
            retries += 1

        vulnerability_density = len(graph.get_vulnerable_nodes()) / len(graph)
        shortname = re.split(r'([a-zA-Z\-]+)-[0-9\.a-zA-Z\-]+(?=-reduced\.json)', name)[1]
        list_of_lists.append(
            [name, shortname, vulnerability_density, correlation_between, p_value_between, correlation_co, p_value_co])

    df = pd.DataFrame(list_of_lists, columns=['name', 'shortname', 'vulnerability_density', 'correlation_betweenness',
                                              'p_value_betweenness', 'correlation_coreachability',
                                              'p_value_coreachability'])
    df.to_csv('correlation.csv', index=False)


if __name__ == '__main__':
    main()
