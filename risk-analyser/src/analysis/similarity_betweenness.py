import difflib
import glob
import operator
import os
import re

import pandas as pd 
import config
from risk_engine.exhaustive_search import calculate_all_execution_paths
from risk_engine.graph import RiskGraph, parse_JSON_file
from utils.graph_sampling import ff_sample_subgraph
import networkx as nx

from itertools import chain, product, starmap
from functools import partial
from copy import deepcopy
import heapq

from datetime import datetime

import signal
from scipy.stats import spearmanr
import numpy as np

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
    'org.testingisdocumenting.webtau.webtau-core-1.22-SNAPSHOT-reduced.json',
    'net.optionfactory.hibernate-json-3.0-SNAPSHOT-reduced.json',
    'com.genersoft.wvp-1.5.10.RELEASE-reduced.json',
    # 'com.flipkart.zjsonpatch.zjsonpatch-0.4.10-SNAPSHOT-reduced.json',
    # 'org.mandas.docker-client-2.0.0-SNAPSHOT-reduced.json',
]


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



def calculate_correlations(g, name, n=100):
    all_execution_paths = None
    for retry in range(3):
        try:
            print('[{}] Processing (attempt {}): {}'.format(datetime.now(), retry, name))
            with timeout(seconds=10):
                subgraph = ff_sample_subgraph(g, g.get_vulnerable_nodes().keys(),
                                              min(n, len(g.nodes)))  # math.floor(len(graph) * 0.15))
                all_execution_paths = calculate_all_execution_paths(subgraph)
            break
        except TimeoutError:
            pass
    if all_execution_paths is None:
        return ((0, 0), (0, 0))
    exhaustive_centralities = np.fromiter(exhaustive_centrality(subgraph, all_execution_paths).values(), dtype=float)
    betweenness_centralities = np.fromiter(
        nx.algorithms.centrality.betweenness_centrality(subgraph, endpoints=True).values(), dtype=float)
    coreachability_centrality = np.fromiter(
        {node_id: len(nx.algorithms.dag.ancestors(subgraph, node_id)) for node_id in subgraph.nodes.keys()}.values(),
        dtype=float)
    return (spearmanr(betweenness_centralities, exhaustive_centralities), spearmanr(coreachability_centrality, exhaustive_centralities))



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
        vulnerability_density = len(graph.get_vulnerable_nodes()) / len(graph)

        (correlation_between, p_value_between), (correlation_co, p_value_co) = calculate_correlations(graph, name)
        retries = 0
        while retries < 5 and (correlation_between < 0 or correlation_co < 0):
            (correlation_between, p_value_between), (correlation_co, p_value_co) = calculate_correlations(graph, name)
            retries += 1

        shortname = re.split(r'([a-zA-Z\-]+)-[0-9\.a-zA-Z\-]+(?=-reduced\.json)', name)[1]
        list_of_lists.append(
            [name, shortname, vulnerability_density, correlation_between, p_value_between, correlation_co, p_value_co])

    df = pd.DataFrame(list_of_lists, columns=['name', 'shortname', 'vulnerability_density', 'correlation_betweenness',
                                              'p_value_betweenness', 'correlation_coreachability',
                                              'p_value_coreachability'])
    df.to_csv('correlation.csv', index=False)


if __name__ == '__main__':
    main()
