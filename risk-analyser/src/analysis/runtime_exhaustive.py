import logging
import os.path
import config

import time

import networkx as nx
import pandas as pd
from rbo import rbo
from func_timeout import FunctionTimedOut

logging.basicConfig(filename=os.path.join(config.BASE_DIR, 'logs', 'exhaustive.log'), level=logging.INFO, format='[%(asctime)s][%(levelname)s] %(message)s', datefmt='%m-%d %H:%M')
# logging.basicConfig(level=logging.INFO, format='[%(asctime)s][%(levelname)s] %(message)s', datefmt='%m-%d %H:%M')

from analysis.sampling import hong_risk, sort_dict, calculate_risk_from_tuples, proportional_risk
from risk_engine.exhaustive_search import calculate_all_execution_paths, hong_exhaustive_search
from risk_engine.graph import RiskGraph, parse_JSON_file
from utils.graph_sampling import ff_sample_subgraph

# FILE = os.path.join(config.BASE_DIR, 'repos', 'net.optionfactory.hibernate-json-3.0-SNAPSHOT-reduced.json')
# FILE = os.path.join(config.BASE_DIR, 'repos', 'com.flipkart.zjsonpatch.zjsonpatch-0.4.10-SNAPSHOT-reduced.json')
# FILE = os.path.join(config.BASE_DIR, 'reduced_callgraphs', 'net.optionfactory.hibernate-json-3.0-SNAPSHOT-reduced.json')
FILE = os.path.join(config.BASE_DIR, 'reduced_callgraphs', 'com.genersoft.wvp-1.5.10.RELEASE-reduced.json')

graph = RiskGraph.create(*parse_JSON_file(FILE), auto_update=False)
nodeset = set(graph.get_vulnerable_nodes().keys())


def remove_simple_loops(graph: RiskGraph):
    node_list = list(graph.nodes)
    adj = nx.linalg.adj_matrix(graph, nodelist=node_list)
    for idx_u, u in enumerate(node_list):
        for idx_v, v in enumerate(node_list[idx_u:]):
            if adj[idx_u,idx_u+idx_v] and adj[idx_u+idx_v,idx_u]:
                graph.remove_edge(u, v)
    return graph


def try_all_paths(sg: RiskGraph, node_set, previous_calculation_time):
    g, aep = None, []
    for retry in range(4):
        g = remove_simple_loops(ff_sample_subgraph(sg, node_set, min(n, len(sg.nodes))))
        try:
            aep = calculate_all_execution_paths(g, previous_calculation_time + retry*10)
            break
        except FunctionTimedOut:
            pass

    return g, aep


list_of_lists = []
all_paths_time = 0.0
for n in range(10, 240, 10):
    logging.info('Using subgraph of size: {}'.format(n))
    start = time.perf_counter()

    subgraph, all_execution_paths = try_all_paths(graph, nodeset, all_paths_time)
    nodeset = nodeset.union(set(subgraph.nodes.keys()))
    nx.write_gexf(subgraph, os.path.join(config.BASE_DIR, 'out', 'subgraph.gexf'))
    all_paths_stop = time.perf_counter()
    all_paths_time = all_paths_stop-start
    exhausive_risk_psv, _ = hong_exhaustive_search(subgraph, all_execution_paths)

    exhaustive_stop = time.perf_counter()

    subgraph.configure_for_model('d')

    hong_risks = hong_risk(subgraph)
    hong_risk_psv = list(sort_dict(calculate_risk_from_tuples(hong_risks, 1)).keys())
    hong_stop = time.perf_counter()

    betweenness_risks = {node: subgraph.get_inherent_risk_for(node) for node in subgraph.nodes.keys()}
    model_risk_psv = list(proportional_risk(subgraph, betweenness_risks).keys())

    model_stop = time.perf_counter()

    hong_rbo = rbo.RankingSimilarity(exhausive_risk_psv, hong_risk_psv).rbo()
    model_rbo = rbo.RankingSimilarity(exhausive_risk_psv, model_risk_psv).rbo()

    finish_stop = time.perf_counter()

    record = [
        n,
        hong_rbo,
        model_rbo,
        exhausive_risk_psv,
        hong_risk_psv,
        model_risk_psv,
        all_paths_time,
        exhaustive_stop-all_paths_stop,
        hong_stop-exhaustive_stop,
        model_stop-hong_stop,
        finish_stop-model_stop,
    ]
    print(record)
    list_of_lists.append(record)

df = pd.DataFrame(list_of_lists, columns=['subgraph_size', 'hong_rbo', 'model_rbo', 'exhaustive_psv', 'hong_psv', 'model_psv', 'all_paths_time', 'exhaustive_time', 'hong_time', 'model_time', 'score_time'])
df.to_csv('runtime_analysis.csv', index=False)
print(nodeset)

print(df)
