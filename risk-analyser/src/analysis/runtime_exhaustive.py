import logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s][%(levelname)s] %(message)s', datefmt='%m-%d %H:%M')

import os.path
from datetime import datetime
import time

import pandas as pd
from rbo import rbo

import config
from analysis.sampling import hong_risk, sort_dict, calculate_risk_from_tuples, proportional_risk
from risk_engine.exhaustive_search import calculate_all_execution_paths, hong_exhaustive_search
from risk_engine.graph import RiskGraph, parse_JSON_file
from utils.graph_sampling import ff_sample_subgraph

FILE = os.path.join(config.BASE_DIR, 'repos', 'com.genersoft.wvp-1.5.10.RELEASE-reduced.json')
# FILE = os.path.join(config.BASE_DIR, 'repos', 'net.optionfactory.hibernate-json-3.0-SNAPSHOT-reduced.json')
# FILE = os.path.join(config.BASE_DIR, 'repos', 'com.flipkart.zjsonpatch.zjsonpatch-0.4.10-SNAPSHOT-reduced.json')
# FILE = os.path.join(config.BASE_DIR, 'reduced_callgraphs', 'net.optionfactory.hibernate-json-3.0-SNAPSHOT-reduced.json')
FILE = os.path.join(config.BASE_DIR, 'reduced_callgraphs', 'com.genersoft.wvp-1.5.10.RELEASE-reduced.json')

graph = RiskGraph.create(*parse_JSON_file(FILE), auto_update=False)
nodeset = set(graph.get_vulnerable_nodes().keys())

list_of_lists = []
for n in range(80, 210, 10):
    logging.info('Using subgraph of size: {}'.format(n))
    start = time.perf_counter()
    subgraph = ff_sample_subgraph(graph, nodeset, min(n, len(graph.nodes)))
    subgraph_stop = time.perf_counter()
    nodeset = nodeset.union(set(subgraph.nodes.keys()))
    union_stop = time.perf_counter()

    all_execution_paths = calculate_all_execution_paths(subgraph)
    all_paths_stop = time.perf_counter()
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
        subgraph_stop-start,
        union_stop-subgraph_stop,
        all_paths_stop-union_stop,
        exhaustive_stop-all_paths_stop,
        hong_stop-exhaustive_stop,
        model_stop-hong_stop,
        finish_stop-model_stop,
    ]
    print(record)
    list_of_lists.append(record)

df = pd.DataFrame(list_of_lists, columns=['subgraph_size', 'hong_rbo', 'model_rbo', 'exhaustive_psv', 'hong_psv', 'model_psv', 'subgraph_time', 'union_time', 'all_paths_time', 'exhaustive_time', 'hong_time', 'model_time', 'score_time'])
df.to_csv('runtime_analysis.csv', index=False)
print(nodeset)

print(df)
