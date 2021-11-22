import os.path
from datetime import datetime

import pandas as pd
from rbo import rbo

import config
from analysis.sampling import calculate_all_execution_paths, sort_dict, calculate_risk_from_tuples, proportional_risk, \
    hong_exhaustive_search, hong_risk
from risk_engine.graph import RiskGraph, parse_JSON_file
from utils.graph_sampling import ff_sample_subgraph

# FILE = os.path.join(config.BASE_DIR, 'repos', 'com.genersoft.wvp-1.5.10.RELEASE-reduced.json')
FILE = os.path.join(config.BASE_DIR, 'repos', 'net.optionfactory.hibernate-json-3.0-SNAPSHOT-reduced.json')

graph = RiskGraph.create(*parse_JSON_file(FILE), auto_update=False)
nodeset = set(graph.get_vulnerable_nodes().keys())

list_of_lists = []
for n in range(10, 60, 10):
    print(n)
    subgraph = ff_sample_subgraph(graph, nodeset, min(n, len(graph.nodes)))
    nodeset = nodeset.union(set(subgraph.nodes.keys()))

    start = datetime.now()
    all_execution_paths = calculate_all_execution_paths(subgraph)

    exhaustive_stop = datetime.now()

    subgraph.configure_for_model('d')
    betweenness_risks = {node: subgraph.get_inherent_risk_for(node) for node in subgraph.nodes.keys()}
    model_stop = datetime.now()
    hong_risks = hong_risk(subgraph)
    hong_stop = datetime.now()

    exhausive_risk_psv, _ = hong_exhaustive_search(subgraph, all_execution_paths)
    hong_risk_psv = list(sort_dict(calculate_risk_from_tuples(hong_risks, 1)).keys())
    model_risk_psv = list(proportional_risk(subgraph, betweenness_risks).keys())

    hong_rbo = rbo.RankingSimilarity(exhausive_risk_psv, hong_risk_psv).rbo()
    model_rbo = rbo.RankingSimilarity(exhausive_risk_psv, model_risk_psv).rbo()

    list_of_lists.append([
        n,
        hong_rbo,
        model_rbo,
        exhausive_risk_psv,
        hong_risk_psv,
        model_risk_psv,
        (exhaustive_stop-start).seconds,
        (hong_stop-model_stop).seconds,
        (model_stop-exhaustive_stop).seconds
    ])

df = pd.DataFrame(list_of_lists, columns=['subgraph_size', 'hong_rbo', 'model_rbo', 'exhaustive_psv', 'hong_psv', 'model_psv', 'exhaustive_search_time', 'hong_time', 'model_time'])
df.to_csv('runtime_analysis.csv', index=False)

print(df)
