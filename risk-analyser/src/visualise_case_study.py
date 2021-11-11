import pickle
import random

import latextable
from mysql.connector import connect

from find_vulnerable_ones import _scan_repo_for_risk
import os
import config
from risk_engine.graph import RiskGraph, parse_JSON_file, _combine_scores
import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import seaborn as sns

from utils.graph_sampling import forest_fire_traversal

if __name__ == '__main__':
    enriched_graph = RiskGraph.create(*parse_JSON_file(os.path.join(config.BASE_DIR, 'repos', 'webtau', 'target', 'callgraphs', 'org.testingisdocumenting.webtau.webtau-cache-1.23-SNAPSHOT-reduced.json')), auto_update=False)
    print(len(enriched_graph.get_vulnerable_nodes().keys()))
    print(len(enriched_graph.nodes.keys()))
    # vulnerable_nodes = list(enriched_graph.get_vulnerable_nodes().keys())

    # Use one static sample
    node_set = {14338, 9091, 4869, 4873, 4683, 4876, 4108, 3022, 8335, 8336, 8337, 8338, 4878, 8349, 3422, 16413, 4126, 2595, 5224, 5225, 2538, 2480, 14321, 14322, 14323, 9140, 2485, 14006, 14007, 9141, 14013, 3198, 14335}
    # Else resample nodes
    if not node_set:
        selected_source_nodes = [3022, 4876]
        sample_size_per_iter = 10
        node_set = set()
        for source_node in selected_source_nodes:
            node_set = node_set.union(forest_fire_traversal(enriched_graph.reverse(), source_node, sample_size_per_iter))
            node_set = node_set.union(forest_fire_traversal(enriched_graph, source_node, sample_size_per_iter))

    sub_graph = enriched_graph.sub_graph_from_node_ids(node_set)
    print(sub_graph.nodes().keys())
    sub_graph.remove_edges_from(nx.selfloop_edges(sub_graph))
    results = {'additional_vulnerable_nodes': [], 'a': [], 'b': [], 'c': [], 'd': []}

    vulnerable_nodes = set(sub_graph.get_vulnerable_nodes().keys())
    unaffected_nodes = node_set-vulnerable_nodes
    for i in range(11):
        if len(vulnerable_nodes)-2 < i:
            new_vulnerable_nodes = set(random.sample(unaffected_nodes, i+2-len(vulnerable_nodes)))
            vulnerable_nodes = vulnerable_nodes.union(new_vulnerable_nodes)
            unaffected_nodes = unaffected_nodes-new_vulnerable_nodes
            for node in new_vulnerable_nodes:
                sub_graph.add_vulnerability(node, 5.8, 'CVE-2021-8888')
        print(vulnerable_nodes)
        results['additional_vulnerable_nodes'].append(i)
        for model in ['a', 'b', 'c', 'd']:
            sub_graph.configure_for_model(model)
            results[model].append(sub_graph.get_app_risk())

    df = pd.DataFrame.from_dict(results)
    fig, (ax1, ax2, ax3, ax4) = plt.subplots(4)
    sns.lineplot(data=df, x='additional_vulnerable_nodes', y='a', ax=ax1)
    sns.lineplot(data=df, x='additional_vulnerable_nodes', y='b', ax=ax2)
    sns.lineplot(data=df, x='additional_vulnerable_nodes', y='c', ax=ax3)
    sns.lineplot(data=df, x='additional_vulnerable_nodes', y='d', ax=ax4)
    plt.xlabel('Additional vulnerable nodes')
    plt.tight_layout()
    plt.show()

    sns.lineplot(data=df, x='additional_vulnerable_nodes', y='a', legend='brief', label='Model A')
    sns.lineplot(data=df, x='additional_vulnerable_nodes', y='b', legend='brief', label='Model B')
    sns.lineplot(data=df, x='additional_vulnerable_nodes', y='c', legend='brief', label='Model C')
    sns.lineplot(data=df, x='additional_vulnerable_nodes', y='d', legend='brief', label='Model D')
    plt.xlabel('Additional vulnerable nodes')
    plt.ylabel('Risk score')
    plt.title('Effect of additional vulnerable nodes\non the application risk score')
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig('plots/additional_vulnerable_nodes.pdf')
    plt.show()

    sub_graph.configure_for_model('d')
    print(sub_graph.get_app_risk())

    coreachability = {node_id: len(nx.algorithms.dag.ancestors(sub_graph, node_id)) for node_id in sub_graph.nodes.keys()}
    betweenness = nx.algorithms.centrality.betweenness_centrality(sub_graph, endpoints=True)

    ## MODEL A
    sub_graph.reset_cache()
    sub_graph.centrality_score_function = lambda x: coreachability[x] / sum(coreachability.values())
    sub_graph.propagation_function = lambda x: sum(x)
    risks = {k: sub_graph.get_inherent_risk_for(k) for k in sub_graph.get_vulnerable_nodes().keys()}
    sub_graph.draw(title='Model A - Risk {:.2f}'.format(sum(list(risks.values()))), legend=True, cvss_table=False, legend_outside=False)
    plt.savefig(os.path.join(config.BASE_DIR, 'src', 'plots', 'model-a.pdf'))
    plt.show()

    ## MODEL B
    sub_graph.reset_cache()
    sub_graph.centrality_score_function = lambda x: coreachability[x] / max(coreachability.values())
    sub_graph.propagation_function = _combine_scores
    risks = {k: sub_graph.get_inherent_risk_for(k) for k in sub_graph.get_vulnerable_nodes().keys()}
    sub_graph.draw(title='Model B - Risk {:.2f}'.format(_combine_scores(list(risks.values()))), legend=True, cvss_table=False, legend_outside=False)
    plt.savefig(os.path.join(config.BASE_DIR, 'src', 'plots', 'model-b.pdf'))
    plt.show()

    ## MODEL C
    sub_graph.reset_cache()
    sub_graph.centrality_score_function = lambda x: betweenness[x] / sum(betweenness.values())
    sub_graph.propagation_function = lambda x: sum(x)
    risks = {k: sub_graph.get_inherent_risk_for(k) for k in sub_graph.get_vulnerable_nodes().keys()}
    sub_graph.draw(title='Model C - Risk {:.2f}'.format(sum(list(risks.values()))), legend=True, cvss_table=False, legend_outside=False)
    plt.savefig(os.path.join(config.BASE_DIR, 'src', 'plots', 'model-c.pdf'))
    plt.show()

    ## MODEL D
    sub_graph.reset_cache()
    sub_graph.centrality_score_function = lambda x: betweenness[x] / max(betweenness.values())
    sub_graph.propagation_function = _combine_scores
    risks = {k: sub_graph.get_inherent_risk_for(k) for k in sub_graph.get_vulnerable_nodes().keys()}
    sub_graph.draw(title='Model D - Risk {:.2f}'.format(_combine_scores(list(risks.values()))), legend=True, cvss_table=False, legend_outside=False)
    plt.savefig(os.path.join(config.BASE_DIR, 'src', 'plots', 'model-d.pdf'))
    plt.show()

    with open('output/webtau.tex', 'w') as f:
        f.write(latextable.draw_latex(sub_graph.to_table(), caption='Methods and associated CVSS scores'))

