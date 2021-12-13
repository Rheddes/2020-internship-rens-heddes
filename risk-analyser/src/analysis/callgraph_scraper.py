import glob
import pandas as pd
import numpy as np
import os

from risk_engine.graph import parse_JSON_file, RiskGraph
from src import config


def basic_stats(dataframe):
    print(dataframe.describe())


def find_shortest_vulnerable_path(cg: RiskGraph):
    visited = set(cg.get_vulnerable_nodes().keys())
    queue = [[source] for source in visited]
    while queue:
        current_path = queue.pop()
        current_node = current_path[-1]
        if cg.nodes[current_node]['metadata'].get('application_node', False):
            return current_path
        for neighbor in cg.predecessors(current_node):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(current_path + [neighbor])
    return []


if __name__ == '__main__':
    list_of_lists = []
    graphs = dict()
    for call_graph in glob.glob(os.path.join(config.BASE_DIR, 'repos', '**', '*-reduced.json'), recursive=True):
        name = call_graph.split('/')[-1]
        nodes, edges, vulnerable, frame, vulnerabilities = parse_JSON_file(call_graph)
        graph = RiskGraph.create(nodes, edges, vulnerable, frame, auto_update=False)
        no_nodes = len(nodes)
        no_edges = len(edges)
        no_vulnerable = len(vulnerable)
        no_packages = frame.uri.str.extract('fasten://(?P<ecosystem>.+)!(?P<package>[a-zA-Z_\-.:]+)\$(?P<version>[0-9.a-zA-Z\-_]+)\/.*').package.nunique()
        no_vulnerabilities = len(vulnerabilities)
        shortest_vulnerable_path = len(find_shortest_vulnerable_path(graph))
        list_of_lists.append([name, no_nodes, no_edges, no_vulnerable, shortest_vulnerable_path, no_packages, no_vulnerabilities])
        graphs[name] = graph

    df = pd.DataFrame(list_of_lists, columns=['callgraph', 'nodes', 'edges', 'vulnerable', 'shortest_vulnerable_path', 'dependencies', 'vulnerabilities'])
    df['vulnerable_ratio'] = df.eval('vulnerable/nodes').fillna(0).replace({np.inf: 0})
    print(df)
    basic_stats(df)
    df.to_csv(os.path.join(config.BASE_DIR, 'out', 'call_graph_stats.csv'))


