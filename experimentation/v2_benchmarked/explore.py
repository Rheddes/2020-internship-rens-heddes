import networkx as nx
from networkx.readwrite import json_graph
import json

import constants
from util.core import get_method_name_from


def read_json_file(filename):
    with open(filename) as f:
        js_graph = json.load(f)
    return json_graph.node_link_graph(js_graph, True, False, attrs={'link': 'edges'})


if __name__ == '__main__':
    graph = read_json_file(constants.BASE_DIR + '/data/project-small.enriched.jgrapht.json')
    for node_id, node in graph.nodes.items():
        graph.nodes[node_id]['label'] = '{} - {}'.format(node_id, get_method_name_from(node['uri']))
    nx.write_gexf(graph, 'example-project-small.gexf')
