import networkx as nx
import matplotlib.pyplot as plt
import random

from networkx import Graph, DiGraph
from networkx.drawing.nx_pydot import graphviz_layout

from v2_benchmarked.util.core import get_method_name_from
from v2_benchmarked.util.graph_factory import sub_graph_from_node_set


def breadth_first_traversal(graph: Graph, source, no_nodes=20):
    visited = {source}
    queue = [source]
    while queue:
        v = queue.pop()
        for neighbor in graph.neighbors(v):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)

            if len(visited) == no_nodes:
                return visited
    return visited


def bfs_sample_subgraph(graph: DiGraph, source):
    return sub_graph_from_node_set(graph, breadth_first_traversal(graph, source))


def forest_fire_traversal(graph: DiGraph, size):
    list_nodes = list(graph.nodes())

    random_node = random.sample(set(list_nodes), 1)[0]
    visited = {random_node}
    queue = [random_node]
    while len(visited) < size:
        if queue:
            v = queue.pop()
            if v not in visited:
                visited.add(v)
                neighbors = list(graph.neighbors(v))
                if neighbors:
                    np = random.randint(1, len(neighbors))
                    [queue.append(selected_neighbor) for selected_neighbor in neighbors[:np]]
        else:
            # random_node = random.sample(set(list_nodes) and visited, 1)[0]
            random_node = random.sample(set(list_nodes), 1)[0]
            queue.append(random_node)
    queue.clear()
    return visited


def ff_sample_subgraph(graph: DiGraph, size):
    node_set = forest_fire_traversal(graph, size)
    print(node_set)
    return sub_graph_from_node_set(graph, node_set)


def subsample_graphs(graph, no_sub_samples=20):
    # print(nodes)
    sub_graph_count = 0
    while sub_graph_count < no_sub_samples:
        # random_source = random.choice(list(graph.nodes.keys()))
        # sub_graph_nodes = breadth_first_traversal(graph, random_source)
        # if len(sub_graph_nodes) < 20:
        #     continue
        sub_graph = ff_sample_subgraph(graph, 20)
        labels = {note_id: get_method_name_from(attributes['uri']) for note_id, attributes in sub_graph.nodes.items()}
        pos = graphviz_layout(sub_graph, prog='twopi')
        # nx.draw_kamada_kawai(sub_graph, labels=labels)
        nx.draw(sub_graph, pos=pos, labels=labels)
        plt.text(0, 0, 'ForestFireSampling')
        plt.show()
        sub_graph_count += 1
