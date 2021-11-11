import random
from networkx import Graph
from risk_engine.graph import RiskGraph


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


def bfs_sample_subgraph(graph: RiskGraph, source):
    return graph.sub_graph_from_node_ids(breadth_first_traversal(graph, source))


def forest_fire_traversal(graph: RiskGraph, source, size):
    list_nodes = list(graph.nodes())

    visited = set()
    queue = list(source)
    while len(visited) < size:
        if queue:
            v = queue.pop(0)
            if v not in visited:
                visited.add(v)
                neighbors = list(graph.successors(v)) + list(graph.predecessors(v))
                for neighbor in neighbors:
                    if random.randint(0, 1) < 0.7:
                        queue.append(neighbor)
        else:
            # random_node = random.sample(set(list_nodes) and visited, 1)[0]
            random_node = random.sample(set(list_nodes), 1)[0]
            queue.append(random_node)
    queue.clear()
    return visited


def ff_sample_subgraph(graph: RiskGraph, source_nodes, size):
    node_set = forest_fire_traversal(graph, source_nodes, size)
    return graph.sub_graph_from_node_ids(node_set, auto_update=False)
