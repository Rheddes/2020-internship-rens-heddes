import networkx as nx
import matplotlib.pyplot as plt
from math import prod


def make_graph():
    G = nx.DiGraph()
    G.add_node('App')
    G.add_node('MethodA')
    G.add_node('MethodB')
    G.add_node('MethodC')
    G.add_node('VulnerableA', severity=4)
    G.add_node('VulnerableB', severity=7)
    G.add_node('UnconnectedA')
    G.add_node('VulnerableC', severity=7)

    G.add_edge('App', 'MethodA', impact=1)
    G.add_edge('App', 'MethodB', impact=1)
    G.add_edge('App', 'MethodC', impact=1)

    G.add_edge('MethodA', 'VulnerableB', impact=1)
    G.add_edge('MethodB', 'VulnerableB', impact=0.8)
    G.add_edge('MethodC', 'VulnerableB', impact=0.5)

    G.add_edge('MethodB', 'VulnerableA', impact=1)

    G.add_edge('UnconnectedA', 'VulnerableC', impact=1)

    # nx.draw_spring(G, with_labels=True)
    # plt.show()
    return G


def edges_in_paths_from_to(G, source, target):
    return map(nx.utils.pairwise, nx.all_simple_paths(G, source=source, target=target))


def cascaded_risk_of_path(G, severity, path):
    impacts = nx.get_edge_attributes(G, 'impact')
    return severity * prod([impacts[edge] for edge in path])


def cumulative_dependency_risk(G, vulnerable_method, severity, application):
    return sum([
        cascaded_risk_of_path(G, severity, path) for path in edges_in_paths_from_to(G, application, vulnerable_method)
    ])


def combined_cumulative_dependency_risk(G, severities):
    return sum([
        cumulative_dependency_risk(G, vulnerable_method, severity, 'App') for vulnerable_method, severity in severities.items()
    ])


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    call_graph = make_graph()
    print('Total risk for application: {}'.format(combined_cumulative_dependency_risk(
        call_graph,
        nx.get_node_attributes(call_graph, 'severity')
    )))
