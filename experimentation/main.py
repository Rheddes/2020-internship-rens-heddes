import networkx as nx
import matplotlib.pyplot as plt


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


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    G = make_graph()
    impacts = nx.get_edge_attributes(G, 'impact')
    severities = nx.get_node_attributes(G, 'severity')
    combined_risk = 0
    for vulnerable_method in severities.keys():
        print(vulnerable_method)
        cumulative_dependency_risk = 0
        for path in map(nx.utils.pairwise, nx.all_simple_paths(G, source='App', target=vulnerable_method)):
            cascaded_risk = severities[vulnerable_method]
            for edge in path:
                cascaded_risk *= impacts[edge]
            cumulative_dependency_risk += cascaded_risk
        print('Cumulative isk for method: {}, is {}'.format(vulnerable_method, cumulative_dependency_risk))
        combined_risk += cumulative_dependency_risk
    print('Total risk for application: {}'.format(combined_risk))
