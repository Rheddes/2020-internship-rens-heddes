import networkx as nx
import matplotlib.pyplot as plt
import constants
from v2_benchmarked.util.json_parser import JSONParser
import jgrapht
import re

from v2_benchmarked.util.risk_engine import VulnerabilityRiskEngine

if __name__ == '__main__':
    [classes, nodes, edges] = JSONParser().parseCGOpalGraph(constants.BASE_DIR + '/data/call-graph-with-metadata.json')
    g = jgrapht.create_graph(directed=True, weighted=True, allowing_self_loops=False, allowing_multiple_edges=False, any_hashable=True)
    for node_id, node in nodes.items():
        g.add_vertex(node_id)
        g.vertex_attrs[node_id] = node
    g.add_edges_from(edges)

    risk_engine = VulnerabilityRiskEngine({
        'low': constants.CVSS_RISK_LOW_RANGE,
        'moderate': constants.CVSS_RISK_MODERATE_RANGE,
        'high': constants.CVSS_RISK_HIGH_RANGE,
        'very high': constants.CVSS_RISK_VERY_HIGH_RANGE,
    })
    (is_connected, covers) = jgrapht.algorithms.connectivity.is_weakly_connected(g)
    entrypoint_id = 1  # FIXME hardcoded
    print(is_connected)
    app_graph = next(cover for cover in covers if entrypoint_id in cover)
    print(app_graph)
    print(risk_engine.calculate_risk(g.vertices, g))
    print(risk_engine.calculate_risk(app_graph, g))
    # with open('output/graph.json', 'w') as text_file:
    #     text_file.write(jgrapht.io.exporters.generate_json(g))

    nxg = jgrapht.convert.to_nx(g)
    risk_engine_weighted = VulnerabilityRiskEngine({
        'low': constants.CVSS_RISK_LOW_RANGE,
        'moderate': constants.CVSS_RISK_MODERATE_RANGE,
        'high': constants.CVSS_RISK_HIGH_RANGE,
        'very high': constants.CVSS_RISK_VERY_HIGH_RANGE,
    }, lambda callable_id: nx.algorithms.centrality.betweenness_centrality(nxg)[callable_id])
    print(risk_engine_weighted.calculate_risk(g.vertices, g))
    print(risk_engine_weighted.calculate_risk(app_graph, g))

    def get_method_name_from(uri):
        return re.search(r'\/[a-zA-Z0-9_.]+\/[a-zA-Z0-9_]+\.([a-zA-Z0-9_%]+)\(', uri).group(1)


    labels = {note_id:  get_method_name_from(attributes['uri']) for note_id, attributes in nxg.nodes.items()}

    # pos = nx.spectral_layout(nxg)
    # nx.draw(nxg.reverse(), pos=pos, with_labels=True, labels=labels, font_size=6)
    # plt.show()

    print(labels)

    print('------- Centralities --------')
    print(nx.algorithms.centrality.betweenness_centrality(nxg))
    print(nx.algorithms.centrality.betweenness_centrality(nxg.reverse()))
    print(nx.algorithms.centrality.closeness_centrality(nxg))
    print(nx.algorithms.centrality.closeness_centrality(nxg.reverse()))
    print(nx.algorithms.centrality.load_centrality(nxg))
    print(nx.algorithms.centrality.load_centrality(nxg.reverse()))
    print('------- End Centralities --------')

    total = 0
    for node in nxg.nodes.keys():
        local_centrality = nx.algorithms.centrality.local_reaching_centrality(nxg.reverse(), node)
        print('Node: {} ---- {}'.format(node, local_centrality))
        total += local_centrality

    print(total)

