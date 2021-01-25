import networkx as nx
import matplotlib.pyplot as plt
import constants
from v2_benchmarked.util.json_parser import JSONParser
import jgrapht

from v2_benchmarked.util.risk_engine import VulnerabilityRiskEngine

if __name__ == '__main__':
    [classes, nodes, edges] = JSONParser().parseCGOpalGraph(constants.BASE_DIR + '/data/call-graph-with-metadata.json')
    g = jgrapht.create_graph(directed=True, weighted=True, allowing_self_loops=True, allowing_multiple_edges=True, any_hashable=True)
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
    entrypoint_id = 18 # FIXME hardcoded
    print(is_connected)
    app_graph = next(cover for cover in covers if entrypoint_id in cover)
    print(app_graph)
    print(risk_engine.calculate_risk(g.vertices, g))
    print(risk_engine.calculate_risk(app_graph, g))
    # with open('output/graph.json', 'w') as text_file:
    #     text_file.write(jgrapht.io.exporters.generate_json(g))

    nxg = jgrapht.convert.to_nx(g)
    pos = nx.spring_layout(nxg, seed=2342)  # Seed layout for reproducibility
    nx.draw(nxg, pos=pos, with_labels=True)
    plt.show()
