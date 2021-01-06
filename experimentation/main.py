from handlers.construct_graph import ConstructGraph
from handlers.file_input import FileInput
from handlers.graph_pre_processing import GraphPreProcessing
from handlers.risk_engine import RiskEngine
from pipeline import Pipeline
from util.json_parser import JSONParser
import jgrapht


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    # pipeline = Pipeline([
    #     FileInput(),
    #     GraphPreProcessing(),
    #     ConstructGraph(),
    #     RiskEngine(),
    # ])
    # print('Total risk for application: {}'.format(pipeline.process('data/example-graph.json')))
    # with open('example-graph.json', 'w') as file:
    #     file.write(json.dumps(nx.node_link_data(call_graph)))
    #
    # g = jgrapht.create_graph(directed=True, weighted=True, allowing_self_loops=False, allowing_multiple_edges=True)
    # g.add_vertex(0)
    # g.add_vertex(1)
    # g.add_edge(0, 1)
    # for e in g.edges:
    #     print('Edge {}'.format(g.edge_tuple(e)))

    JSONParser().parseJSONFile('data/hello-world-graph.json')
