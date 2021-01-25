from constants import BASE_DIR
from v1.handlers.construct_graph import ConstructGraph
from v1.handlers.file_input import FileInput
from v1.handlers.graph_pre_processing import GraphPreProcessing
from v1.handlers.risk_engine import RiskEngine
from v1.pipeline import Pipeline

if __name__ == '__main__':
    pipeline = Pipeline([
        FileInput(),
        GraphPreProcessing(),
        ConstructGraph(),
        RiskEngine(),
    ])
    print('Total risk for application: {}'.format(pipeline.process(BASE_DIR + '/data/example-graph.json')))
    # with open('example-graph.json', 'w') as file:
    #     file.write(json.dumps(nx.node_link_data(call_graph)))
