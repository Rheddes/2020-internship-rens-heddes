from handlers.construct_graph import ConstructGraph
from handlers.file_input import FileInput
from handlers.graph_pre_processing import GraphPreProcessing
from handlers.risk_engine import RiskEngine
from pipeline import Pipeline


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    pipeline = Pipeline([
        FileInput(),
        GraphPreProcessing(),
        ConstructGraph(),
        RiskEngine(),
    ])
    print('Total risk for application: {}'.format(pipeline.process('data/example-graph.json')))
    # with open('example-graph.json', 'w') as file:
    #     file.write(json.dumps(nx.node_link_data(call_graph)))
