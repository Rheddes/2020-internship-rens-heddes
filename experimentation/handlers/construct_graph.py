import networkx as nx
from handlers.handler import Handler


class ConstructGraph(Handler):
    def process(self, handler_input):
        return nx.node_link_graph(handler_input)
