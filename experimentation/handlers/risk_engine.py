from math import prod
from networkx import Graph, nx
from handlers.handler import Handler


class RiskEngine(Handler):
    def __init__(self, start_node=1):
        self.start_node = start_node

    @staticmethod
    def _edges_in_paths_from_to(call_graph: Graph, source, sink):
        return map(nx.utils.pairwise, nx.all_simple_paths(call_graph, source=source, target=sink))

    @staticmethod
    def _cascaded_risk_of_path(call_graph: Graph, severity, path):
        impacts = nx.get_edge_attributes(call_graph, 'impact')
        # Impact in this scenario refers to the impact such as described in the FASTEN deliverable.
        return severity * prod([impacts[edge] for edge in path])

    def _cumulative_dependency_risk(self, call_graph: Graph, vulnerable_method, severity, application):
        return sum([
            self._cascaded_risk_of_path(call_graph, severity, path) for path in self._edges_in_paths_from_to(
                call_graph,
                application,
                vulnerable_method
            )
        ])

    def _combined_cumulative_dependency_risk(self, call_graph: Graph, severities):
        return sum([
            self._cumulative_dependency_risk(
                call_graph,
                vulnerable_method,
                severity,
                self.start_node
            ) for vulnerable_method, severity in severities.items()
        ])

    def process(self, handler_input: Graph) -> float:
        return self._combined_cumulative_dependency_risk(
            handler_input,
            nx.get_node_attributes(handler_input, 'severity')
        )

