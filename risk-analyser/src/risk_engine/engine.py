import os
from pathlib import Path

import networkx as nx

import config
from config import BASE_DIR
from utils.graph import parse_JSON_file, create_graphs, EnrichedCallGraph


def _weighted_sum(vulnerable_nodes: dict, use_cvss_v3 = True) -> dict:
    occurrences = {}
    for vulnerable_node in vulnerable_nodes.values():
        for vulnerability in vulnerable_node.keys():
            if vulnerability not in occurrences:
                occurrences[vulnerability] = 0
            occurrences[vulnerability] += 1

    weighted_sums = {}
    for node_id, vulnerabilities in vulnerable_nodes.items():
        sum = 0
        weights = 0
        for cve, vulnerability in vulnerabilities.items():
            if use_cvss_v3 and 'scoreCVSS3' in vulnerability:
                sum += occurrences[cve] * (vulnerability['scoreCVSS3'])
                weights += occurrences[cve]
        weighted_sums[node_id] = sum/weights
    return weighted_sums


class RiskEngine:
    def __init__(self, merged_graph_path):
        self.merged_graph_path = merged_graph_path

    def _risk_scores_for_metrics(self, graph: EnrichedCallGraph):
        # scores_for_centrality = {node_id: len(nx.algorithms.dag.ancestors(graph, node_id))/len(graph.nodes.keys()) for node_id in graph.nodes.keys()}
        scores_for_centrality = nx.algorithms.centrality.closeness_centrality(graph)
        sum_scores = sum(scores_for_centrality.values())
        intrinsic_risk_scores = {node_id: (score * max(graph.get_severity_scores_for(node_id)) / sum_scores) for
                                 node_id, score in scores_for_centrality.items()}
        # def risk_for_counting_vulnerabilities_double(n):
        #     return intrinsic_risk_scores[n] + sum(
        #         [risk_for_counting_vulnerabilities_double(neighbor) for neighbor in graph.neighbors(n)])

        def risk_for_singular(n):
            return intrinsic_risk_scores[n] + sum(
                [intrinsic_risk_scores[pred] for pred in graph.reachable_by(n)])

        return {node_id: risk_for_singular(node_id) for node_id in graph.nodes.keys()}

    def run(self):
        nodes, edges, vulnerabilities, df = parse_JSON_file(self.merged_graph_path)
        # graph, reverse_graph, centralities = create_graphs(nodes, edges)
        enriched_graph = EnrichedCallGraph.create(nodes, edges, vulnerabilities)
        risk_scores = self._risk_scores_for_metrics(enriched_graph)
        application_node_ids = list(df[df['application_node']]['id'])

        risk = 0
        for app_node_id in application_node_ids:
            risk += risk_scores[app_node_id]

        # vulnerable_application_nodes = get_total_vulnerability_coverage(reverse_graph, vulnerabilities, application_node_ids)
        # weighted_sums = _weighted_sum(vulnerable_application_nodes)
        return risk, risk_scores, df


if __name__ == '__main__':
    for project in os.listdir(os.path.join(config.BASE_DIR, 'vulnerable')):
        print('----------------BEGIN {}----------------'.format(project))
        risks = []
        for path in Path(os.path.join(config.BASE_DIR, 'vulnerable', project)).glob('**/*-merged.json'):
            has_vulnerability = open(path).read().find('vulnerabilit') > 0
            print('has_vulnerability: {}, in ({})'.format(has_vulnerability, path))
            engine = RiskEngine(path)
            risk, risk_scores, frame = engine.run()
            print(risk)
            risks.append(risk)
        print('-------------------------------------------')
        print('Risks for {} are {}'.format(project, risk))
        print('----------------END----------------')

