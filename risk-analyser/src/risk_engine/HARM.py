from risk_engine.graph import RiskGraph


def HARM_risk(graph: RiskGraph, alpha=0.5):
    CV_vul = lambda n, v: alpha * graph.centrality_score_function(n) + (1 - alpha) * graph.get_impact_scores_for(n)[v]
    risks = {}
    for node, attributes in graph.get_vulnerable_nodes().items():
        for vulnerability in attributes['metadata']['vulnerabilities'].keys():
            risks[(node, vulnerability)] = CV_vul(node, vulnerability)
    return risks


def calculate_risk_from_tuples(harmrisk, index=0):
    risks = {key: 0.0 for key in set([key_tuple[index] for key_tuple in harmrisk])}
    for key_tuple, score in harmrisk.items():
        risks[key_tuple[index]] += score
    return risks
