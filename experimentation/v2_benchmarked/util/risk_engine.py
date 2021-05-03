import numpy as np
import constants
from jgrapht.types import Graph, AttributesGraph

from v2_benchmarked.util.risk_profile import RiskProfile, RiskLevel

CVSS_RISK_PROFILE = {
    'very high': constants.CVSS_RISK_PROFILE_VERY_HIGH_TH,
    'high': constants.CVSS_RISK_PROFILE_HIGH_TH,
    'moderate': constants.CVSS_RISK_PROFILE_MODERATE_TH,
    'low': constants.CVSS_RISK_PROFILE_LOW_TH,
}


class VulnerabilityRiskEngine:
    def __init__(self, thresholds=None, weight_function=lambda x: 1):
        self.thresholds = thresholds
        self.weight_function = weight_function

    def calculate_risk_profile(self, vertex_set: set, graph: AttributesGraph) -> RiskProfile:
        """

        :rtype: object
        """
        risk_profile = RiskProfile()
        for callable_id in vertex_set:
            vulnerabilities = graph.vertex_attrs[callable_id]['metadata'].get('vulnerabilities', None)
            if vulnerabilities:
                highest_score = max([float(vulnerability[constants.CVSS_SCORE_VERSION]) for vulnerability in vulnerabilities.values()])
                if self.thresholds['low']['low'] < highest_score <= self.thresholds['low']['high']:
                    risk_profile.add_callable(callable_id, self.weight_function(callable_id), RiskLevel.LOW)
                elif self.thresholds['moderate']['low'] < highest_score <= self.thresholds['moderate']['high']:
                    risk_profile.add_callable(callable_id, self.weight_function(callable_id), RiskLevel.MODERATE)
                elif self.thresholds['high']['low'] < highest_score <= self.thresholds['high']['high']:
                    risk_profile.add_callable(callable_id, self.weight_function(callable_id), RiskLevel.HIGH)
                elif self.thresholds['very high']['low'] < highest_score <= self.thresholds['very high']['high']:
                    risk_profile.add_callable(callable_id, self.weight_function(callable_id), RiskLevel.VERY_HIGH)
            else:
                risk_profile.add_callable(callable_id, self.weight_function(callable_id), RiskLevel.NONE)
        return risk_profile

    def calculate_overall_risk(self, measured_profile):
        def check_threshold(profile):
            return measured_profile.get_ratio(RiskLevel.MODERATE) > profile[0] \
                   or measured_profile.get_ratio(RiskLevel.HIGH) > profile[1] \
                   or measured_profile.get_ratio(RiskLevel.VERY_HIGH) > profile[2]

        if check_threshold(CVSS_RISK_PROFILE['very high']):
            return 5
        elif check_threshold(CVSS_RISK_PROFILE['high']):
            return 4
        elif check_threshold(CVSS_RISK_PROFILE['moderate']):
            return 3
        if check_threshold(CVSS_RISK_PROFILE['low']):
            return 2
        return 1

    def calibrate_system(self, graph: Graph):

        severenessList = []

        for callable in graph.vertices:
            vulnerabilities = graph.vertex_attrs[callable]['metadata'].get('vulnerabilities', None)
            if vulnerabilities:
                severenessList.extend(
                    [float(vulnerability[constants.CVSS_SCORE_VERSION]) for vulnerability in vulnerabilities.values()])

        print(severenessList)
        cvss_mediumBorder = np.percentile(severenessList, 70)
        cvss_highBorder = np.percentile(severenessList, 80)
        cvss_veryHighBorder = np.percentile(severenessList, 90)

        print(cvss_mediumBorder)
        print(cvss_highBorder)
        print(cvss_veryHighBorder)
        self.thresholds = [cvss_mediumBorder, cvss_highBorder, cvss_veryHighBorder]
        return cvss_mediumBorder, cvss_highBorder, cvss_veryHighBorder
