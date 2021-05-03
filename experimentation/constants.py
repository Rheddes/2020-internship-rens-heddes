import os
import sys

# Constants

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = BASE_DIR + '/data'
CVSS_SCORE_VERSION = 'scoreCVSS3'

# cvss score risk thresholds 70/80/90
# CVSS_RISK_LOW_RANGE = {'low': 0, 'high': 6.8}
# CVSS_RISK_MODERATE_RANGE = {'low': 6.8, 'high': 7.5}
# CVSS_RISK_HIGH_RANGE = {'low': 7.5, 'high': 9.0}
# CVSS_RISK_VERY_HIGH_RANGE = {'low': 9.0, 'high': 10}

# cvss score risk thresholds 25/50/75
CVSS_RISK_LOW_RANGE = {'low': 0, 'high': 4.3}
CVSS_RISK_MODERATE_RANGE = {'low': 4.3, 'high': 5.0}
CVSS_RISK_HIGH_RANGE = {'low': 5.0, 'high': 7.2}
CVSS_RISK_VERY_HIGH_RANGE = {'low': 7.2, 'high': 10}

# Unit size risk profile thresholds
CVSS_RISK_PROFILE_LOW_TH = (0.25, 0, 0)
CVSS_RISK_PROFILE_MODERATE_TH = (0.3, 0.05, 0)
CVSS_RISK_PROFILE_HIGH_TH = (0.4, 0.1, 0)
CVSS_RISK_PROFILE_VERY_HIGH_TH = (0.5, 0.15, 0.05)
