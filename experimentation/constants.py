import os
import sys

# Constants

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Unit size risk thresholds
CVSS_RISK_LOW_RANGE = {'low': 0, 'high': 7.8}
CVSS_RISK_MODERATE_RANGE = {'low': 7.8, 'high': 8.8}
CVSS_RISK_HIGH_RANGE = {'low': 8.8, 'high': 9.8}
CVSS_RISK_VERY_HIGH_RANGE = {'low': 9.8, 'high': 10}

# Unit size risk profile thresholds
CVSS_RISK_PROFILE_LOW_TH = (0.25, 0, 0)
CVSS_RISK_PROFILE_MODERATE_TH = (0.3, 0.05, 0)
CVSS_RISK_PROFILE_HIGH_TH = (0.4, 0.1, 0)
CVSS_RISK_PROFILE_VERY_HIGH_TH = (0.5, 0.15, 0.05)
