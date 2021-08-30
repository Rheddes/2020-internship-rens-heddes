The Data Management Plan (DMP) is created at the beginning of a
research project.  At that time, not all details will typically be
available, leaving some gaps to be filled in later. During the
project, the DMP is kept updated by the Project Leader, who notifies
their SIG Supervisor of all updates.

# Project Identification
- Project Leader: Rens Heddes
- Project ID:
- Time Period: 1st of October 2020 - 31st of August 2021
- SIG Supervisor: Miroslav Zivkovic
- Academic Supervisor: Sebastian Proksch (TU Delft)

# Data Sources
Please identify all data sources that will be used or generated during
the project.

1. Data Source 1
	- Brief description: Set of all scanned repositories, and their updates with release & commit dates.
	- Classification: Public
	- Origin: This project
2. Data Source 2
	- Brief description: Set of all vulnerabilities and which dependencies, and versions thereof, are affected
	- Classification: Public
	- Origin: The OWASP dependency check project
3. Data Source 3
	- Brief description: FASTEN Knowledge Base, containing information about methods, files, classes, calls, versions of packages for Java, C & Python
	- Classification: Public
	- Origin: The FASTEN project

# Data Storage
For each Data Source, please list where the data will be stored during
the project. Note that confidential data can only be stored within the
SIG network.

1. Data Source 1
	 - Location: On laptop
	 - Format: MySQL database
2. Data Source 2
	 - Location: On laptop
	 - Format: MySQL database
3. Data Source 3
	 - Location: Research fasten instance for SIG hosted version, Monster/Lima for TU Delft hosted one
	 - Format: Postgres DB

# Sharing of Data 
Please list the Data Sources that are intended to be shared outside of
SIG. Note that an academic supervisor is considered to be outside of
SIG. In case of Confidential Data, explicit permission from the SIG
supervisor is required before sharing, and special measures of
anonymization are typically mandatory. Also in cases of Public Data,
anonymization can be required to comply with GDPR regulations.

1. Data Source 1
	- Recipient:
	- Anonymization procedure:
	- Permission granted by:
2. Data Source 2

# Code Artefacts
Please identify all code artefacts that will be developed as part of
the project.

1. Code Artefact 1
	- Brief description: Pipeline for selecting open source repositories, and scanning their update history
	- Location: code.sig.eu/research/2020-internship-Rens-Heddes/vulnerability-history
2. Code Artefact 2
	- Brief description: Risk analyser, which can scan a repository for the risk associated with vulnerabilities in dependencies
	- Location: code.sig.eu/research/2020-internship-Rens-Heddes/risk-analyser

