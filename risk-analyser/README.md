# Vulnerability Risk Analyser

Predict risk form open source dependencies with vulnerabilities.

## Prerequisites

- Python 3 (with requirements from `requirements.txt`)
- Git
- Java with Maven
- [Rapid integration tools](https://github.com/software-improvement-group-research/rapid-integration-tools) in local maven repo
- Access to `vulnerability-history` db (with credentials in `.env` file)

## Running the analyser

```bash
python entrypoint.py
```