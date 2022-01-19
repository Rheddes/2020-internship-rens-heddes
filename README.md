# 2020-internship-rens-heddes

[![DOI](https://zenodo.org/badge/358278903.svg)](https://zenodo.org/badge/latestdoi/358278903)

The code in this repository is divided in to three parts, each being a different independent subproject:

| folder | purpose |
| ------ | ------- |
| `vulnerability-history` | Is used to generate a database with open source java projects, dependency updates in those projects and the associated vulnerability information if the update fixes a vulnerability |
| `risk-analyser` | Obtains the enriched call-graphs for vulnerable versions of projects fromt the `vulnerability-history` database, and th associated risk scores |
| `data-analysis` | Uses resulting data from other two projects to generate tables and figures which are in the report. A snapshot of the data as is used in the report is supplied, in order to generate new data please refer to the [README](https://github.com/Rheddes/2020-internship-rens-heddes/tree/master/data-analysis) in that directory |

Each of these subprojects has a Docker Compose setup for easy local deployment.


## Generating all tables and figures

In order to generate all tables and figures used in the report locally, with the supplied snapshot of data please perform the following steps:

```bash
# First make sure to enter the correct subproject
cd data-analysis
# Start the docker container
docker compose up # For older versions of Docker: docker-compose up
```
