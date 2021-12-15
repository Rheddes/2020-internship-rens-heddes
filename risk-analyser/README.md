# Vulnerability Risk Analyser

Predict risk form open source dependencies with vulnerabilities.

## Prerequisites

- Python 3 (with requirements from `requirements.txt`)
- Git
- Java with Maven
- [Rapid integration tools](https://github.com/software-improvement-group-research/rapid-integration-tools) in local maven repo
- Access to `vulnerability-history` db (with credentials in `.env` file)

## Set up

```bash
pip install -r requirements.txt
```

## Generating callgraphs

The first step will generate enriched callgraphs for all projects in the `vulnerability-history` database, at the commit right before the fix is performed.
This is done to ensure the vulnerable dependency should be there.

```bash
python src/1_generate_callgraphs.py
```

A directory `reduced_callgraphs` should be created with enriched callgraphs (`PROJECT_NAME-reduced.json`)

## Basic statistics about analysed projects

In order to get a better understanding of the dataset we analyse the callgraphs for properties such as number of nodes, no. vulnerable nodes, no. edges etc.

```bash
python src/2_callgraph_stats.py
```

## Investigating centrality metrics

Understanding which centrality measure to use in the risk model is key, we can compare betweenness and co-reachability to an exhaustive search centrality.

```bash
python src/3_centrality_correlation.py
```

## Analysing risk & runtimes

Last step is analysing the risk associated with vulnerabilities.
In the research we will compare with a HARM (as introduced by [Hong et al.](https://doi.org/10.1109/DSN.2014.68)) and an exhaustive search approach.
The exhaustive search is limited to subgraphs, so we will also investigate runtime.

```bash
python src/4_analyse_callgraphs.py -o ./out/analysis --searchtime=60
```

