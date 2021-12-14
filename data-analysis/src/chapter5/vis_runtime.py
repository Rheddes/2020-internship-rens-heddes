import os
import re

import pandas as pd
import matplotlib.pyplot as plt

from utils.config import BASE_DIR, SHORT_NAME_REGEX

def plot_exhaustive_runtime_analysis(csv_path, output_path):
    df = pd.read_csv(csv_path)

    fig, ax = plt.subplots(figsize=(9, 5))
    df.plot(x='graphsizes', ax=ax).legend(loc='upper left', bbox_to_anchor=(1, 1))
    plt.legend([])
    plt.yscale('log')
    plt.ylabel('Runtime for exhaustive search (seconds)')
    plt.xlabel('Subgraph size (nodes)')
    plt.title('Runtime for increasing graph sizes\n (limit of 15 minutes per project)')
    plt.tight_layout()
    plt.savefig(os.path.join(BASE_DIR, output_path, 'runtime_all_projects.pdf'))
    plt.show()

    fig, ax = plt.subplots(figsize=(9, 5))
    timedout = df.iloc[-1][df.iloc[-1].isnull()].index.values
    df.plot(x='graphsizes', y=timedout, ax=ax).legend(loc='upper left', bbox_to_anchor=(1, 1))
    plt.yscale('log')
    plt.ylabel('Runtime for exhaustive search (seconds)')
    plt.xlabel('Subgraph size (nodes)')
    plt.title('Runtime for increasing graph sizes\n for projects which reached 15 minute time limit')
    plt.tight_layout()
    plt.savefig(os.path.join(BASE_DIR, output_path, 'runtime_timedout.pdf'))
    plt.show()


def plot_exhaustive_runtime_factors(path_to_csv, output_path):
    df = pd.read_csv(path_to_csv)
    df['density'] = df.edges / df.nodes
    df['short_name'] = df.apply(lambda row: re.split(SHORT_NAME_REGEX, row['project'])[1], axis=1)


    colors = {project: plt.cm.tab10(i) for i, project in enumerate(df.short_name.unique())}

    fig, ax = plt.subplots(figsize=(9, 5))
    for key, group in df.query('nodes > 10 and edges > 10').groupby('short_name'):
        group.plot.scatter(ax=ax, x='density', y='runtime', label=key, color=colors[key])
    plt.legend(loc='upper left', bbox_to_anchor=(1, 1))
    plt.yscale('log')
    plt.xscale('log')
    plt.xlabel('Density (edges per node)')
    plt.ylabel('Runtime for exhaustive search (seconds)')
    plt.title('Affect of edge over node density on runtime\nfor exhaustive search')
    plt.tight_layout()
    plt.savefig(os.path.join(BASE_DIR, output_path, 'runtime_density.pdf'))
    plt.show()

    fig, ax = plt.subplots(figsize=(9, 5))
    for key, group in df.groupby('short_name'):
        group.plot(ax=ax, x='nodes', y='paths', label=key, color=colors[key])
    plt.legend(loc='upper left', bbox_to_anchor=(1, 1))
    plt.ylabel('Number of attack paths found')
    plt.xlabel('Graph size (nodes)')
    plt.title('Number of attack paths found for increasing graph sizes')
    plt.tight_layout()
    plt.savefig(os.path.join(BASE_DIR, output_path, 'paths.pdf'))
    plt.show()

