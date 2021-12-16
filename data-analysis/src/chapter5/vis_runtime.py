import os
import re

import pandas as pd
import matplotlib.pyplot as plt

from utils.config import BASE_DIR, SHORT_NAME_REGEX


def plot_exhaustive_runtime_analysis(csv_path, output_path):
    df = pd.read_csv(csv_path)

    fig, ax = plt.subplots(figsize=(9, 5))
    for key, group in df.groupby('short_name'):
        group.plot(ax=ax, x='nodes', y='runtime', label=key)
    fig.legend(loc='upper left', bbox_to_anchor=(1, 1))
    plt.legend([])
    plt.yscale('log')
    plt.ylabel('Runtime for exhaustive search (seconds)')
    plt.xlabel('Subgraph size (nodes)')
    plt.title('Runtime for increasing graph sizes\n (max. 30min for an exhaustive search)')
    plt.tight_layout()
    plt.savefig(os.path.join(BASE_DIR, output_path, 'runtime_all_projects.pdf'))
    plt.show()

    fig, ax = plt.subplots(figsize=(9, 5))
    completed_projects = df.query(f'nodes == {df.nodes.max()}').full_name
    for key, group in df[~df.full_name.isin(completed_projects)].groupby('short_name'):
        group.plot(ax=ax, x='nodes', y='runtime', label=key)
    fig.legend(loc='upper left', bbox_to_anchor=(1, 1))
    plt.yscale('log')
    plt.xlim(0, df.nodes.max())
    plt.ylabel('Runtime for exhaustive search (seconds)')
    plt.xlabel('Subgraph size (nodes)')
    plt.title('Runtime for increasing graph sizes\n for projects which reached 15 minute time limit')
    plt.tight_layout()
    plt.savefig(os.path.join(BASE_DIR, output_path, 'runtime_timedout.pdf'))
    plt.show()


def plot_exhaustive_runtime_factors(path_to_csv, output_path):
    df = pd.read_csv(path_to_csv)
    df['density'] = df.edges / df.nodes

    completed_projects = df.query(f'nodes == {df.nodes.max()}').full_name
    df = df[~df.full_name.isin(completed_projects)]

    colors = {project: plt.cm.tab10(i) for i, project in enumerate(df.short_name.unique())}

    fig, ax = plt.subplots(figsize=(9, 5))
    for key, group in df.query('nodes > 10 and edges > 10').groupby('short_name'):
        group.sort_values('density').plot(ax=ax, x='density', y='runtime', label=key, color=colors[key])
    plt.legend(loc='upper left', bbox_to_anchor=(1, 1))
    plt.yscale('log')
    # plt.xscale('log')
    plt.xlabel('Density (edges per node)')
    plt.ylabel('Runtime for exhaustive search (seconds)')
    plt.title('Affect of edge over node density on runtime\nfor exhaustive search')
    plt.tight_layout()
    plt.savefig(os.path.join(BASE_DIR, output_path, 'runtime_density.pdf'))
    plt.show()

    fig, ax = plt.subplots(figsize=(9, 5))
    for key, group in df.groupby('short_name'):
        group.plot(ax=ax, x='nodes', y='execution_paths', label=key, color=colors[key])
    plt.legend(loc='upper left', bbox_to_anchor=(1, 1))
    plt.ylabel('Number of attack paths found')
    plt.xlabel('Graph size (nodes)')
    plt.title('Number of attack paths found for increasing graph sizes')
    plt.tight_layout()
    plt.savefig(os.path.join(BASE_DIR, output_path, 'paths.pdf'))
    plt.show()

