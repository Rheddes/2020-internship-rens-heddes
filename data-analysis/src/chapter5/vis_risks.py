import os
import re

import pandas as pd
import matplotlib.pyplot as plt
import rbo
import ast

from utils.config import BASE_DIR, SHORT_NAME_REGEX


def plot_rbo(csv_path, output_path, graphsize=100):
    df = pd.read_csv(csv_path)
    df = df.query(f'nodes == {graphsize}')

    df.plot(y=['HARM RBO', 'Model D RBO'], x='short_name', kind='bar')
    plt.legend(loc='lower right')
    plt.title('Rank Biased Overlap for\n subgraphs of size 100')
    plt.ylabel('Rank Biased Overlap of \n PLV compared with Exhaustive Search')
    plt.xlabel('Project')
    plt.tight_layout()
    plt.savefig(os.path.join(BASE_DIR, output_path, f'results_100.pdf'))
    plt.clf()


def plot_rbo_for_graphsizes(csv_path, output_path, project='wvp'):
    df = pd.read_csv(csv_path)
    df = df.query(f'short_name == "{project}"')
    df.plot(y=['HARM RBO', 'Model D RBO'], x='nodes')
    plt.ylabel('Rank Biased Overlap of \n PLV compared with Exhaustive Search')
    plt.ylim(0, 1)
    plt.xlabel('Subgraph size (nodes)')
    plt.title(f'Rank Biased Overlap of PLV compared with\n Exhaustive Search for increasing graph sizes (project: {project})')
    plt.savefig(os.path.join(BASE_DIR, output_path, 'rbo_graphsize.pdf'))
    plt.clf()
