import os
import re

import pandas as pd
import matplotlib.pyplot as plt
import rbo
import ast

from utils.config import BASE_DIR, SHORT_NAME_REGEX


def plot_rbo(csv_path, output_path):
    df = pd.read_csv(csv_path)

    for column in ['ex_path_vuln', 'ex_cen_vuln', 'hong_vuln', 'model_vuln']:
        df[column] = df[column].apply(ast.literal_eval).values

    df['HARM RBO'] = df.apply(lambda row: rbo.RankingSimilarity(row['ex_path_vuln'], row['hong_vuln']).rbo(), axis=1)
    df['Model D RBO'] = df.apply(lambda row: rbo.RankingSimilarity(row['ex_path_vuln'], row['model_vuln']).rbo(),
                                 axis=1)
    df['short_name'] = df.apply(lambda row: re.split(SHORT_NAME_REGEX, row['callgraph'])[1], axis=1)

    df.plot(y=['HARM RBO', 'Model D RBO'], x='short_name', kind='bar')
    plt.title('Rank Biased Overlap for\n subgraphs of size 100')
    plt.ylabel('Rank Biased Overlap of \n PLV compared with Exhaustive Search')
    plt.xlabel('Project')
    plt.tight_layout()
    plt.savefig(os.path.join(BASE_DIR, output_path, f'results_100.pdf'))
    plt.show()


def plot_rbo_for_graphsizes(csv_path, output_path):
    df = pd.read_csv(csv_path)

    df.plot(y=['HARM', 'Model D'], x='subgraph_size')
    plt.ylabel('Rank Biased Overlap of \n PLV compared with Exhaustive Search')
    plt.xlabel('Subgraph size (nodes)')
    plt.savefig(os.path.join(BASE_DIR, output_path, 'rbo_graphsize.pdf'))
    plt.show()
