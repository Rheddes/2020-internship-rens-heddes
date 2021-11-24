import os
import re

import pandas as pd
import matplotlib.pyplot as plt
import rbo
import ast

from src import config


if __name__ == '__main__':
    for no_nodes in [80, 100]:
        df = pd.read_csv(os.path.join(config.BASE_DIR, 'data', 'results_{}.csv'.format(no_nodes)))

        for column in ['ex_path_vuln', 'ex_cen_vuln', 'hong_vuln', 'model_vuln']:
            df[column] = df[column].apply(ast.literal_eval).values

        df['hong_rbo'] = df.apply(lambda row: rbo.RankingSimilarity(row['ex_path_vuln'], row['hong_vuln']).rbo(), axis=1)
        df['model_rbo'] = df.apply(lambda row: rbo.RankingSimilarity(row['ex_path_vuln'], row['model_vuln']).rbo(), axis=1)
        df['short_name'] = df.apply(
            lambda row: re.split(r'([a-zA-Z0-9\-]+)-[0-9\.a-zA-Z\-]+(?=-reduced\.json)', row['callgraph'])[1], axis=1)

        df.plot(y=['hong_rbo', 'model_rbo'], x='short_name', kind='bar')
        plt.title('Rank Biased Overlap for\n subgraphs of size {}'.format(no_nodes))
        plt.ylabel('RBO')
        plt.xlabel('project')
        plt.tight_layout()
        plt.savefig(os.path.join(config.BASE_DIR, 'output', f'results_{no_nodes}.pdf'))
        plt.show()
