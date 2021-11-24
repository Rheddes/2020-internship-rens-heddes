import re

import pandas as pd
import config
import os

if __name__ == '__main__':
    df = pd.read_csv(os.path.join(config.BASE_DIR, 'src', 'analysis', 'call_graph_stats.csv'))
    df['short_name'] = df.apply(lambda row: re.split(r'([a-zA-Z0-9\-]+)-[0-9\.a-zA-Z\-]+(?=-reduced\.json)', row['callgraph'])[1], axis=1)
    df = df.query('vulnerabilities > 0').sort_values('vulnerabilities', ascending=False)
    print(df.to_latex(index=False, columns=['short_name', 'nodes', 'edges', 'vulnerable', 'vulnerabilities']))
