import re

import pandas as pd
import config
import os


def latex_float(f):
    float_str = '{0:.2e}'.format(f)
    if 'e' in float_str:
        base, exponent = float_str.split('e')
        return r'${0} \times 10^{{{1}}}$'.format(base, int(exponent))
    return f'${float_str}$'


def call_graph_stats_csv():
    df = pd.read_csv(os.path.join(config.BASE_DIR, 'out', 'call_graph_stats.csv'))
    df['short_name'] = df.apply(lambda row: re.split(config.SHORT_NAME_REGEX, row['callgraph'])[1], axis=1)
    df = df.query('vulnerabilities > 0').sort_values('vulnerabilities', ascending=False)
    print(df.to_latex(index=False, columns=['short_name', 'nodes', 'edges', 'vulnerable', 'vulnerabilities']))


def correlation():
    df = pd.read_csv(os.path.join(config.BASE_DIR, 'out', 'correlation.csv'))
    df['correlation_p_betweenness'] = df.apply(lambda row: '${:0.2f}/{:.2f}$'.format(row['correlation_betweenness'], row['p_value_betweenness']), axis=1)
    df['correlation_p_coreachability'] = df.apply(lambda row: '${:0.2f}/{:.2f}$'.format(row['correlation_coreachability'], row['p_value_coreachability']), axis=1)
    df.to_latex(buf=os.path.join(config.BASE_DIR, 'out', 'correlation.tex'), index=False, escape=False, column_format='|l|r|r|r|', label='tab:correlation',
                caption='Spearman correlation between the \\textit{betweenness} and \\textit{co-reachability} centrality metrics and an exhaustive search over all paths in subgraphs with 100 nodes',
                formatters=[None, latex_float, None, None],
                columns=['shortname', 'vulnerability_density', 'correlation_p_betweenness', 'correlation_p_coreachability'],
                header=[r'\textbf{Project}', r'\multicolumn{1}{|p{2.2cm}|}{\centering \textbf{Vulnerability} \\ \textbf{Density}}', r'\multicolumn{1}{|p{2.2cm}|}{\centering \textbf{Correlation} \\ \textbf{Betweenness}}', r'\multicolumn{1}{|p{3cm}|}{\centering \textbf{Correlation/P-value} \\ \textbf{Co-reachability/P-value}}']
    )


if __name__ == '__main__':
    correlation()
