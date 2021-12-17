import os
import re

import pandas as pd

from utils.config import BASE_DIR, SHORT_NAME_REGEX
from utils.latex import latex_float, latex_int, process_and_write_latex_table, latex_float_with_precision


def call_graph_properties(csv_path, output_path):
    df = pd.read_csv(csv_path)
    df = df[df['vulnerable'] > 0].sort_values(by='vulnerabilities', ascending=False)
    df['short_name'] = df.apply(lambda row: re.split(SHORT_NAME_REGEX, row['callgraph'])[1], axis=1)
    table_string = df.to_latex(
        index=False, escape=False,
        columns=['short_name', 'nodes', 'edges', 'vulnerable', 'vulnerabilities'],
        column_format=r'@{}lrrrr@{}', label='tab:dataset',
        formatters=[None, latex_int, latex_int, latex_int, latex_int],
        caption='Call-graph properties of the analysed projects',
        header=['project', 'nodes', 'edges', 'vulnerable nodes', 'vulnerabilities'])
    process_and_write_latex_table(table_string, os.path.join(BASE_DIR, output_path, 'projects.tex'))


def centrality_correlations(csv_path, output_path):
    df = pd.read_csv(csv_path)
    df['correlation_p_betweenness'] = df.apply(
        lambda row: '${:0.2f}/{:.2f}$'.format(row['correlation_betweenness'], row['p_value_betweenness']), axis=1)
    df['correlation_p_coreachability'] = df.apply(
        lambda row: '${:0.2f}/{:.2f}$'.format(row['correlation_coreachability'], row['p_value_coreachability']), axis=1)
    df['empty'] = [''] * len(df)
    table_string = df.to_latex(
        index=False, escape=False, column_format=r'@{}lrrrlrr@{}', label='tab:correlation',
        caption='Spearman correlation between the \\textit{betweenness} and \\textit{co-reachability} centrality metrics and an exhaustive search over all paths in subgraphs with 100 nodes',
        formatters=[None, latex_float, latex_float, latex_float_with_precision(2), None, latex_float, latex_float_with_precision(2)],
        columns=['shortname', 'vulnerability_density', 'correlation_betweenness', 'p_value_betweenness', 'empty', 'correlation_coreachability', 'p_value_coreachability'],
    )
    means = df.mean()
    header_row = r'''
    \\toprule
    {} & {} &  \\multicolumn{2}{c}{\\textit{Betweenness}} & \\phantom{a} & \\multicolumn{2}{c}{\\textit{Co-reachability}}\\\\
    \\cmidrule{3-4} \\cmidrule{6-7}
    project & vulnerability density & correlation & P-value  & & correlation & P-value\\\\
    '''
    mean_row = r'\textit{{mean}} & {} & {} & & & {} & \\'.format(latex_float(means['vulnerability_density']),
                                                            latex_float(means['correlation_betweenness']),
                                                            latex_float(means['correlation_coreachability']))
    table_string = re.sub(r'\\toprule\n.*\\\\', header_row, table_string)\
        .replace(r'\bottomrule', f'\\midrule\n{mean_row}\n\\bottomrule')

    process_and_write_latex_table(table_string, os.path.join(BASE_DIR, output_path, 'correlation.tex'), )
