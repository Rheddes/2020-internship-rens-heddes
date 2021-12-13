import getopt
import os.path
import sys
import config

from matplotlib import rcParams

from chapter3.visualise_db import VulnerabilityHistory
from chapter5.tables import call_graph_properties, centrality_correlations
from chapter5.vis_risks import plot_rbo, plot_rbo_for_graphsizes
from chapter5.vis_runtime import plot_exhaustive_runtime_analysis, plot_exhaustive_runtime_factors
from config import ensure_path


def get_opts(argv):
    update_dataframe_path = None
    scriptname = argv[0].split('/')[-1]
    help_string = f'{scriptname} --update-dataframe <path to dataframe.p containing update data> '
    try:
        opts, args = getopt.getopt(argv[1:], 'hd:', ['update-dataframe='])
    except getopt.GetoptError as e:
        print(help_string)
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print(help_string)
            sys.exit()
        elif opt in ('-d', '--update-dataframe'):
            update_dataframe_path = arg
    return update_dataframe_path


def main(argv):
    update_dataframe_path = get_opts(argv)
    rcParams.update({'figure.autolayout': True})
    # history_analyser = VulnerabilityHistory(update_dataframe_path)
    # history_analyser.data_overview('./output/chapter3')
    # history_analyser.scatter_dist('./output/chapter3')
    # history_analyser.plot_for_single_repo('./output/chapter3')

    call_graph_properties(os.path.join(config.BASE_DIR, 'data', 'call_graph_stats.csv'), './output/chapter5/runtime')
    centrality_correlations(os.path.join(config.BASE_DIR, 'data', 'correlation.csv'), './output/chapter5')

    plot_exhaustive_runtime_analysis(os.path.join(config.BASE_DIR, 'data', 'runtimes_for_projects.csv'), './output/chapter5/runtime')
    plot_exhaustive_runtime_factors(os.path.join(config.BASE_DIR, 'data', 'extensive_runtime.csv'), './output/chapter5/runtime')

    plot_rbo(os.path.join(config.BASE_DIR, 'data', 'results_100.csv'), './output/chapter5/risk')  # input variable --rbo ??
    plot_rbo_for_graphsizes(os.path.join(config.BASE_DIR, 'data', 'results_webtau.csv'), './output/chapter5/risk')


if __name__ == '__main__':
    ensure_path('output')
    ensure_path('output/chapter3')
    ensure_path('output/chapter5')
    ensure_path('output/chapter5/runtime')
    ensure_path('output/chapter5/risk')

    main(sys.argv)

