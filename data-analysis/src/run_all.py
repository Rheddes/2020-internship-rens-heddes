import getopt
import os.path
import sys

from matplotlib import rcParams

from chapter3.visualise_db import VulnerabilityHistory
from chapter5.tables import call_graph_properties, centrality_correlations
from chapter5.vis_risks import plot_rbo, plot_rbo_for_graphsizes
from chapter5.vis_runtime import plot_exhaustive_runtime_analysis, plot_exhaustive_runtime_factors
from utils.config import ensure_path, BASE_DIR


def get_opts(argv):
    update_dataframe_path = None
    scriptname = argv[0].split('/')[-1]
    help_string = f'{scriptname} --update-dataframe "<path to dataframe.p containing update data>"'
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
    history_analyser = VulnerabilityHistory(update_dataframe_path)
    history_analyser.data_overview('./plots/chapter3')
    history_analyser.scatter_dist('./plots/chapter3')
    history_analyser.plot_for_single_repo('./plots/chapter3')

    call_graph_properties(os.path.join(BASE_DIR, 'data', 'call_graph_stats.csv'), './plots/chapter5/runtime')
    centrality_correlations(os.path.join(BASE_DIR, 'data', 'correlation.csv'), './plots/chapter5')

    plot_exhaustive_runtime_analysis(os.path.join(BASE_DIR, 'data', 'runtimes_for_projects.csv'), './plots/chapter5/runtime')
    plot_exhaustive_runtime_factors(os.path.join(BASE_DIR, 'data', 'runtimes_for_projects.csv'), './plots/chapter5/runtime')

    plot_rbo(os.path.join(BASE_DIR, 'data', 'runtimes_for_projects.csv'), './plots/chapter5/risk')  # input variable --rbo ??
    plot_rbo_for_graphsizes(os.path.join(BASE_DIR, 'data', 'runtimes_for_projects.csv'), './plots/chapter5/risk')


if __name__ == '__main__':
    ensure_path('plots')
    ensure_path('plots/chapter3')
    ensure_path('plots/chapter5')
    ensure_path('plots/chapter5/runtime')
    ensure_path('plots/chapter5/risk')

    main(sys.argv)

