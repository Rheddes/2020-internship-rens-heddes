import getopt
import glob
import logging
import os.path
import re
import shutil
import sys

from utils import config

import time

import networkx as nx
import pandas as pd
import numpy as np
from rbo import rbo

from utils.timelimit import run_with_limited_time, NO_RESULTS

logging.basicConfig(filename=os.path.join(config.BASE_DIR, 'logs', 'exhaustive.log'), level=logging.INFO, format='[%(asctime)s][%(levelname)s] %(message)s', datefmt='%m-%d %H:%M')
# logging.basicConfig(level=logging.INFO, format='[%(asctime)s][%(levelname)s] %(message)s', datefmt='%m-%d %H:%M')

from analysis.sampling import hong_risk, sort_dict, calculate_risk_from_tuples, proportional_risk
from risk_engine.exhaustive_search import calculate_all_execution_paths, hong_exhaustive_search
from risk_engine.graph import RiskGraph, parse_JSON_file
from utils.graph_sampling import ff_sample_subgraph

# FILE = os.path.join(config.BASE_DIR, 'reduced_callgraphs', 'com.flipkart.zjsonpatch.zjsonpatch-0.4.10-SNAPSHOT-reduced.json')
# FILE = os.path.join(config.BASE_DIR, 'reduced_callgraphs', 'net.optionfactory.hibernate-json-3.0-SNAPSHOT-reduced.json')
# FILE = os.path.join(config.BASE_DIR, 'reduced_callgraphs', 'com.genersoft.wvp-1.5.10.RELEASE-reduced.json')
# FILE = os.path.join(config.BASE_DIR, 'reduced_callgraphs', 'com.xenoamess.x8l-2.1.2-reduced.json')
# FILE = os.path.join(config.BASE_DIR, 'reduced_callgraphs', 'me.gaigeshen.wechat.wechat-mp-1.2.0-SNAPSHOT-reduced.json')


def remove_simple_loops(graph: RiskGraph):
    node_list = list(graph.nodes)
    adj = nx.linalg.adj_matrix(graph, nodelist=node_list)
    for idx_u, u in enumerate(node_list):
        for idx_v, v in enumerate(node_list[idx_u:]):
            if adj[idx_u,idx_u+idx_v] and adj[idx_u+idx_v,idx_u]:
                graph.remove_edge(u, v)
    return graph


def _get_project_name_from_path(path):
    return path.split('/')[-1]


def runtime_analysis_for(json_callgraph, graphsizes, outdir, queue=None):
    list_of_lists = []
    callgraph = RiskGraph.create(*parse_JSON_file(json_callgraph), auto_update=False)
    if not callgraph.get_vulnerable_nodes():
        logging.warning('No vulnerable nodes skipping %s', json_callgraph)
        if queue:
            queue.put(NO_RESULTS)
        return

    full_project_name = _get_project_name_from_path(json_callgraph)
    short_name = re.split(config.SHORT_NAME_REGEX, full_project_name)[1]
    project_out_dir = os.path.join(outdir, short_name)
    os.mkdir(project_out_dir)
    change_log_file(os.path.join(project_out_dir, 'exhaustive.log'))
    output_logger = get_output_logger(project_out_dir)

    nodeset = set(callgraph.get_vulnerable_nodes())
    for n in graphsizes:
        logging.info('Using subgraph of size: {}'.format(n))
        start = time.perf_counter()

        subgraph = ff_sample_subgraph(callgraph, nodeset, min(n, len(callgraph.nodes)))
        nx.write_gexf(subgraph, os.path.join(project_out_dir, f'subgraph_{n}.gexf'))
        all_execution_paths = calculate_all_execution_paths(subgraph)
        nodeset = nodeset.union(set(subgraph.nodes.keys()))

        all_paths_stop = time.perf_counter()

        exhausive_risk_psv, _ = hong_exhaustive_search(subgraph, all_execution_paths)

        exhaustive_stop = time.perf_counter()

        subgraph.configure_for_model('d')
        hong_risks = hong_risk(subgraph)
        hong_risk_psv = list(sort_dict(calculate_risk_from_tuples(hong_risks, 1)).keys())

        hong_stop = time.perf_counter()

        betweenness_risks = {node: subgraph.get_inherent_risk_for(node) for node in subgraph.nodes.keys()}
        model_risk_psv = list(proportional_risk(subgraph, betweenness_risks).keys())

        model_stop = time.perf_counter()

        hong_rbo = rbo.RankingSimilarity(exhausive_risk_psv, hong_risk_psv).rbo()
        model_rbo = rbo.RankingSimilarity(exhausive_risk_psv, model_risk_psv).rbo()

        finish_stop = time.perf_counter()

        record = [
            n,
            hong_rbo,
            model_rbo,
            exhausive_risk_psv,
            hong_risk_psv,
            model_risk_psv,
            all_paths_stop-start,
            exhaustive_stop - all_paths_stop,
            hong_stop - exhaustive_stop,
            model_stop - hong_stop,
            finish_stop - model_stop,
        ]
        output_logger.info(record)
        list_of_lists.append(record)
        if queue:
            queue.put([full_project_name, short_name, n, len(subgraph.edges), len(all_execution_paths), exhaustive_stop-start, model_rbo, hong_rbo])

    df = pd.DataFrame(list_of_lists,
                      columns=['subgraph_size', 'hong_rbo', 'model_rbo', 'exhaustive_psv', 'hong_psv', 'model_psv',
                               'all_paths_time', 'exhaustive_time', 'hong_time', 'model_time', 'score_time'])

    df.to_csv(os.path.join(project_out_dir, 'runtime_analysis.csv'), index=False)


def change_log_file(new_log_file):
    filehandler = logging.FileHandler(new_log_file, 'a')
    formatter = logging.Formatter('[%(asctime)s][%(levelname)s] %(message)s', datefmt='%m-%d %H:%M')
    filehandler.setFormatter(formatter)
    log = logging.getLogger()  # root logger - Good to get it only once.
    for hdlr in log.handlers[:]:  # remove the existing file handlers
        if isinstance(hdlr, logging.FileHandler):  # fixed two typos here
            log.removeHandler(hdlr)
    log.addHandler(filehandler)


def get_output_logger(outdir):
    output_logger = logging.getLogger('output')
    fh = logging.FileHandler(os.path.join(outdir, 'output.log'))
    fh.setFormatter(logging.Formatter('%(message)s'))
    fh.setLevel(logging.INFO)
    output_logger.setLevel(logging.INFO)
    output_logger.addHandler(fh)
    return output_logger



def clear_output_directory(outdir):
    if os.path.exists(outdir) and not os.path.islink(outdir):
        shutil.rmtree(outdir)
    os.mkdir(outdir)


def get_opts(argv):
    inputfile = None
    outputdir = None
    timeout = None
    scriptname = argv[0].split('/')[-1]
    try:
        opts, args = getopt.getopt(argv[1:], 'hi:o:t:', ['ifile=', 'ofile=', 'timeout='])
    except getopt.GetoptError:
        print(f'{scriptname} -t <timeout in seconds (optional, 5min default)> -i <inputfile (optional)> -o <outputdir from project root (optional)>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print(f'{scriptname} -t <timeout> -i <inputfile> -o <outputdir from project root>')
            sys.exit()
        elif opt in ('-i', '--ifile'):
            inputfile = arg
        elif opt in ('-o', '--ofile'):
            outputdir = os.path.join(config.BASE_DIR, arg)
        elif opt in ('-t', '--timeout'):
            timeout = float(arg)
    logging.info('Input file is "{}"'.format(inputfile))
    logging.info('Output dir is "{}"'.format(outputdir))
    return inputfile, outputdir, timeout


def main(argv):
    provided_callgraph, outdir, timeout = get_opts(argv)
    if not outdir:
        outdir = os.path.join(config.BASE_DIR, 'out', 'runtime_analysis')
    if not timeout:
        timeout = 5*60.0

    # graphsizes = [230]
    graphsizes = list(range(10, 260, 10))
    df_data = []

    callgraph_dir = 'test_callgraphs' if os.environ.get('USE_TEST_CALLGRAPHS', False) else 'reduced_callgraphs'
    clear_output_directory(outdir)

    if provided_callgraph:
        runtime_analysis_for(os.path.join(config.BASE_DIR, 'reduced_callgraphs', provided_callgraph), graphsizes, outdir)
        return


    for file in glob.glob(os.path.join(config.BASE_DIR, callgraph_dir, '**', '*-reduced.json'), recursive=True):
        results = run_with_limited_time(runtime_analysis_for, (os.path.join(config.BASE_DIR, callgraph_dir, file), graphsizes, outdir), timeout=timeout)
        print(f'Results for {file}: ', results)
        if results:
            df_data += results

    df = pd.DataFrame(df_data, columns=['full_name', 'short_name', 'nodes', 'edges', 'execution_paths', 'runtime', 'Model D RBO', 'HARM RBO'])
    df.to_csv(os.path.join(outdir, 'runtimes_for_projects.csv'))


if __name__ == '__main__':
    main(sys.argv)
