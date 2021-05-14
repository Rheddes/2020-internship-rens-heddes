import os
from config import BASE_DIR
from utils.graph import parse_JSON_file, create_graphs, get_total_vulnerability_coverage


class RiskEngine:
    def __init__(self, clone_dir):
        self.clone_dir = clone_dir

    def run(self):
        merged_graph = os.path.join(self.clone_dir, 'target', 'callgraphs',
                                    'com.flipkart.zjsonpatch.zjsonpatch-0.4.10-SNAPSHOT-merged.json')
        nodes, edges, df = parse_JSON_file(merged_graph)
        graph, reverse_graph, centralities = create_graphs(nodes, edges)
        print(df)
        vulnerable_node_ids = list(df[df['cvss_v2'].notnull()]['id'])
        application_node_ids = list(df[df['application_node']]['id'])
        vulnerable_application_nodes = get_total_vulnerability_coverage(reverse_graph, vulnerable_node_ids, application_node_ids)
        return df


if __name__ == '__main__':
    engine = RiskEngine(os.path.join(BASE_DIR, 'old_repos', 'jackson-databind', 'zjsonpatch'))
    frame = engine.run()
