import os
import config
import glob
import re

patterns = {
    'nodes': r'.*nodes: (\d+)',
    'edges': r'.*edges: (\d+)',
    'vulnerabilities': r'.*vulnerabilities: (\d+)',
    'paths': r'.*paths: (\d+)',
}

LoL = []

current_nodes = None

for logfile in glob.glob(os.path.join(config.BASE_DIR, 'data', 'logs', '**', '*.log')):
    project = logfile.split('/')[-2]
    with open(logfile) as file:
        for line in file:
            if re.match(r'.*nodes: (\d+)', line):
                    current_nodes = int(re.search(r'.*nodes: (\d+)', line)[1])
            if re.match(r'.*paths: (\d+)', line):
                LoL.append([project, current_nodes, int(re.search(r'.*paths: (\d+)', line)[1])])

print(LoL)