import re


def get_method_name_from(uri):
    return re.search(r'/[a-zA-Z0-9_.]+/[a-zA-Z0-9_$%]+\.([a-zA-Z0-9_%$]+)\(', uri).group(1)


def coords_from_gexf(path):
    coord_dict = {}
    with open(path, 'r') as gexf:
        node_id = None
        for line in gexf:
            if 'node id' in line:
                node_id = int(re.search(r'(?<=id=\")\d+', line).group(0))
            if 'viz:position' in line:
                x = float(re.search(r'(?<=x=\")-?\d+\.\d+', line).group(0))
                y = float(re.search(r'(?<=y=\")-?\d+\.\d+', line).group(0))
                coord_dict[node_id] = {'x': x, 'y': y, 'z': 0.0}
    return coord_dict