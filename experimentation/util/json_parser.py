import ijson

from jgrapht.types import Graph
import jgrapht


class JSONParser:

    def parseJSONFile(self, filename: str):
        with open(filename, 'r') as file:

            parser = ijson.parse(file)
            edges = []  # (source, sink)
            nodes = []
            classes = []

            index = 0  # indicate whether it is source (odd) or sink (even)

            sourceNode = -1

            # Parse the JSON file and get nodes/edges

            for prefix, event, value in parser:
                if (prefix == 'cha.internalTypes' or prefix == 'cha.externalTypes' or prefix == 'cha.resolvedTypes'):
                    print('YAAAS: ', value)
                    classes.append(prefix+'.'+value+'.methods')
                elif (prefix == 'graph.internalCalls.item.item' or prefix == 'graph.externalCalls.item.item' or prefix == 'graph.resolvedCalls.item.item') and event == 'string':
                    index += 1
                    if index % 2 == 0:  # Even
                        edges.append((sourceNode, value))
                    else:  # Odd
                        sourceNode = value
                elif (prefix in classes) and event == 'map_key':
                    nodes.append(prefix + '.' + value)
                    continue


