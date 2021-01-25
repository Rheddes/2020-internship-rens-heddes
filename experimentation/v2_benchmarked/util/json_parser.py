import ijson
from ijson import ObjectBuilder

from jgrapht.types import Graph, AttributesGraph
import jgrapht


class JSONParser:

    def parseCGOpalGraph(self, filename: str):
        with open(filename, 'r') as file:

            parser = ijson.parse(file)
            edges = []  # (source, sink)
            nodes = {}
            classes = []
            key = '-'

            index = 0  # indicate whether it is source (odd) or sink (even)

            sourceNode = -1

            # Parse the JSON file and get nodes/edges

            for prefix, event, value in parser:
                # self.debug_print(prefix, event, value)
                if prefix.startswith(key):  # while at this key, build the object
                    # NESTED OBJECTS ARE NOT PARSED AS SUCH
                    builder.event(event, value)
                    if prefix == key and event == 'end_map':
                        add_to[int(id)] = builder.value
                elif (prefix == 'cha.internalTypes' or prefix == 'cha.externalTypes' or prefix == 'cha.resolvedTypes') and event == 'map_key':
                    classes.append(prefix+'.'+value+'.methods')
                # elif (prefix == 'graph.internalCalls.item.item' or prefix == 'graph.externalCalls.item.item' or prefix == 'graph.resolvedCalls.item.item') and event == 'string':
                elif (prefix == 'graph.internalCalls.item.item' or prefix == 'graph.externalCalls.item.item') and event == 'string':
                    index += 1
                    if index % 2 == 0:  # Even
                        edges.append((int(sourceNode), int(value)))
                    else:  # Odd
                        sourceNode = value
                elif (prefix in classes) and event == 'map_key' and not prefix.startswith('cha.resolvedType'):
                    key = prefix+'.'+value
                    builder = ObjectBuilder()
                    add_to = nodes
                    id = value
                    continue
        return [classes, nodes, edges]

    def parseMetadata(self, filename: str, graph: AttributesGraph):
        with open(filename, 'r') as file:
            callables = ijson.items(file, 'item')
            for callable in callables:
                vertex_id = self.findVertexIdFromURI(graph, callable['fasten_uri'])
                if vertex_id:
                    graph.vertex_attrs[vertex_id]['metadata'] = {**graph.vertex_attrs[vertex_id]['metadata'],
                                                                 **callable['metadata']}

    def findVertexIdFromURI(self, graph, uri):
        for id, attrs in graph.vertex_attrs.items():
            if attrs['uri'] == uri:
                return id
        return None


    def debug_print(self, prefix, event, value):
        print('-----Item-----')
        print('Prefix: ', prefix)
        print('Event: ', event)
        print('Value: ', value)
        print('--------------')


