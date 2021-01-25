from v1.handlers.handler import Handler


class MutableDict():
    def __init__(self, start_dict):
        self._dict = start_dict

    def rename(self, oldkey, newkey):
        if newkey != oldkey:
            self._dict[newkey] = self._dict[oldkey]
            del self._dict[oldkey]
        return self

    def flatten(self, subdict):
        for key, value in self._dict[subdict].items():
            self._dict[key] = value
        del self._dict[subdict]
        return self

    def to_dict(self):
        return self._dict


class GraphPreProcessing(Handler):
    @staticmethod
    def _process_links(links):
        return list(map(
            lambda link: MutableDict(link)
            .rename('source_id', 'source')
            .rename('target_id', 'target')
            .flatten('metadata')
            .to_dict(),
            links
        ))

    @staticmethod
    def _process_nodes(nodes):
        return list(map(lambda node: MutableDict(node).flatten('metadata').to_dict(), nodes))

    def process(self, handler_input):
        handler_input['links'] = self._process_links(handler_input['links'])
        handler_input['nodes'] = self._process_nodes(handler_input['nodes'])
        return handler_input
