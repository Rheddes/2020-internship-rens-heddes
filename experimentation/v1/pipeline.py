from v1.handlers.handler import Handler


class Pipeline(Handler):
    def __init__(self, handlers):
        self._handlers = handlers

    def process(self, handler_input):
        current_input = handler_input
        for handler in self._handlers:
            current_input = handler.process(current_input)
        return current_input
