import json
import os.path
from handlers.handler import Handler


class FileInput(Handler):
    def process(self, handler_input):
        try:
            f = open(handler_input, 'r')
        except OSError:
            print('Cannot open supplied file')
            raise FileNotFoundError('The specified file could not be opened')
        else:
            data = json.load(f)
            f.close()
            return data

