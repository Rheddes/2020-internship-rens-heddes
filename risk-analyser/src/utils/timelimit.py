import logging
from multiprocessing import Process, Queue
from time import sleep


QUEUE_STOP = 'STOP'
NO_RESULTS = 'NO_RESULTS'

def f(time):
    sleep(time)


def dump_queue(queue):
    """
    Empties all pending items in a queue and returns them in a list.
    """
    result = []

    for i in iter(queue.get, QUEUE_STOP):
        if i == NO_RESULTS:
            return None
        result.append(i)
    sleep(.1)
    return result


def run_with_limited_time(func, args=None, kwargs=None, timeout=5):
    """Runs a function with time limit

    :param func: The function to run
    :param args: The functions args,  given as tuple
    :param kwargs: The functions keywords, given as dict
    :param timeout: The time limit in seconds
    :return: True if the function ended successfully. False if it was terminated.
    """
    if args is None:
        args = ()
    if kwargs is None:
        kwargs = {}
    results = Queue()
    kwargs['queue'] = results
    p = Process(target=func, args=args, kwargs=kwargs)
    p.start()
    p.join(timeout)
    results.put(QUEUE_STOP)
    if p.is_alive():
        p.terminate()
        logging.warning('Function timeout {} with args {}'.format(func, args))
    return dump_queue(results)
