import logging
from multiprocessing import Process
from time import sleep


def f(time):
    sleep(time)


def run_with_limited_time(func, args=None, kwargs=None, timeout=5):
    """Runs a function with time limit

    :param func: The function to run
    :param args: The functions args, given as tuple
    :param kwargs: The functions keywords, given as dict
    :param time: The time limit in seconds
    :return: True if the function ended successfully. False if it was terminated.
    """
    if args is None:
        args = ()
    if kwargs is None:
        kwargs = {}
    p = Process(target=func, args=args, kwargs=kwargs)
    p.start()
    p.join(timeout)
    if p.is_alive():
        p.terminate()
        logging.warning('Function timeout {} with args {}'.format(func, args))
        return False
    return True
