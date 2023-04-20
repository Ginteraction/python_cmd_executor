# logs config
import logging
import os
from logging.handlers import RotatingFileHandler


class cls_logger():
    '''
    classdocs
    '''

    __mLogger = None

    def __init__(self):
        '''
        Constructor
        '''
        self.debug_level = logging.INFO

    @staticmethod
    def make_ready(logfile, level=logging.INFO):
        dirname = os.path.dirname(logfile)
        if not os.path.exists(dirname):
            os.makedirs(dirname, 600)
        cls_logger.__mLogger = cls_logger.__setupLogger(logfile, level)

    @staticmethod
    def get_logger():
        return cls_logger.__mLogger

    @staticmethod
    def __setupLogger(logfile, level):
        mlogger = logging.getLogger('app_info')
        mlogger.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
        file_handler = logging.FileHandler(logfile)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG)

        console = logging.StreamHandler()
        console.setLevel(level)
        cformatter = logging.Formatter('%(levelname)-8s %(message)s')
        console.setFormatter(cformatter)
        # add hanlder
        mlogger.addHandler(console)
        mlogger.addHandler(file_handler)
        return mlogger
