import argparse
import json
import os
import time
from concurrent.futures.thread import ThreadPoolExecutor
import sys

sys.path.append('../../server')
import tools
from os_env import g_s_os_env
from config import env_config_parser

executor = ThreadPoolExecutor(16)


class BaseCase(object):

    def __init__(self, task_id, case_id, block_name, case_parameter=None):
        # 通用属性
        self.executor = executor
        # self.init_timestamp = int(time.time())

        self.task_id = task_id
        self.case_id = case_id
        self.block_name = block_name
        self.case_parameter = case_parameter
        self.case_max_timeout = int(env_config_parser.case_max_timeout)
        self.callback_url = env_config_parser.host + env_config_parser.callback_url
        self.download_url = env_config_parser.host + env_config_parser.download_url
        self.upload_url = env_config_parser.host + env_config_parser.upload_url
        # self.case_workspace = os.getcwd() + "/workspace/" + str(self.task_id) + "_" + str(case_id)
        self.case_workspace = "./workspace/" + str(self.task_id) + "_" + str(case_id)
        self.common_result_dict = tools.generate_result_dict({}, self.task_id, self.case_id, self.block_name,
                                                             self.case_parameter)

    def prepare_workspace(self):
        # workspace
        if not os.path.exists("./workspace"):
            os.makedirs("./workspace", 777)
        os.system("chmod 777 " + "./workspace")
        if not os.path.exists(self.case_workspace):
            os.makedirs(self.case_workspace, 777)
        os.system("chmod 777 " + self.case_workspace)

    def active_call_block_function(self):
        print("start active_call_block_function " + self.block_name)
        block_function = getattr(self, self.block_name)
        # 就直接调用。如果有其他参数，一样地传就好了
        return block_function()


if __name__ == '__main__':
    pass
