# -*- coding: utf-8 -*-
'''

@author: Ginteraction
'''

# from collections import OrderedDict
import os
import time

import sys
from concurrent.futures.thread import ThreadPoolExecutor

sys.path.append('../server')

import tools
from config import env_config_parser
from os_env import g_s_os_env
from cases.basecase import BaseCase

executor = ThreadPoolExecutor(16)

from cases.case_one import case_one

SPECIAL_BLOCK_LIST = ["ping", "kill_process", "subnet"]


# cmd如果以后要扩展成多个的情况比较好改，先不管
class CaseHandler(object):
    '''
    一个用例执行器抽象
    '''
    os_env = g_s_os_env

    def __init__(self, task_id, case_id=None, case_file_name=None, block_name=None, case_parameter={}):
        self.task_id = task_id
        self.case_id = case_id

        self.case_file_name = case_file_name
        self.block_name = block_name
        self.case_parameter = case_parameter

        self.init_timestamp = int(time.time())
        self.call_back_url = env_config_parser.host + env_config_parser.callback_url
        self.result_dict = tools.generate_result_dict({}, self.task_id, self.case_id, self.block_name,
                                                      self.case_parameter)

        self.fork_process_id = None

    # 常规的解析。该步骤后续如果还需要额外操作，则还可以继续封装
    def load(self):
        pass

    def handle_special_block(self):
        if self.block_name == "ping":
            if not self.case_parameter or not self.case_parameter.get("target_ip"):
                g_s_os_env.error("ping param error,task_id is {},case_id is {}".format(self.task_id, self.case_id))
                return tools.generate_code_msg(self.result_dict, -2, "参数错误")
            executor.submit(self.check_ping)
            # 结果返回
            return tools.generate_code_msg(self.result_dict, 0, "success")
        if self.block_name == "kill_process":
            if not self.case_parameter or not self.case_parameter.get("process_id"):
                g_s_os_env.error("kill param errorr,task_id is {},case_id is {}".format(self.task_id, self.case_id))
                return tools.generate_code_msg(self.result_dict, -2, "参数错误")

            g_s_os_env.exec_shell_cmd(
                "kill -9 " + str(self.case_parameter.get("process_id")) + " && rm -rf /proc/" + str(
                    self.case_parameter.get("process_id")))
            time.sleep(1)
            g_s_os_env.exec_shell_cmd(
                "kill -9 " + str(self.case_parameter.get("process_id")) + " && rm -rf /proc/" + str(
                    self.case_parameter.get("process_id")))
            # os.system("kill -9 " + str(self.case_parameter.get("process_id")))
            return tools.generate_code_msg(self.result_dict, 0, "success")

        if self.block_name == "subnet":
            if not self.case_parameter or not self.case_parameter.get("ip") or not self.case_parameter.get(
                    "target_ip"):
                g_s_os_env.error("kill param errorr,task_id is {},case_id is {}".format(self.task_id, self.case_id))
                return tools.generate_code_msg(self.result_dict, -2, "参数错误")
            executor.submit(self.check_subnet)
            # 结果返回
            return tools.generate_code_msg(self.result_dict, 0, "success")

    def check_ping(self):
        check_result = tools.check_ping(self.case_parameter.get("target_ip"))
        # 回调逻辑
        if check_result:
            msg = "车载以太网工具与目标IP {}无网络隔离".format(self.case_parameter.get("target_ip"))
            if self.case_file_name == "ETHERNET_CASE_1001":
                msg = "检测通过，" + msg
            call_back_dict = tools.generate_code_msg(self.result_dict, 0, msg)
            tools.post_request(self.call_back_url, call_back_dict)
        else:
            msg = "车载以太网工具与目标IP {}有网络隔离".format(self.case_parameter.get("target_ip"))
            if self.case_file_name == "ETHERNET_CASE_1001":
                msg = "检测不通过，" + msg
            call_back_dict = tools.generate_code_msg(self.result_dict, -1, msg)
            tools.post_request(self.call_back_url, call_back_dict)

    def check_subnet(self):
        check_result = tools.check_subnet(self.case_parameter.get("ip"), self.case_parameter.get("target_ip"))
        if check_result:
            call_back_dict = tools.generate_code_msg(self.result_dict, 0, "车载以太网工具与目标IP {}在同一子网".format(
                self.case_parameter.get("target_ip")))
            tools.post_request(self.call_back_url, call_back_dict)
        else:
            call_back_dict = tools.generate_code_msg(self.result_dict, -1, "车载以太网工具与目标IP {}不在同一子网".format(
                self.case_parameter.get("target_ip")))
            tools.post_request(self.call_back_url, call_back_dict)
        return tools.generate_code_msg(self.result_dict, 0, "success")

    def get_result(self):
        # 特殊block点 通用流程
        if self.block_name in SPECIAL_BLOCK_LIST:
            return self.handle_special_block()

        # 开始执行case
        case = globals().get(self.case_file_name)(self.task_id, self.case_id, self.block_name,
                                                  self.case_parameter)
        BaseCase.prepare_workspace(case)
        block_result = BaseCase.active_call_block_function(case)
        return block_result
