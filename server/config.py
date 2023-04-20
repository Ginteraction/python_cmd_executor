# -*- coding: utf-8 -*-
'''
created gl
date:2022/11/15 15:01
'''
import os
from configparser import ConfigParser
import sys

sys.path.append('../vcompliance_ethernet')
from os_env import g_s_os_env

CONFIG_PATH ="./config/env.conf"


class env_config_parser(object):

    def __init__(self):
        config_obj = ConfigParser()
        config_obj.read(CONFIG_PATH)
        print(CONFIG_PATH)
        self.host = config_obj.get("callback_url", "host")
        self.upload_url = config_obj.get("callback_url", "upload_url")
        self.download_url = config_obj.get("callback_url", "download_url")
        self.callback_url = config_obj.get("callback_url", "callback_url")
        self.case_max_timeout = config_obj.get("case", "timeout")


if __name__ == '__main__':
    # status, output, error = g_s_os_env.exec_shell_cmd("pwd")
    # config = ConfigParser()
    # config.read("./config/env.conf")
    # keys = config.options(section="vcompliance_platform")
    # host = config.get("vcompliance_platform", "host")
    # print(keys)
    pass

env_config_parser = env_config_parser()
