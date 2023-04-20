#!/usr/libexec/platform-python
# -*- coding: utf-8 -*-
'''

@author: Ginteraction
'''
import os
import platform
import signal
import string
import subprocess

from log import cls_logger


class os_env(object):
    '''
    classdocs
    '''
    g_s_logger = cls_logger()

    def __init__(self):
        '''
        Constructor
        '''
        self.se_root_path = os.path.dirname(
            os.path.realpath(__file__)) + os.sep + '..'
        self.run_path = os.getcwd()
        self.configfilelist = []

    def make_ready(self, log_file, level):
        os_env.g_s_logger.make_ready(log_file, level)
        os_env.g_s_logger = self.g_s_logger.get_logger()
        self.info = self.g_s_logger.info
        self.debug = self.g_s_logger.debug
        self.warn = self.g_s_logger.warn
        self.error = self.g_s_logger.error
        self.fatal = self.g_s_logger.fatal
        #self.whoami = os_env.get_shell_cmd_output('whoami')

    @staticmethod
    def exec_shell_cmd(cmd, param={}, cwd=None, debug=True):
        '''exec_shell_cmd
        return (return_code,output)'''
        # print(cwd,param)
        # print(param.get('patch_file',None))

        #    print(str(type(cmd)))
        #    print(str(type(cmd)).find('instancemethod'))
        #     if  isinstance(cmd,str) or str(type(cmd)).find('unicode'):
        (status, output, error) = (0, None, None)
        cmd = string.Template(cmd).safe_substitute(param)

        # if not debug:
        #     stderr = subprocess.PIPE
        # else:
        #     stderr = None
        if cmd.strip().find("file://") == 0:
            cmd_line = cmd.strip()[len("file://"):]
            if not os.path.isabs(cmd_line):
                cmd_line = g_s_os_env.se_root_path + os.sep + cmd_line
            cmd = "sh {0}".format(cmd_line)

        # cls_os_env.g_s_logger.debug("exec_cmd: {0}".format(cmd))
        add_cmd = '''LANG="en_US.ISO8859-1";{}'''.format(
            os_env.get_export_global_env())
        # print(add_cmd)
        cmd = "{0} {1} ".format(add_cmd, cmd)
        if platform.system() == "Windows":
            # if True:
            return (status, output.decode('utf-8'), error.decode('utf-8'))
        p = subprocess.Popen(cmd,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             shell=True,
                             cwd=cwd)  # ,
        output, error = p.communicate()
        status = p.wait()
        return (status, output.decode('utf-8'), error.decode('utf-8'))
        #     elif str(type(cmd)).find('instancemethod')>=0:
        #         print("abcdd")
        #         return cmd(cwd,param,debug)


    @staticmethod
    def get_export_global_env():
        ret = ''
        for k, v in os.environ.items():
            if k.find("SE_") == 0:
                ret += '''export {}={};'''.format(k, v)
        return ret

    @staticmethod
    def start_process_by_cmd(cmd):
        process = subprocess.Popen(cmd, shell=True, executable='bash')
        return process.pid

    @staticmethod
    def kill_process_by_pid(pid):
        os.kill(pid, signal.SIGKILL)


g_s_os_env = os_env()
exec_shell_cmd = os_env.exec_shell_cmd
