import json
import time
import sys

sys.path.append('../../server')
import tools

from cases.basecase import BaseCase
from os_env import g_s_os_env


# 用例命名就按下划线来，其他类按正常来
class case_one(BaseCase):
    def __init__(self, task_id, case_id, block_name, case_parameter):
        super().__init__(task_id, case_id, block_name, case_parameter)
        self.fork_process_id = None
        self.init_timestamp = int(time.time())

    def block_1(self):
        print("start execute block1")
        # 后台启动进程运行命令
        self.fork_process_id = g_s_os_env.start_process_by_cmd("top >> /home/gl/9.txt")
        # 线程监控执行情况并触发校验和kill pid动作
        self.executor.submit(self.callback_logic)
        result_dict = tools.generate_result_dict({}, self.task_id, self.case_id, self.block_name, self.case_parameter)
        return tools.generate_code_msg(result_dict, 0, "success")

    def callback_logic(self):
        g_s_os_env.info("execute callback logic " + str(self.case_id))
        print("execute callback logic " + str(self.case_id))
        # 建议设置每个case后台进程执行的最大执行时间
        while int(time.time() - self.init_timestamp) < 900:
            time.sleep(1)

        # kill掉进程
        status, output, error = g_s_os_env.exec_shell_cmd("kill -9 " + str(self.fork_process_id))
        if status == 0:
            g_s_os_env.info("execute kill -9 " + str(self.fork_process_id) + " end")
        else:
            g_s_os_env.error("execute kill -9 " + str(self.fork_process_id) + "status is " + str(status))


if __name__ == '__main__':
    # dict_1 = json.dumps({"param": 2})
    # param = str(dict_1)
    # result = Case_1("1", 1, "block_1", param).active_call_block_function()
    pass
