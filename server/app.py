import json
import logging
import time

from flask import Flask, request, jsonify

# also consider json2html
import tools
from case_handler import CaseHandler
from os_env import g_s_os_env

app = Flask(__name__)
# resolve chinese encode
app.config['JSON_AS_ASCII'] = False

# resolve _request_ctx_err_msg

ctx = app.app_context()
ctx.push()

timestamp = int(time.time())
log_name = "./logs/log-" + str(timestamp)


# api = Api(app)


@app.route('/case/start_case', methods=['post'])
def get_case_result():
    # responseJson
    result_dict = {}
    request_time = int(time.time())
    try:
        json_data = request.json
    except:
        return tools.generate_code_msg(result_dict, -1, "参数错误")
    g_s_os_env.info("request start_case param is " + json.dumps(json_data) + "\n timestamp is " + str(request_time))
    if "task_id" not in json_data:
        return tools.generate_code_msg(result_dict, -1, "请核验task_id")
    case_handler = CaseHandler(task_id=json_data.get("task_id"), case_id=json_data.get("case_id"),
                               case_file_name=json_data.get("case_file_name"),
                               block_name=json_data.get("block_name"),
                               case_parameter=json_data.get("case_parameter"),
                               )

    case_handler.load()
    result_data = case_handler.get_result()
    return result_data


@app.route('/get_net_info', methods=['get'])
def get_net_info():
    g_s_os_env.info("request get_net_ifo timestamp is " + str(int(time.time())))
    result_data = tools.get_inet_ip()
    return tools.generate_code_msg(result_data, 0, "success")


@app.route('/check', methods=['get'])
def execute_check():
    # g_s_os_env.info("request get_net_ifo timestamp is " + str(int(time.time())))

    result_dict = {}
    status, output, error = g_s_os_env.exec_shell_cmd("whoami")
    status_1, output_1, error_1 = g_s_os_env.exec_shell_cmd("ls /home")
    result_dict.update({"who": output})
    result_dict.update({"ls": output_1})
    return tools.generate_code_msg(result_dict, 0, "success")


if __name__ == '__main__':
    # 日志模块
    g_s_os_env.make_ready(log_name, logging.INFO)
    # api模块
    app.run(host="0.0.0.0", port=30002)

log_name = log_name
