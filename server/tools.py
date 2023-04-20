#!/usr/libexec/platform-python
# -*- coding: utf-8 -*-
'''
'''
import json
import os
# import re
import re
import sys
import time
from concurrent.futures.thread import ThreadPoolExecutor

import requests

sys.path.append('../../vcompliance_ethernet')
from os_env import g_s_os_env

RET_ERROR = 1
RET_SUCCESS = 0

FORK_PROCESS_ID = None
executor = ThreadPoolExecutor(8)


def save_file(local_full_pathname, content, write_mode='wb'):
    with open(local_full_pathname, write_mode) as f:
        f.write(content.encode('utf-8'))


def upload_file_batch(file_path_list, upload_url, retry_time):
    file_id = ""
    while retry_time > 0:
        response_value = requests.post(upload_url, data=None, files=file_path_list)
        if response_value.status_code != 200 and retry_time > 0:
            g_s_os_env.info("upload result is " + response_value.text + " and retry_time is" + str(retry_time))
            retry_time -= 1
            continue
        else:
            response_json = json.loads(response_value.text)
            file_id = response_json.get("data").get("file_id")
            break

    return file_id


from subprocess import Popen, PIPE


# 获取网卡名称和其ip地址
def getIfconfig():
    p = Popen(['ifconfig'], stdout=PIPE)
    data = p.stdout.read().decode('utf-8').split('\n\n')
    return [i for i in data if i and not i.startswith('lo')]


def parseIfconfig(data):
    dic = {}
    for devs in data:
        lines = devs.split('\n')
        devname = lines[0].split(":")[0]
        # macaddr = lines[0].split()[-1]
        ipaddr = lines[1].split()[1]
        dic[devname] = ipaddr
    return dic


def get_inet_ip():
    data = getIfconfig()
    return parseIfconfig(data)


def check_ping(ip):
    status, output, error = g_s_os_env.exec_shell_cmd("ping -c 3 {}".format(ip))
    if "0 received" not in output and not error:
        return True
    return False


def check_subnet(src_ip, dest_ip):
    check_result = False
    src_ip_list = src_ip.split(".")
    dest_ip_list = dest_ip.split(".")
    i = 2
    while i >= 0:
        if src_ip_list[i] == dest_ip_list[i]:
            i -= 1
            continue
        else:
            break
    if i == -1:
        check_result = True
    return check_result


def upload_platform_file(url, data=None, file_path=None, retry_time=3):
    g_s_os_env.info("start upload")
    file_id = ""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36'
    }
    if not file_path or not os.path.exists(file_path):
        g_s_os_env.error("please check file_path exist or filemode write")
        return file_id
    files = {
        'file': open(file_path, 'rb')
    }
    while retry_time > 0:
        retry_time -= 1
        g_s_os_env.info("start post upload")
        if file_id:
            break
        try:
            response_value = requests.post(url, data=data, files=files, headers=headers, timeout=180)
            g_s_os_env.info("end post upload")
            if response_value.status_code != 200 and retry_time > 0:
                # g_s_os_env.info("upload result is " + response_value.text + " and retry_time is" + str(retry_time))
                continue
            else:
                response_json = json.loads(response_value.text)
                g_s_os_env.info(
                    "upload right,response is" + str(response_json) + " and timestamp is" + str(int(time.time())))
                file_id = response_json.get("data").get("file_id")
        except Exception as e:
            g_s_os_env.info("upload file except: " + e)
            continue
            pass

    return file_id


def download_platform_file(url, file_id, dest_file_name, retry_time=3):
    torrent = None
    if not file_id or not dest_file_name:  # 如果参数没有指定文件名
        # g_s_os_env.error("please check file_id exist or dest_file_name exist ")
        pass
    get_url = url + "?file_id=" + file_id
    # torrent = requests.get(get_url, stream=True)
    while retry_time > 0:
        torrent = requests.get(get_url)
        length = len(list(torrent.iter_content(8)))  # 下载区块数,为防止很小，不设置为512
        if length == 1:  # 如果是1 就是空文件 重新下载
            g_s_os_env.error("download empty or file is too small")
            pass
            retry_time -= 1
        else:
            print('下载完成')
            break
    with open(dest_file_name, 'wb') as f:
        if torrent:
            for chunk in torrent.iter_content(1024):  # 防止文件过大，以1024为单位一段段写入
                f.write(chunk)


# 入参data为dict或json
def post_request(url, data={}, retry_time=3):
    request_data = json.dumps(data)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
        'Content-type': 'application/json'
    }
    while retry_time > 0:
        response_value = requests.post(url, data=request_data, headers=headers)
        if response_value.status_code != 200 and retry_time > 0:
            # g_s_os_env.info("upload result is " + response_value.text + " and retry_time is" + str(retry_time))
            retry_time -= 1
            continue
        else:
            response_json = json.loads(response_value.text)
            return response_json
    return {}


def check_process_exist(process_id):
    if os.path.exists("/proc/" + str(process_id)):
        return True
    return False


def generate_result_dict(result_dict, task_id, case_id, block_name, case_parameter):
    result_dict.update(
        {"task_id": task_id, "case_id": case_id, "block_name": block_name, "case_parameter": case_parameter})
    return result_dict


def generate_code_msg(data, code, msg):
    result_dict = {"data": data}
    if "status" in data and data.get("status") == 0:
        data.update({"result": True})
    result_dict.update({"code": code, "msg": msg})
    return result_dict


def generate_callback_code_msg(data, code, msg):
    data.update({"code": code, "msg": msg})
    return data


if __name__ == '__main__':
    # file_id = upload_platform_file(url="https://pre.vsa.car.360.net/message/v1/hg_scanner/upload",
    #                                file_path="./config/env.conf")
    # result = check_subnet("192.168.1.1", "192.168.1.2")
    # result = check_ping("www.baidu.com")
    pass
