# -*- coding: utf-8 -*-
'''
'''
import json
import os
import re
import time
from concurrent.futures.thread import ThreadPoolExecutor
from subprocess import Popen, PIPE

import requests
import sys

from werkzeug.sansio.multipart import MultipartEncoder

sys.path.append('../../vcompliance_ethernet')
# from vcompliance_ethernet.cases.basecase import BaseCase
from os_env import g_s_os_env

executor = ThreadPoolExecutor(2)


# def async_thread(f):
#     def wrapper(*args, **kwargs):
#         t = Thread(target=f, args=args, kwargs=kwargs)
#         t.start()
#         return wrapper
#
#
# def run_task(f, *args, **kwargs):
#     t = Thread(target=f, args=args, kwargs=kwargs)
#     t.start()


def test_time():
    i = 1
    while i < 100:
        time.sleep(1)
        i += 1
        print(i)


def upload_file_batch(file_path_list, upload_url, retry_time):
    file_id = ""
    while retry_time > 0:
        response_value = requests.post(upload_url, data=None, files=file_path_list)
        if response_value.status_code != 200 and retry_time > 0:
            # g_s_os_env.info("upload result is " + response_value.text + " and retry_time is" + str(retry_time))
            retry_time -= 1
            continue
        else:
            response_json = json.loads(response_value.text)
            file_id = response_json.get("data").get("file_id")
            break

    return file_id


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


# 传入有效file时，即可返回file_id。file封装在外面，方便定位问题
def upload_file(url, data=None, file_path=None, retry_time=3):
    file_id = ""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36'
    }
    if not file_path or not os.path.exists(file_path):
        return file_id
    files = {
        'file': open(file_path, 'rb')
    }
    while retry_time > 0:
        retry_time -= 1
        if file_id:
            break
        try:
            response_value = requests.post(url, data=data, files=files, headers=headers, timeout=30)
            if response_value.status_code != 200 and retry_time > 0:
                # g_s_os_env.info("upload result is " + response_value.text + " and retry_time is" + str(retry_time))
                continue
            else:
                response_json = json.loads(response_value.text)
                file_id = response_json.get("data").get("file_id")
        except Exception as e:
            continue
            pass
    return file_id


def download_file(url, file_id, dest_file_name, retry_time=3):
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
            # TODO print error
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
        'Content-Type': 'application/json'
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
    try:
        os.kill(process_id, 0)
        return True
    except:
        return False


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


if __name__ == '__main__':
    data = getIfconfig()
    ip = parseIfconfig(data)
    file_path = "../devops"
    file_path = "/home/gl/echodot1POWER_1.pcap"
    file_id = upload_file("https://pre.vsa.car.360.net/message/v1/hg_scanner/upload", file_path=file_path)
    a = "file_1111"
    b = a.replace("file_", "")
    json_str = "{\"code\":0,\"msg\":\"检测通过 测试时间20221130/2059\",\"data\":{\"task_id\":\"GFW7TXQQ\",\"case_id\":2277,\"block_name\":\"grab\",\"file_id\":\"62fb409ed88890202f6ed2ff\"}}"
    json_result = json.loads(json_str)
    url = "https://pre.vsa.car.360.net/api/v1/eth/async_callback"
    result = post_request(url=url, data=json_result)
    test = "CVE-2-3  DDDDDD CVE-2-3 XXXX..."
    cve_result = re.findall('CVE-.*' '', test)
    cve_result_2 = re.findall('CVE-.*?(?= )', test)
    cve_result_3 = re.findall('^CVE-.*?(?= )', test)
    result = set(cve_result_2)
    # os.system()
    process_id = 10403
    result = check_process_exist(process_id)
    # file = open("../devops", "rb")

    # result = download_file("https://pre.vsa.car.360.net/api/v1/project_file/download", "637f25d429da1000594daca0",
    #                        "./111.pcap")

    pass
