# coding: utf-8
# -------------------------------------------------------------------
# 宝塔Linux面板
# -------------------------------------------------------------------
# Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
# -------------------------------------------------------------------
# Author: hwliang <hwl@bt.cn>
# -------------------------------------------------------------------

# 系统日志
# ------------------------------
import datetime
import json
import os
import re
import sys
import time
import shutil

import requests

import public
from safeModel.base import safeBase


class main(safeBase):

    def __init__(self):
        ssh_cache_path = "{}/data/ssh".format(public.get_panel_path())
        if not os.path.exists(ssh_cache_path): os.makedirs(ssh_cache_path, 384)

    # *********************************************** start ssh收费模块  ******************************************************

    def create_ip_rules(self, get):
        '''
        添加登录ip限制规则
        @param get:
        @return:
        '''
        from firewallModel.comModel import main as comModel
        commodel = comModel()
        ip_list = get['address'] if 'address' in get else ""

        ip_rules_file = "data/ssh_deny_ip_rules.json"
        try:
            ip_rules = json.loads(public.readFile(ip_rules_file))
        except Exception:
            ip_rules = []

        ip_list = ip_list.split(",") if ip_list.find(",") != -1 else [ip_list]
        result_list = []

        for ip in ip_list:
            ip_result = {"ip": ip, "status": True, "msg": "封禁成功!"}
            if not public.is_ipv4(ip):
                ip_result['status'] = False
                ip_result['msg'] = "仅支持ipv4!"
                result_list.append(ip_result)
                continue

            args = public.dict_obj()
            args.operation = 'add'
            args.address = ip
            args.strategy = get['types'] if 'types' in get else "drop"
            args.chain = "INPUT"
            args.family = "ipv4"
            args.brief = get['brief'] if 'brief' in get else "SSH登录日志页面点击IP手动封禁"
            create_result = commodel.set_ip_rule(args)
            if not create_result['status']:
                ip_result['status'] = False
                ip_result['msg'] = create_result['msg']
                result_list.append(ip_result)
                continue
            if ip not in ip_rules: ip_rules.append(ip)
            result_list.append(ip_result)

        public.writeFile(ip_rules_file, json.dumps(ip_rules))
        cache_key = "SSH_DENY_IP_RULES"
        from BTPanel import cache
        cache.set(cache_key, [], 86400)

        return result_list

    def remove_ip_rules(self, get):
        '''
        删除登录ip限制规则
        @param get:
        @return:
        '''
        from firewallModel.comModel import main as comModel
        commodel = comModel()
        ip_list = get['address'] if 'address' in get else ""
        ip_list = ip_list.split(",") if ip_list.find(",") != -1 else [ip_list]
        ip_rules_file = "data/ssh_deny_ip_rules.json"
        try:
            ip_rules = json.loads(public.readFile(ip_rules_file))
        except Exception:
            ip_rules = []

        result_list = []

        for ip in ip_list:
            ip_result = {"ip": ip, "status": False, "msg": "解封失败!"}
            query_result = public.M('firewall_ip').where('address=?', (ip,)).find()
            for index, rule in enumerate(ip_rules):
                if ip_rules[index] == ip:
                    ip_rules.pop(index)

            if len(query_result) == 0:
                ip_result['status'] = True
                ip_result['msg'] = "解封成功"
                result_list.append(ip_result)
                continue
            if not public.is_ipv4(ip):
                ip_result['status'] = False
                ip_result['msg'] = "仅支持ipv4!"
                result_list.append(ip_result)
                continue
            args = public.dict_obj()
            args.operation = 'remove'
            args.address = ip
            args.strategy = "drop"
            args.chain = "INPUT"
            args.family = "ipv4"
            remove_result = commodel.set_ip_rule(args)
            if remove_result['status']:
                ip_result['status'] = True
                ip_result['msg'] = "解封成功"
                result_list.append(ip_result)

        public.writeFile(ip_rules_file, json.dumps(ip_rules))
        return result_list

    def get_ssh_list(self, get):
        """
        @获取SSH登录
        @param get:
            count :数量
        """
        select_pl = ['Accepted', 'Failed password for', 'Connection closed by authenticating user', 'sshd\[.*session opened for user', 'PAM service(sshd) ignoring max retries']
        if hasattr(get, 'select'):
            if get.select == "Accepted":
                select_pl = ['Accepted', 'sshd\[.*session opened for user', 'PAM service(sshd) ignoring max retries']
            elif get.select == "Failed":
                select_pl = ['Failed password for', 'Connection closed by authenticating user']

        p = 1
        count = 20
        if 'count' in get: count = int(get['count'])
        if 'p' in get: p = int(get['p'])

        result = []
        min, max = (p - 1) * count, p * count

        log_list = self.get_log_byfile(self.get_ssh_log_files(get)[0], min, max,
                                       self.__get_search_list(get, select_pl))

        for log in log_list:
            data = self.get_ssh_log_line(log['log'], log['time'])
            if not data: continue
            result.append(data)

        if p < 1000000: public.set_module_logs('ssh_log', 'get_ssh_list')
        return public.return_area(result, 'address')

    def get_ssh_error(self, get):
        """
        @获取SSH错误次数
         @param get:
            count :数量
        """
        p = 1
        count = 20
        if 'count' in get: count = int(get['count'])
        if 'p' in get: p = int(get['p'])

        result = []
        min, max = (p - 1) * count, p * count

        log_list = self.get_log_byfile(self.get_ssh_log_files(get)[0], min, max,
                                       self.__get_search_list(
                                           get,
                                           ['Failed password for', 'Connection closed by authenticating user']
                                       ))

        for log in log_list:
            data = self.get_ssh_log_line(log['log'], log['time'])
            if not data: continue
            result.append(data)

        if p < 1000000: public.set_module_logs('ssh_log', 'get_ssh_list')
        return public.return_area(result, 'address')

    def task_log_byfile(self, sfile, min_num, max_num, search=None):
        """
        @name 获取日志文件的日志
        @param sfile:日志文件
        @param min_num:起始行数
        @param max_num:结束行数
        @param search:搜索关键字
        """
        log_list = []

        if self.is_debain_12():
            h_find = {'log_file': 'journalctl', "list": [], 'uptime': time.time(), 'title': '授权日志', 'size': 10000}
        else:
            if sfile == "/var/log/secure":
                h_find = {'log_file': '/var/log/secure', "list": [], 'uptime': time.time(), 'title': '授权日志',
                          'size': 10000}
            elif sfile == "/var/log/auth.log":
                h_find = {'log_file': '/var/log/auth.log', "list": [], 'uptime': time.time(), 'title': '授权日志',
                          'size': 10000}
            else:
                return log_list

        if not h_find:
            return log_list

        # 获取遍历文件列表
        file_list = [h_find['log_file']]
        for info in h_find['list']:
            file_list.append(info['log_file'])
        for filename in file_list:
            # 处理最新文件
            if filename in ['/var/log/secure', '/var/log/auth.log', 'journalctl'] and search:
                self.get_curr_log_file(filename, search, min_num, max_num, log_list)
        return log_list

    def task_ssh_log_files(self):
        """
        获取ssh日志文件
        """
        s_key = 'secure'
        if not os.path.exists('/var/log/secure'):
            s_key = 'auth.log'
        if os.path.exists('/var/log/secure') and os.path.getsize('/var/log/secure') == 0:
            s_key = 'auth.log'
        spath = '/var/log/'
        return spath + s_key

    def _decode(self, data):
        import urllib.parse
        import binascii
        if type(data) != str:  # 确保输入是字符串类型
            data = str(data)
        json_data = json.dumps(data)
        encoded_data = urllib.parse.quote(json_data)
        hex_data = binascii.hexlify(encoded_data.encode('utf-8'))
        if sys.version_info[0] == 2:
            result = hex_data
        else:
            result = hex_data.decode('utf-8')
        return result

    # 堡塔云安全-恶意文件检测调用接口[为非企业用户支持扫描,将其计划任务入口调用到这里]
    # 云安全恶意文件检测 -每6小时执行一次-直接调用 SafeCloudModel 的 webshell_detection
    def webshell_detection(self, get):
        time.sleep(120)
        try:
            # 确保目录存在
            # print("执行云安全检测")
            safecloud_dir = '/www/server/panel/data/safeCloud'
            if not os.path.exists(safecloud_dir):
                os.makedirs(safecloud_dir)
                
            # 直接导入并实例化 SafeCloudModel
            sys.path.insert(0, '/www/server/panel')
            from projectModel.safecloudModel import main as SafeCloudModel
            
            # 创建参数对象并调用方法
            args = public.dict_obj()
            args.model_index = 'project'
            args.is_task = 1  # 标记为任务调用，方便在目标函数中识别
            
            # 实例化并调用检测函数
            safecloud = SafeCloudModel()

            safecloud.webshell_detection(args)  # 频率控制在函数内部处理
            # 定时更新数据
            safecloud.get_pending_alarm_trend(args)
            safecloud.get_security_trend(args)
            
        except Exception as e:
            pass

    # 堡塔云安全-网站安全扫描
    def webscanning_detection(self, get):
        """
        堡塔云安全-网站安全扫描
        @param get: 请求参数对象
        """
        time.sleep(120)
        try:
            # 确保目录存在
            safecloud_dir = '/www/server/panel/data/safeCloud'
            if not os.path.exists(safecloud_dir):
                os.makedirs(safecloud_dir)

            result_file = os.path.join(safecloud_dir, 'web_scan_result.json')

            # 检查是否需要执行扫描
            need_scan = False
            if not os.path.exists(result_file):
                need_scan = True
            else:
                try:
                    last_scan = json.loads(public.readFile(result_file))
                    # 检查上次扫描时间，如果超过24小时则需要重新扫描
                    last_scan_time = time.mktime(
                        time.strptime(last_scan.get('scan_time', '2000-01-01 00:00:00'), '%Y-%m-%d %H:%M:%S'))
                    if time.time() - last_scan_time > 86400:  # 24小时 = 86400秒
                        need_scan = True
                except:
                    need_scan = True

            if need_scan:
                sys.path.insert(0, '/www/server/panel')
                import PluginLoader

                args = public.dict_obj()
                args.module_get_object = 1

                # 创建参数对象
                args = public.dict_obj()

                # 创建一个模拟的websocket对象
                class DummyWebSocket:
                    def send(self, message):
                        pass

                args._ws = DummyWebSocket()  # 使用模拟的websocket对象
                args.ws_callback = ""  # 添加空的ws_callback属性
                args.site_list = []  # 获取所有PHP站点
                php_sites = public.M('sites').where('project_type=?', ('PHP',)).field('name').select()
                for site in php_sites:
                    args.site_list.append(site['name'])

                PluginLoader.module_run('webscanning', 'ScanAllSite', args)

        except Exception as e:
            pass

    def task_ssh_error_count(self, get):
        local_ip = public.GetLocalIp()
        path_time = "/www/server/panel/data/task_ssh_error_count.pl"

        # 堡塔云安全-恶意文件检测调用接口
        public.run_thread(self.webshell_detection, (get,))
        # 堡塔云安全-网站安全扫描
        public.run_thread(self.webscanning_detection, (get,))

        if not os.path.exists(path_time):
            public.writeFile(path_time, json.dumps({"time": int(time.time())}))
            share_ip_info = {"time": 0,"update":0}
        else:
            share_ip_info = json.loads(public.readFile(path_time))
        if (int(time.time()) - share_ip_info["time"]) < 600:
            return False
        share_ip_info["time"] = int(time.time())
        public.writeFile(path_time, json.dumps(share_ip_info))
        p = 1
        count = 200
        get=public.dict_obj()
        get.count=200
        get.p=1
        if 'count' in get: count = int(get['count'])
        if 'p' in get: p = int(get['p'])
        result = []
        try:
            min, max = (p - 1) * count, p * count
            log_list = self.task_log_byfile(self.task_ssh_log_files(), min, max,self.__get_search_list(get,['Failed password for', 'Connection closed by authenticating user']))
            today = time.strftime('%Y-%m-%d', time.localtime(time.time()))
            for log in log_list:
                data = self.get_ssh_log_line(log['log'], log['time'])
                if not data: continue
                #判断是否为今天的日志
                if 'time' not in data:continue
                local_time=data['time']
                if not local_time.startswith(today):
                    continue
                tmp={}
                timeArray = time.strptime(local_time, "%Y-%m-%d %H:%M:%S")
                timeStamp = int(time.mktime(timeArray))
                tmp['time']=timeStamp
                tmp['address']=data['address']
                tmp['port']=int(data['port'])
                #转为时间戳
                timeArray = time.strptime(local_time, "%Y-%m-%d %H:%M:%S")
                timeStamp = int(time.mktime(timeArray))
                if timeStamp > share_ip_info["update"]:
                    #如果是内网IP不上报
                    if public.is_local_ip(data['address']):
                        continue
                    #如果IP是本机IP不上报
                    if local_ip == data['address']:
                        continue
                    result.append(tmp)

            if len(result) > 0:
                address_dict = {}
                address_dict2={}
                for i in result:
                    if i['time'] >= share_ip_info["update"]:
                        share_ip_info["update"] = i['time']
                    address = i['address']
                    if not public.check_ip(address):continue
                    if address in address_dict:
                        address_dict[address] += 1
                        if address+"time" in address_dict2 and i['time']>address_dict2[address+"time"]:
                            address_dict2[address + "time"] = i['time']
                    else:
                        address_dict[address] = 1
                        address_dict2[address+"time"]=i['time']
                        address_dict2[address + "port"]=i['port']
                public.writeFile(path_time, json.dumps(share_ip_info))
                tmpino=[]
                for i in address_dict:
                    if address_dict[i] < 30:continue
                    i2={"address":i,"count":address_dict[i],"time":address_dict2[i+"time"],"port":address_dict2[i+"port"]}
                    tmpino.append(i2)
                if len(tmpino) == 0: return False
                #上报数据
                tmp={"data":tmpino,"ip":local_ip}
                data_infos=self._decode(json.dumps(tmp))
                token='BT-Paneltask_ssh_error_count'+today
                headers = {
                    'User-Agent': 'BT-Panel-2024',
                    'Token': public.Md5(token)
                }
                upload_data={"data":data_infos,"md5":public.Md5(data_infos)}
                import requests
                requests.post(url="https://www.bt.cn/system/api/server_error_count", data=upload_data, headers=headers,timeout=20)
                return True
        except:
            pass

        return False

    def get_ssh_success(self, get):
        """
        @获取SSH登录成功次数
        @param get:
            count :数量
        """
        p = 1
        count = 20
        if 'count' in get: count = int(get['count'])
        if 'p' in get: p = int(get['p'])

        result = []
        min, max = (p - 1) * count, p * count

        log_list = self.get_log_byfile(self.get_ssh_log_files(get)[0], min, max,
                                       self.__get_search_list(get, ['Accepted']))

        for log in log_list:
            data = self.get_ssh_log_line(log['log'], log['time'])
            if not data: continue
            result.append(data)
        if p < 1000000: public.set_module_logs('ssh_log', 'get_ssh_list')
        return public.return_area(result, 'address')

    def __get_search_list(self, get, slist):
        """
        @组合搜索条件
        return list 查询组合
               status 1 增加查询条件
        """
        res = []
        if 'search' in get and get['search'].strip():
            search = get['search'].strip()
            for info in slist:
                res.append(info + '&' + search)
            if len(res) == 0:
                return search
            return res
        return slist

    def __get_system_version(self):
        system_version = public.cache_get("system_version")

        if not system_version:
            try:
                system_version = public.ExecShell("cat /etc/os-release | grep -E 'OpenCloudOS.*9'")[0]
                if system_version:
                    public.cache_set("system_version", system_version, 86400)
            except Exception as e:
                system_version = None

        return system_version

    def get_ssh_log_line(self, log, log_time):
        '''
            @name 获取ssh日志行
            @param log<str> 日志行
            @param log_time<str> 前一条记录的日志时间
        '''
        try:
            ip_rules_file = "data/ssh_deny_ip_rules.json"
            try:
                ip_rules = json.loads(public.readFile(ip_rules_file))
            except Exception:
                ip_rules = []

            tmps = log.replace('  ', ' ').split(' ')
            if len(tmps) < 3:
                return False
            data = {}
            data['time'] = log_time
            # 获取 system_version
            system_version = self.__get_system_version()
            if system_version:
                if log.find('Failed password for invalid user') != -1:
                    data['user'] = tmps[7]
                    data['address'] = tmps[10]
                    data['port'] = tmps[12]
                elif log.find('Connection closed by authenticating') != -1:
                    data['user'] = tmps[8]
                    data['address'] = tmps[9]
                    data['port'] = tmps[11]
                else:
                    data['user'] = tmps[6]
                    data['address'] = tmps[8]
                    data['port'] = tmps[10]
            else:
                if log.find('closed by authenticating user') != -1:
                    data['user'] = tmps[10]
                    data['address'] = tmps[11]
                    data['port'] = tmps[13]
                elif log.find('Failed password for invalid user') != -1:
                    data['user'] = tmps[10]
                    data['address'] = tmps[12]
                    data['port'] = tmps[14]
                else:
                    data['user'] = tmps[8]
                    data['address'] = tmps[10]
                    data['port'] = tmps[12]

            data['status'] = 0
            if log.find('Accepted') >= 0:
                data['status'] = 1

            data["deny_status"] = 1 if data["address"] in ip_rules else 0
            if data["deny_status"] == 0:
                panel_ip_deny = public.M('firewall_ip').field("address").select()
                for i in panel_ip_deny:
                    if i["address"] == data["address"]:
                        data["deny_status"] = 1
                        break

                # 文件内容删除  但是数据库内容还在的清空进行更新
                if not ip_rules and panel_ip_deny:
                    public.M('firewall_ip').where("address=?", (data["address"],)).delete()
                    data["deny_status"] = 0

            return data
        except:
            return False

    # *********************************************** end ssh 收费模块  ******************************************************

    #  获取ssh命令
    def __ssh_commands(self, filename, limit_max, max):
        if filename == 'journalctl':
            commands = [
                "journalctl -u ssh --no-pager --reverse --grep='Accepted' --lines={}".format(max),
                # 筛选登陆失败记录(排除无效尝试)
                "journalctl -u ssh --no-pager --reverse --lines={} --grep='Failed password for' |grep -v 'invalid'".format(max),
                # 筛选预认证阶段关闭的连接
                "journalctl -u ssh --no-pager --reverse --grep='Connection closed by authenticating user|preauth' --lines={}".format(max),
                # 获取全部
                "journalctl -u ssh --no-pager --reverse --grep='Accepted|Failed password for|Connection closed by authenticating user|PAM service(sshd) ignoring max retries' --lines={}".format(max),
            ]
        else:
            commands = [
                "cat {}|grep -a 'Accepted' {} | tac".format(filename, limit_max),  # 登录成功
                "cat {}|grep -a 'sshd\[.*session opened for user' {} | tac".format(filename, limit_max),  # 会话打开
                "cat {}|grep -a 'Failed password for' | grep -v 'invalid' {} | tac".format(filename, limit_max),  # 登录失败
                "cat {}|grep -a 'Connection closed by authenticating user' | grep -a 'preauth' {} | tac".format(filename, limit_max),  # 连接关闭
                "cat {}|grep -a 'PAM service(sshd) ignoring max retries' | grep -a {} | tac".format(filename, limit_max),  # PAM 服务
                # # 获取全部的
                "grep -aE 'Accepted|Failed password for|Connection closed by authenticating user|PAM service(sshd) ignoring max retries' {} {} | tac".format(
                    filename, limit_max),
            ]
        return commands

    # 根据搜索条件过滤命令
    def __filter_commands(self, commands, search, filename):
        if 1 < len(search) < 4:
            # 成功
            if 'Accepted' in search[0]:
                filtered_commands = [commands[0]] if filename == "journalctl" else commands[:2]
            # 失败
            else:
                filtered_commands = commands[1:3] if filename == "journalctl" else commands[2:5]
        else:
            filtered_commands = [commands[3]] if filename == "journalctl" else [commands[5]]
        return filtered_commands

    def get_curr_log_file(self, filename, search, min, max, log_list):
        """
        @name 获取当前日志文件
        @param filename: 日志文件名
        @param search: 搜索条件
        @param min: 最小值
        @param max: 最大值
        @param log_list: 匹配的日志列表
        """
        log_list.clear()
        limit_max = '| tail -n {}'.format(max)
        if len(search) > 0 and search[0].find('&') >= 0: limit_max = ''

        #  获取ssh命令
        command = self.__ssh_commands(filename, limit_max, max)
        # 根据搜索条件过滤命令
        shells = self.__filter_commands(command, search, filename)

        result = []
        for shell in shells:
            res = public.ExecShell(shell)[0].strip()
            if not res: continue
            result.append(res.split("\n"))

        find_idx = 0
        log_time = 0
        limit = max - min

        user_list = self.get_user()
        for log in result:
            if log == "": continue
            for ll in log:
                log_time = self.get_log_pre_time(filename, ll, log_time)
                if len(log_list) >= limit:
                    find_idx += 1
                    break
                if self.__find_line_str(ll, search):
                    find_idx += 1
                    if find_idx > min:
                        ll = public.xssencode2(ll.replace('  ', ' '))
                        # 解决SSH登录日志搜索ip或用户名不准确的情况
                        if type(search) == list and len(search[0].split("&")) > 1:
                            rep_str = search[0].split("&")
                            rep = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
                            re_result = re.search(rep, ll).group()
                            if rep_str[1] in re_result:
                                log_list.append({'log': ll, 'time': log_time})
                            elif rep_str[1] in user_list:
                                log_list.append({'log': ll, 'time': log_time})
                        else:
                            log_list.append({'log': ll, 'time': log_time})
        return find_idx

    def get_sys_datetime(self, pre_time, log_time):
        """
        @name 对比日志时间，日志时间保存年份，日志时间比前一条时间大，则判断为上一年，
        @param pre_time 上一条日志时间
        @param log_time 当前日志时间
        @return 当前日志时间(校准年份)
        """

        if type(log_time) == str:
            log_time = self.__get_to_date(log_time)

        if type(pre_time) == str:
            pre_time = self.__get_to_date(pre_time)

        if (log_time > pre_time and pre_time > 0) or log_time >= time.time():
            d = datetime.datetime.strptime(public.format_date(times=log_time), "%Y-%m-%d %H:%M:%S")
            n_date = self.__get_to_date(
                '{}-{}-{} {}:{}:{}'.format(d.year - 1, d.month, d.day, d.hour, d.minute, d.second))
            return public.format_date(times=n_date)
        if type(log_time) == int:
            return public.format_date(times=log_time)
        return log_time

    def get_log_pre_time(self, log_file, _line, pre_time):
        """
        @name 计算上次日志时间
        @param log_file<str> 日志文件
        @param _line<str> 日志行
        @param pre_time<str> 上次日志时间
        @auther cjxin
        """
        log_time = 0
        if _line[:3] in self._months:
            log_time = self.to_date4(_line[:16].strip())
        elif _line[:2] in ['19', '20', '21', '22']:
            log_time = _line[:19].strip()
        elif log_file.find('alternatives') >= 0:
            _tmp = _line.split(": ")
            _last = _tmp[0].split(" ")
            log_time = ' '.join(_last[1:]).strip()

        log_time = self.get_sys_datetime(pre_time, log_time)
        return log_time

    def get_user(self):
        '''
        @name 获取系统用户名
        :return:
        '''
        pass_file = public.readFile("/etc/passwd")
        pass_file = pass_file.split('\n')
        user_list = []
        for p in pass_file:
            p = p.split(':', 1)
            user_list.append(p[0])
        return user_list

    def get_log_byfile(self, sfile, min_num, max_num, search=None):
        """
        @name 获取日志文件的日志
        @param sfile:日志文件
        @param min_num:起始行数
        @param max_num:结束行数
        @param search:搜索关键字
        """
        log_list = []
        h_find = None

        # 系统ubuntu22 debian12 通过journalctl获取
        if self.is_debain_12():
            h_find = {'log_file': 'journalctl', "list": [], 'uptime': time.time(), 'title': '授权日志', 'size': 10000}

        else:
            # 获取归档文件列表
            for info in self.get_sys_logfiles(None):
                if info['log_file'] == sfile:
                    h_find = info
                    break

        if not h_find:
            return log_list

        # 获取遍历文件列表
        file_list = [h_find['log_file']]
        for info in h_find['list']:
            file_list.append(info['log_file'])
        find_idx = 0
        log_time = 0
        limit = max_num - min_num
        user_list = self.get_user()
        for filename in file_list:
            # 处理最新文件
            if filename in ['/var/log/secure', '/var/log/auth.log', 'journalctl'] and search:
                find_idx = self.get_curr_log_file(filename, search, min_num, max_num, log_list)
                continue
            if not os.path.exists(filename): continue

            p = 0  # 分页计数器
            next_file = False
            sfile = filename
            if filename[-3:] in ['.gz', '.xz']: sfile = sfile[:-3]
            check_file, is_cache = self.__check_other_search(filename, search)
            if check_file:
                cache_path = '{}/data/ssh/{}{}'.format(public.get_panel_path(), os.path.basename(sfile), check_file)
                if not os.path.exists(cache_path):
                    self.__set_ssh_log(filename, check_file)
                filename = cache_path
            # 数据不够，则解压归档文件进行查询
            if filename[-3:] in ['.gz', '.xz']:
                public.ExecShell("gunzip -c " + filename + " > " + filename[:-3])
                filename = filename[:-3]
            while not next_file:
                if not os.path.exists(filename): continue  # 文件不存在？
                if len(log_list) >= limit or os.path.getsize(filename) == 0:
                    break
                p += 1

                # 每次读取10000行，不足10000行跳转下个文件
                result = self.GetNumLines(filename, 10001, p, search).split("\n")
                if len(result) < 10000:
                    next_file = True
                result.reverse()
                for _line in result:
                    if not _line.strip(): continue

                    log_time = self.get_log_pre_time(filename, _line, log_time)
                    # 处理搜索关键词
                    is_search = False
                    if self.__find_line_str(_line, search):
                        is_search = True

                    # 读取数量超过最大值，跳出
                    if len(log_list) >= limit:
                        break

                    if is_search:
                        find_idx += 1
                        if find_idx > min_num:
                            _line = public.xssencode2(_line.replace('  ', ' '))
                            # 解决SSH登录日志搜索ip或用户名不准确的情况
                            if type(search) == list and len(search[0].split("&")) > 1:
                                rep_str = search[0].split("&")
                                rep = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
                                match = re.search(rep, _line)
                                re_result= match.group() if match else ""
                                # re_result = re.search(rep, _line).group()
                                if rep_str[1] in re_result:
                                    log_list.append({'log': _line, 'time': log_time})
                                elif rep_str[1] in user_list:
                                    log_list.append({'log': _line, 'time': log_time})
                            else:
                                log_list.append({'log': _line, 'time': log_time})

        return log_list

    def __set_ssh_log(self, filename, check_file):
        """
        @name 缓存SSH登录日志
        @param filename<str> 缓存文件
        @param check_file<list> 文件类型
        """

        cache_path = '{}/data/ssh/{}{}'.format(public.get_panel_path(), os.path.basename(filename), check_file)

        if check_file == '_success':
            if filename == "journalctl":
                shell = "journalctl  -u ssh --no-pager|grep -a 'Accepted'"
            else:
                shell = "cat {}|grep -a 'Accepted'".format(filename)
        elif check_file == '_error':
            if filename == "journalctl":
                shell = "journalctl  -u ssh --no-pager|grep -E 'Failed password for|Connection closed by authenticating user' |grep -v 'invalid'"
            else:
                shell = "cat {}|grep -E 'Failed password for|Connection closed by authenticating user' |grep -v 'invalid'".format(
                    filename)
        else:
            if filename == "journalctl":
                shell = "journalctl  -u ssh --no-pager|grep -E 'Failed password for|Accepted|Connection closed by authenticating user' |grep -v 'invalid'"
            else:
                shell = "cat {}|grep -E 'Failed password for|Accepted|Connection closed by authenticating user' |grep -v 'invalid'".format(
                    filename)

        if not os.path.exists(cache_path):
            res = public.ExecShell(shell)[0]
            public.writeFile(cache_path, res)
        return True

    def __check_other_search(self, filename, search):
        """
        @检测是否需要缓存ssh登录日志
        @filename<str> 文件名
        @search<str> 搜索关键字
        """
        if not search: return False, False
        if filename.find('secure-') >= 0 or filename.find('auth.log.') >= 0:
            res = search
            if type(search) == list:
                res = ' '.join(search)

            is_cache = False
            if res.find('&') == -1: is_cache = True

            if len(search) == 3:
                return '_all', is_cache
            if search[0].find('Accepted') >= 0:
                return '_success', is_cache
            return '_error', is_cache
        return False, False

    def __find_line_str(self, __line, find_str):
        """
        @ 批量搜索文件
        @ __line<str> 文件行
        @ find_str<str> 搜索关键字
        """
        if type(find_str) == list:
            if len(find_str) == 0:
                return True
            for search in ['Accepted', 'Failed password for', 'Connection closed by authenticating user', 'sshd[.*session opened for user', 'PAM service(sshd) ignoring max retries']:
                if __line.find(search) != -1:
                    return True
            else:
                return False
        else:
            if find_str:
                return self.__find_str(__line, find_str.strip())
            return True

    def __find_str(self, _line, find_str):
        """
        @查找关键词
        @_line<str> 文件行
        @find_str<str> 搜索关键字
        """
        is_num = 0
        slist = find_str.split("&")
        for search in slist:
            if search == 'Failed password for':
                # 兼容多个系统的登录失败
                if _line.find(search) >= 0 and _line.find('invalid') == -1:
                    is_num += 1
                elif _line.find('Connection closed by authenticating user') >= 0 and _line.find(
                        'preauth') >= 0:  # debian系统使用宝塔SSH终端登录失败
                    is_num += 1
                elif _line.find('Connection closed by') >= 0 and _line.find('preauth') >= 0:
                    is_num += 1
            else:
                if _line.find(search) >= 0:
                    is_num += 1

        if is_num == len(slist):
            return True
        return False

    def get_log_title(self, log_name):
        '''
            @name 获取日志标题
            @author hwliang<2021-09-03>
            @param log_name<string> 日志名称
            @return <string> 日志标题
        '''
        log_name = log_name.replace('.1', '')
        if log_name in ['auth.log', 'secure'] or log_name.find('auth.') == 0:
            return '授权日志'
        if log_name in ['dmesg'] or log_name.find('dmesg') == 0:
            return '内核缓冲区日志'
        if log_name in ['syslog'] or log_name.find('syslog') == 0:
            return '系统警告/错误日志'
        if log_name in ['btmp']:
            return '失败的登录记录'
        if log_name in ['utmp', 'wtmp']:
            return '登录和重启记录'
        if log_name in ['lastlog']:
            return '用户最后登录'
        if log_name in ['yum.log']:
            return 'yum包管理器日志'
        if log_name in ['anaconda.log']:
            return 'Anaconda日志'
        if log_name in ['dpkg.log']:
            return 'dpkg日志'
        if log_name in ['daemon.log']:
            return '系统后台守护进程日志'
        if log_name in ['boot.log']:
            return '启动日志'
        if log_name in ['kern.log']:
            return '内核日志'
        if log_name in ['maillog', 'mail.log']:
            return '邮件日志'
        if log_name.find('Xorg') == 0:
            return 'Xorg日志'
        if log_name in ['cron.log']:
            return '定时任务日志'
        if log_name in ['alternatives.log']:
            return '更新替代信息'
        if log_name in ['debug']:
            return '调试信息'
        if log_name.find('apt') == 0:
            return 'apt-get相关日志'
        if log_name.find('installer') == 0:
            return '系统安装相关日志'
        if log_name in ['messages']:
            return '综合日志'
        return '{}日志'.format(log_name.split('.')[0])

    def get_history_filename(self, filepath):
        '''
        @name 获取归档文件名称
        @filepath<string> 文件路径
        '''
        log_name = os.path.basename(filepath)

        # 归档压缩文件,auth.log.1.gz
        if filepath[-3:] in ['.gz', '.xz']:
            log_file = filepath[:-3]
            if os.path.exists(log_file):
                return False
            log_name = os.path.basename(log_file)

        # 处理auth.log-20221024
        if re.search('-(\d{8})', log_name):
            arrs = log_name.split('-')
            arrs = arrs[0: len(arrs) - 1]
            return '-'.join(arrs)
        # 处理auth.log.1
        if re.search('.\d{1,10}$', log_name):
            arrs = log_name.split('.')
            arrs = arrs[0: len(arrs) - 1]
            return '.'.join(arrs)
        return log_name

    def is_debain_12(self):
        try:
            if os.path.exists('/etc/os-release'):
                f = public.readFile('/etc/os-release')
                f = f.split('\n')
                ID = ''
                VERSION_ID = 0
                for line in f:
                    if line.startswith('VERSION_ID'):
                        VERSION_ID = int(line.split('=')[1].split('.')[0].strip('"'))
                    if line.startswith('ID'):
                        if ID != '': continue
                        ID = line.strip().split('=')[1].strip('"')
                        try:
                            ID = ID.split('.')[0]
                        except:
                            pass
                if (ID.lower() == 'debian' and VERSION_ID >= 12) or (ID.lower() == 'ubuntu' and VERSION_ID >= 22):
                    return True
                return False
        except:
            return False

    def get_sys_logfiles(self, get):
        '''
            @name 获取系统日志文件列表
            @author hwliang<2021-09-02>
            @param get<dict_obj>
            @return list
        '''
        res = {}
        log_dir = '/var/log'

        # debian Ubuntu22 系统日志
        name_list = [
            'kern.log', 'mail.log', 'auth.log', 'lastlog', 'dpkg.log',
            'btmp', 'alternatives.log', 'daemon.log',
            'boot.log', 'syslog', 'wtmp', 'debug.log', 'cron.log', 'apt', "installer"
        ]
        #  日志文件映射
        map_data = {
            'lastlog': '/var/log/lastlog',  # 系统用户登录记录
            'btmp': '/var/log/btmp',  # 登录失败记录
            'wtmp': '/var/log/wtmp',  # 用户列表登陆信息
        }

        if self.is_debain_12():
            # 处理预定义日志
            for name in name_list:
                log_path = map_data.get(name, "/var/log/{}".format(name))
                if name == "apt":
                    log_path = "/var/log/apt/term.log"
                if name == "installer":
                    log_path = "/var/log/installer/syslog"
                # 获取日志文件大小
                try:
                    size = os.path.getsize(log_path)
                except:
                    size = '未知大小'

                log_name = name
                res[log_name] = {
                    'name': log_name,
                    'log_file': map_data.get(log_name, log_name),
                    'size': size,
                    'title': self.get_log_title(log_name),
                    'uptime': '',
                    'list': [],
                }

        # 遍历 /var/log
        for log_file in os.listdir(log_dir):
            if log_file in ['.', '..', 'faillog', 'fontconfig.log', 'unattended-upgrades', 'tallylog']: continue
            extensions = ('.zip', '.tar', '.tar.gz', '.tar.bz2', 'gz', 'xz', 'bz2', 'zip')
            # 跳过压缩文件
            if log_file.endswith(extensions): continue
            filename = os.path.join(log_dir, log_file)
            # 文件不存在
            if not os.path.exists(filename): continue
            # 路径是文件的情况 进行处理
            if os.path.isfile(filename):
                # 归档文件原名
                log_name = self.get_history_filename(filename)
                if not log_name: continue

                if not log_name in res:
                    filepath = os.path.join(log_dir, log_name)
                    if not os.path.exists(filepath): continue

                    res[log_name] = {
                        'name': log_name,
                        'log_file': filepath,
                        'size': os.path.getsize(filepath),
                        'title': self.get_log_title(log_name),
                        'uptime': os.path.getmtime(filepath),
                        'list': [],
                    }

                if log_name != log_file:
                    res[log_name]['list'].append({
                        'name': log_file,
                        'size': os.path.getsize(filename),
                        'uptime': os.path.getmtime(filename),
                        'log_file': filename
                    })
            else:
                # filename 是目录的情况 拿子目录下的日志文件
                for next_name in os.listdir(filename):
                    next_file = os.path.join(filename, next_name)
                    if not os.path.isfile(next_file): continue
                    log_name = self.get_history_filename(next_file)
                    if not log_name: continue

                    if not log_name in res:
                        filepath = os.path.join(filename, log_name)
                        if not os.path.exists(filepath): continue

                        res[log_name] = {
                            'name': log_name,
                            'log_file': filepath,
                            'size': os.path.getsize(filepath),
                            'title': self.get_log_title(log_name),
                            'uptime': os.path.getmtime(filepath),
                            'list': [],
                        }

                    if log_name != next_name:
                        res[log_name]['list'].append({
                            'name': next_name,
                            'size': os.path.getsize(next_file),
                            'uptime': os.path.getmtime(next_file),
                            'log_file': next_file
                        })
        # 排序并返回结果
        for key in res:
            res[key]['list'] = sorted(res[key]['list'], key=lambda x: x['name'], reverse=True)
        log_files = sorted(res.values(), key=lambda x: x['name'], reverse=True)
        return log_files

    def get_lastlog(self, get):
        '''
            @name 获取lastlog日志
            @author hwliang<2021-09-02>
            @param get<dict_obj>
            @return list
        '''
        cmd = '''LANG=en_US.UTF-8
lastlog|grep -v Username'''
        result = public.ExecShell(cmd)
        lastlog_list = []

        p = int(get.get('p', 1))
        count = int(get.get('count', 10))
        search = get.get('search', '')

        idx = 0
        min_idx = (p - 1) * count
        max_idx = p * count
        for _line in result[0].strip().split("\n"):
            if not _line: continue
            if search and _line.find(search) == -1: continue
            _line = public.xssencode2(_line)
            tmp = {}
            sp_arr = _line.split()
            if len(sp_arr) < 4: continue
            tmp['用户'] = sp_arr[0]
            # tmp['_line'] = _line
            if _line.find('Never logged in') != -1:
                tmp['最后登录时间'] = '0'
                tmp['最后登录来源'] = '-'
                tmp['最后登录端口'] = '-'

            else:
                tmp['最后登录来源'] = sp_arr[2]
                tmp['最后登录端口'] = sp_arr[1]
                tmp['最后登录时间'] = self.to_date2(' '.join(sp_arr[3:]))

            if min_idx <= idx < max_idx:
                lastlog_list.append(tmp)

            idx += 1
        lastlog_list = sorted(lastlog_list, key=lambda x: x['最后登录时间'], reverse=True)
        for i in range(len(lastlog_list)):
            if lastlog_list[i]['最后登录时间'] == '0': lastlog_list[i]['最后登录时间'] = '从未登录过'

        return {"data": lastlog_list, "total": idx}

    def get_last(self, get):
        '''
            @name 获取用户会话日志
            @author hwliang<2021-09-02>
            @param get<dict_obj>
            @return list
        '''
        cmd = '''LANG=en_US.UTF-8
last -n 1000 -x -f {}|grep -v 127.0.0.1|grep -v " begins"'''.format(get.log_name)
        result = public.ExecShell(cmd)
        lastlog_list = []

        search = get.get('search', '')
        p = int(get.get('p', 1))
        count = int(get.get('count', 10))

        idx = 0
        min_idx = (p - 1) * count
        max_idx = p * count

        for _line in result[0].strip().split("\n"):
            if not _line:
                continue
            if search and _line.find(search) == -1:
                continue
            _line = public.xssencode2(_line)
            tmp = {}
            sp_arr = _line.split()

            tmp['用户'] = sp_arr[0]
            if sp_arr[0] == 'runlevel':
                tmp['来源'] = sp_arr[4]
                tmp['端口'] = ' '.join(sp_arr[1:4])
                tmp['时间'] = self.to_date3(' '.join(sp_arr[5:])) + ' ' + ' '.join(sp_arr[-2:])
            elif sp_arr[0] in ['reboot', 'shutdown']:
                tmp['来源'] = sp_arr[3]
                tmp['端口'] = ' '.join(sp_arr[1:3])
                if sp_arr[-3] == '-':
                    tmp['时间'] = self.to_date3(' '.join(sp_arr[4:])) + ' ' + ' '.join(sp_arr[-3:])
                else:
                    tmp['时间'] = self.to_date3(' '.join(sp_arr[4:])) + ' ' + ' '.join(sp_arr[-2:])
            elif sp_arr[1] in ['tty1', 'tty', 'tty2', 'tty3', 'hvc0', 'hvc1', 'hvc2'] or len(sp_arr) == 9:
                tmp['来源'] = ''
                tmp['端口'] = sp_arr[1]
                tmp['时间'] = self.to_date3(' '.join(sp_arr[2:])) + ' ' + ' '.join(sp_arr[-3:])
            else:
                tmp['来源'] = sp_arr[2]
                tmp['端口'] = sp_arr[1]
                tmp['时间'] = self.to_date3(' '.join(sp_arr[3:])) + ' ' + ' '.join(sp_arr[-3:])
            if min_idx <= idx < max_idx:
                lastlog_list.append(tmp)
            idx += 1
        return {"data": lastlog_list, "total": idx}

    def __get_to_date(self, times):
        """
        日期转时间戳
        """
        try:
            return int(time.mktime(time.strptime(times, "%Y-%m-%d %H:%M:%S")))
        except:
            try:
                return int(time.mktime(time.strptime(times, "%Y/%m/%d %H:%M:%S")))
            except:
                return 0

    def get_sys_log(self, get):
        '''
            @name  获取指定系统日志
            @author hwliang<2021-09-02>
            @param get<dict_obj>
            @return list
        '''

        log_file = get.log_name
        p, limit, search = 1, 5, ''
        if 'p' in get: p = int(get.p)
        if 'limit' in get: limit = int(get.limit)
        if 'search' in get: search = get.search

        # 日志文件不存在 符合指定系统
        if (not os.path.exists(log_file)) and log_file.find('/') == -1 and self.is_debain_12():
            limit = 1000 if search else 200
            # 通过journalctl获取日志
            name = log_file.split('.')[0]

            journalctl_commands = {
                'debug': 'journalctl --no-pager -p debug -n {}'.format(limit),
                'boot': 'journalctl --no-pager -b -n {}'.format(limit),
                'dpkg': 'tail -n {} /var/log/dpkg.log'.format(limit),
                'alternatives': 'tail -n {} /var/log/alternatives.log'.format(limit),
                'apt': 'tail -n {} /var/log/apt/term.log'.format(limit),
                'installer': 'tail -n {} /var/log/installer/syslog'.format(limit)
            }

            command_template = journalctl_commands.get(name, 'journalctl --no-pager --facility={} -n {}')
            command = command_template.format(name, limit) if name not in journalctl_commands else command_template.format(limit)

            if search:
                command += ' | grep -i {}'.format(search.strip())

            res = public.ExecShell(command)[0]

            return public.xssencode2(res.strip()).split('\n')

        sfile_name = os.path.basename(get.log_name)
        # utmp wtmp 登陆和重启记录 btmp 登陆失败记录
        if sfile_name in ['wtmp', 'btmp', 'utmp']:
            return self.get_last(get)

        # 获取用户最后登录记录
        if sfile_name in ['lastlog']:
            return self.get_lastlog(get)

        if get.log_name.find('sa/sa') >= 0:
            if get.log_name.find('sa/sar') == -1:
                command = "sar -f /var/log/{}".format(get.log_name)
                if search:
                    command += ' | grep -i {}'.format(search.strip())
                res = public.ExecShell(command)[0]
                return public.xssencode2(res)

        if os.path.exists(log_file) and self.is_debain_12():
            limit = 1000 if search else 200
            command = 'tail -n {} {}'.format(limit, log_file)
            if search:
                command += ' | grep -i {}'.format(search.strip())
            res = public.ExecShell(command)[0]
            return public.xssencode2(res.strip()).split('\n')

        is_string = True
        result = []
        min_idx, max_idx = (p - 1) * limit, p * limit  # 最小值，最大值
        # 获取位置文件的日志内容
        log_list = self.get_log_byfile(log_file, min_idx, max_idx, search)

        # 日志不存在或者为空等
        if not log_list: is_string = False
        # 遍历构造返回内容
        for info in log_list:
            _line = info['log']
            if _line[:3] in self._months:
                _tmps = _line.split(' ')
                _msg = ' '.join(_tmps[3:])
                _tmp = _msg.split(": ")
                _act = ''
                if len(_tmp) > 1:
                    _act = _tmp[0]
                    _msg = _tmp[1]
                else:
                    _msg = _tmp[0]
                _line = {"时间": info['time'], "角色": _act, "事件": _msg}
                is_string = False
            elif _line[:2] in ['19', '20', '21', '22']:
                _msg = _line[19:]
                _tmp = _msg.split(" ")
                _act = _tmp[1]
                _msg = ' '.join(_tmp[2:])
                _line = {"时间": info['time'], "角色": _act, "事件": _msg}
                is_string = False
            elif log_file.find('alternatives') >= 0:
                _tmp = _line.split(": ")
                _last = _tmp[0].split(" ")
                _act = _last[0]
                _msg = ' '.join(_tmp[1:])
                _line = {"时间": info['time'], "角色": _act, "事件": _msg}
                is_string = False
            else:
                if not is_string:
                    if type(_line) != dict: continue
            result.append(_line)

        # 字符串返回 固定200行
        str_list = []
        if is_string:
            min_idx, max_idx = (p - 1) * 200, p * 200  # 最小值，最大值
            log_list = self.get_log_byfile(log_file, min_idx, max_idx, search)
            for info in log_list:
                _line = info['log']
                str_list.append(_line)
            return str_list

        public.set_module_logs('sys_log', 'get_sys_log')
        try:
            _string = []
            _dict = []
            _list = []

            for _line in result:
                if isinstance(_line, str):
                    _string.append(_line.strip())
                elif isinstance(_line, dict):
                    _dict.append(_line)
                elif isinstance(_line, list):
                    for item in _line:
                        if isinstance(item, list):
                            _list.extend(item)
                        else:
                            _list.append(item)
                else:
                    continue

            _str_len = len(_string)
            _dict_len = len(_dict)
            _list_len = len(_list)
            if _str_len >= _dict_len + _list_len:
                return _string
            elif _dict_len >= _str_len + _list_len:
                return {"data": _dict, "total": _dict_len}
            else:
                return _list

        except Exception as e:
            return '\n'.join(result)

    # 取文件指定尾行数
    def GetNumLines(self, path, num, p=1, search=None):
        pyVersion = sys.version_info[0]
        max_len = 1024 * 1024 * 2
        try:
            from cgi import html
            if not os.path.exists(path): return ""
            start_line = (p - 1) * num
            count = start_line + num
            fp = open(path, 'rb')
            buf = ""
            fp.seek(-1, 2)
            if fp.read(1) == "\n": fp.seek(-1, 2)
            data = []
            total_len = 0
            b = True
            n = 0
            for i in range(count):
                while True:
                    newline_pos = str.rfind(str(buf), "\n")
                    pos = fp.tell()
                    if newline_pos != -1:
                        if n >= start_line:
                            line = buf[newline_pos + 1:]

                            is_res = True
                            if search:
                                is_res = False
                                if isinstance(search, list):
                                    for str_search in search:
                                        if line.find(str_search) >= 0 or re.search(str_search, line):
                                            is_res = True
                                else:
                                    if line.find(search) >= 0 or re.search(search, line):
                                        is_res = True

                            if is_res:
                                line_len = len(line)
                                total_len += line_len
                                sp_len = total_len - max_len
                                if sp_len > 0:
                                    line = line[sp_len:]
                                try:
                                    data.insert(0, line)
                                except:
                                    pass
                        buf = buf[:newline_pos]
                        n += 1
                        break
                    else:
                        if pos == 0:
                            b = False
                            break
                        to_read = min(4096, pos)
                        fp.seek(-to_read, 1)
                        t_buf = fp.read(to_read)
                        if pyVersion == 3:
                            t_buf = t_buf.decode('utf-8')

                        buf = t_buf + buf
                        fp.seek(-to_read, 1)
                        if pos - to_read == 0:
                            buf = "\n" + buf
                    if total_len >= max_len: break
                if not b: break
            fp.close()
            result = "\n".join(data)
            if not result: raise Exception('null')
        except:
            result = public.ExecShell("tail -n {} {}".format(num, path))[0]
            if len(result) > max_len:
                result = result[-max_len:]

        try:
            try:
                result = json.dumps(result)
                return json.loads(result).strip()
            except:
                if pyVersion == 2:
                    result = result.decode('utf8', errors='ignore')
                else:
                    result = result.encode('utf-8', errors='ignore').decode("utf-8", errors="ignore")
            return result.strip()
        except:
            return ""

    def export_ssh_log(self, get):
        """
        @获取SSH登录
        @param get:
            count :数量
        """
        select_pl = ['Accepted', 'Failed password for', 'Connection closed by authenticating user']
        if hasattr(get, 'select'):
            if get.select == "Accepted":
                select_pl = ['Accepted']
            elif get.select == "Failed":
                select_pl = ['Failed password for', 'Connection closed by authenticating user']

        p = 1
        count = 200
        if 'count' in get:
            count = int(get['count'])
        if 'p' in get:
            p = int(get['p'])

        result = []
        min_idx, max_idx = (p - 1) * count, p * count
        log_list = self.get_log_byfile(self.get_ssh_log_files(get)[0], min_idx, max_idx,
                                       self.__get_search_list(get, select_pl))
        for log in log_list:
            data = self.get_ssh_log_line(log['log'], log['time'])
            if not data:
                continue
            result.append(data)

        result_data = public.return_area(result, 'address')

        tmp_logs_path = "/tmp/export_ssh_log"
        if not os.path.exists(tmp_logs_path):
            os.makedirs(tmp_logs_path, 0o600)
        tmp_logs_file = "{}/ssh_log_{}.csv".format(tmp_logs_path, int(time.time()))

        with open(tmp_logs_file, mode="w+", encoding="utf-8") as fp:
            fp.write("IP地址,端口,归属地,用户,状态,操作时间\n")
            for line in result_data:
                tmp = (
                    line["address"],
                    line["port"],
                    line["area"].get("info", ""),
                    line["user"],
                    "登录成功" if int(line["status"]) == 1 else "登录失败",
                    line["time"],
                )
                fp.write(",".join(tmp))
                fp.write("\n")
        return {
            "status": True,
            "output_file": tmp_logs_file,
        }

    @staticmethod
    def clear_export_log(get=None):
        tmp_logs_path = "/tmp/export_ssh_log"
        if not os.path.exists(tmp_logs_path):
            return public.returnMsg(True, '没有可清理的冗余日志')
        shutil.rmtree(tmp_logs_path)
        return public.returnMsg(True, '没有清理成功')
