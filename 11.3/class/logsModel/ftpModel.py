# coding: utf-8
#  + -------------------------------------------------------------------
# | 宝塔Linux面板
#  + -------------------------------------------------------------------
# | Copyright (c) 2015-2016 宝塔软件(http:#bt.cn) All rights reserved.
#  + -------------------------------------------------------------------
# | Author: hezhihong <272267659@@qq.cn>
#  + -------------------------------------------------------------------
import json
import traceback
import sys
import datetime
from collections import defaultdict

if not '/www/server/panel/class/' in sys.path:
    sys.path.insert(0, '/www/server/panel/class/')
import public, os, time
from logsModel.base import logsBase
import datetime
import crontab
import re

try:
    from BTPanel import session
except:
    pass
# 英文转月份缩写
month_list = {
    "Jan": "1",
    "Feb": "2",
    "Mar": "3",
    "Apr": "4",
    "May": "5",
    "Jun": "6",
    "Jul": "7",
    "Aug": "8",
    "Sept": "9",
    "Sep": "9",
    "Oct": "10",
    "Nov": "11",
    "Dec": "12"
}


class main(logsBase):
    analysis_config_path = '/www/server/panel/data/analysis_config.json'
    white_list_path = '/www/server/panel/data/ftp_white_list.json'
    _time_regex = re.compile(r"((Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec|\d+)([-/]|\s+)){2,3}[\sT]?(\d+:){2}\d+")

    def __init__(self):
        self.__messages_file = "/var/log/"
        self.__ftp_backup_path = public.get_backup_path() + '/pure-ftpd/'
        if not os.path.isdir(self.__ftp_backup_path):
            public.ExecShell('mkdir -p {}'.format(self.__ftp_backup_path))
        self.__script_py = public.get_panel_path() + '/script/ftplogs_cut.py'
        self.white_list = self.get_white_list(None)

    def get_file_list(self, path, is_bakcup=False):
        """
        @name 取所有messages日志文件
        @param path: 日志文件路径
        @return: 返回日志文件列表
        """
        files = os.listdir(path)
        if is_bakcup:
            file_name_list = [{
                "file": "/var/log/pure-ftpd.log",
                "time": int(time.time())
            }]
        else:
            file_name_list = []
        for i in files:
            tmp_dict = {}
            if not i: continue
            file_path = path + i
            tmp_dict['file'] = file_path
            if is_bakcup:
                if os.path.isfile(file_path) and i.find('pure-ftpd.log') != -1:
                    tmp_dict['time'] = int(
                        public.to_date(
                            times=os.path.basename(file_path).split('_')[0] +
                                  ' 00:00:00'))
                    file_name_list.append(tmp_dict)
            else:
                if os.path.isfile(file_path) and i.find('messages') != -1:
                    tmp_dict['time'] = int(
                        public.to_date(
                            times=os.path.basename(file_path).split('-')[1] +
                                  ' 00:00:00'))
                    file_name_list.append(tmp_dict)
        file_name_list = sorted(file_name_list,
                                key=lambda x: x['time'],
                                reverse=False)
        return file_name_list

    def set_ftp_log(self, get):
        """
        @name 开启、关闭、获取日志状态
        @author hezhihong
        @param get.exec_name 执行的动作
        """
        if not hasattr(get, 'exec_name'):
            return public.returnMsg(False, '参数不正确！')
        conf_path = '/etc/rsyslog.conf'
        conf = public.readFile(conf_path)
        if not os.path.exists(conf_path) or conf is False:
            return public.returnMsg(False, 'rsyslog配置文件不存在！\n请检查rsyslog是否安装或/ect/rsyslog.conf是否存在！\n若未安装<br>debain系统请执行：apt-get install rsyslog\n<br>centos系统请执行：yum install rsyslog')
        import re
        search_str = r"ftp\.\*.*\t*.*\t*.*-/var/log/pure-ftpd.log"
        search_str_two = "ftp.none"
        rep_str = '\nftp.*\t\t-/var/log/pure-ftpd.log\n'
        if not isinstance(conf, str):
            return public.returnMsg(False, '读取配置文件时有误。')
        result = re.search(search_str, conf)
        other_status = True if self.is_debian_12() else False
        # 获取日志状态
        if get.exec_name == 'getlog':
            public.print_log(result)
            if result:
                return_result = 'start'
            else:
                return_result = 'stop'
            return public.returnMsg(True, return_result)
        # 开启日志审计
        elif get.exec_name == 'start':
            # 配置文件配置写坏
            if conf.count('ftp.none') > 5 and other_status:
                conf = '''
# /etc/rsyslog.conf configuration file for rsyslog
#
# For more information install rsyslog-doc and see
# /usr/share/doc/rsyslog-doc/html/configuration/index.html


#################
#### MODULES ####
#################

module(load="imuxsock") # provides support for local system logging
module(load="imklog")   # provides kernel logging support
#module(load="immark")  # provides --MARK-- message capability

# provides UDP syslog reception
#module(load="imudp")
#input(type="imudp" port="514")

# provides TCP syslog reception
#module(load="imtcp")
#input(type="imtcp" port="514")


###########################
#### GLOBAL DIRECTIVES ####
###########################

#
# Set the default permissions for all log files.
#
$FileOwner root
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0755
$Umask 0022

#
# Where to place spool and state files
#
$WorkDirectory /var/spool/rsyslog

#
# Include all config files in /etc/rsyslog.d/
#
$IncludeConfig /etc/rsyslog.d/*.conf


###############
#### RULES ####
###############

#
# Log anything besides private authentication messages to a single log file
#
*.*;auth,authpriv.none		-/var/log/syslog

#
# Log commonly used facilities to their own log file
#
auth,authpriv.*			/var/log/auth.log
cron.*				-/var/log/cron.log
kern.*				-/var/log/kern.log
mail.*				-/var/log/mail.log
user.*				-/var/log/user.log

#
# Emergencies are sent to everybody logged in.
#
*.emerg				:omusrmsg:*            
'''
                public.writeFile(conf_path, conf)
                return self.set_ftp_log(get)

            if result:
                conf = conf.replace(search_str, rep_str)
            else:
                conf += rep_str
            if not other_status:
                # 禁止ftp日志写入/var/log/messages
                d_conf = conf[conf.rfind('info;'):]
                d_conf = d_conf[:d_conf.find('/')]
                s_conf = d_conf.replace(',', ';')
                if s_conf.find(search_str_two) == -1:
                    str_index = s_conf.rfind(';')
                    s_conf = s_conf[:str_index +
                                     1] + search_str_two + s_conf[str_index + 1:]
                    conf = conf.replace(d_conf, s_conf)
            self.add_crontab()
        # 关闭日志审计
        elif get.exec_name == 'stop':
            if result:
                conf = re.sub(search_str, '', conf)
            if not other_status:
                # 取消禁止ftp日志写入/var/log/messages
                if conf.find(search_str_two) != -1:
                    conf = conf.replace(search_str_two, '')
                    for i in [';;', ',,', ';,', ',;']:
                        if conf.find(i) != -1: conf = conf.replace(i, '')
            self.del_crontab()
        public.writeFile(conf_path, conf)
        public.ExecShell('systemctl restart rsyslog')
        return public.returnMsg(True, '设置成功')

    def get_format_time(self, englist_time):
        """
        @name 时间英文转换
        """
        chinanese_time = ''
        try:
            for i in month_list.keys():
                if i in englist_time:
                    tmp_time = englist_time.replace(i, month_list[i])
                    tmp_time = tmp_time.split()
                    chinanese_time = '{}-{} {}'.format(tmp_time[0], tmp_time[1],
                                                       tmp_time[2])
                    break
            return chinanese_time
        except:
            return chinanese_time

    def get_login_log(self, get):
        """
        @name 取登录日志
        @author hezhihong
        @param get.user_name ftp用户名
        return
        """
        search_str = 'pure-ftpd'
        if not hasattr(get, 'user_name'):
            return public.returnMsg(False, '参数不正确！')
        args = public.dict_obj()
        args.exec_name = 'getlog'
        file_name = self.__ftp_backup_path
        is_backup = True
        other_status = True if self.is_debian_12() else False
        if self.set_ftp_log(get) == 'stop':
            file_name = self.__messages_file
            is_backup = False

        # 取所有messages日志文件
        file_list = self.get_file_list(file_name, is_backup)
        sortid = 0
        tmp_dict = {}
        login_all = []
        for file in file_list:
            if not os.path.isfile(file['file']):
                continue
            conf = public.readFile(file['file'])

            # 过滤日志文件  过滤掉不需要的行，保留重要的登录和认证相关的日志
            lines = [
                line for line in conf.strip().split('\n')
                if 'pure-ftpd' in line and
                   (
                       '?@' not in line or
                       ' is now logged in' in line or
                       'Authentication failed for user' in line
                   )
            ]
            for line in lines:
                if not line or search_str not in line:
                    continue
                login_info = {}
                tmp_value = ' is now logged in'
                info = line[:line.find(search_str)].strip()
                try:
                    if other_status:
                        exec_time = datetime.datetime.fromisoformat(info.split(" ")[0].split(".")[0])
                        exec_time = exec_time.strftime('%-m-%d %H:%M:%S')
                    else:
                        hostname = info.split()[-1]
                        exec_time = info.split(hostname)[0].strip()
                        exec_time = self.get_format_time(exec_time)
                except:
                    continue

                user_ip_part = line[line.find('(') + 1:line.find(')')]
                if '@' in user_ip_part:
                    user, ip = user_ip_part.split('@')
                else:
                    continue

                # 取登录成功日志
                if tmp_value in line:
                    user = line.split(tmp_value)[0].strip().split()[-1]
                    if user == '?' or user != get.user_name:
                        continue
                    dict_index = '{}__{}'.format(user, ip)
                    if dict_index not in tmp_dict:
                        tmp_dict[dict_index] = []
                    tmp_dict[dict_index].append(exec_time)

                # 取登出日志
                tmp_value = '[INFO] Logout.'
                tmp_value_two = 'Timeout - try typing a little faster next time'
                if tmp_value in line or tmp_value_two in line:
                    user = line[line.find('(') + 1:line.find(')')].split('@')[0]
                    if user == '?' or user != get.user_name:
                        continue
                    dict_index = '{}__{}'.format(user, ip)
                    try:
                        login_info['out_time'] = exec_time
                        login_info['in_time'] = tmp_dict[dict_index][0]
                        login_info['user'] = user
                        login_info['ip'] = ip
                        login_info['status'] = '登录成功'  # 0为登录失败，1为登录成功
                        login_info['sortid'] = sortid
                        login_all.append(login_info)
                        tmp_dict[dict_index] = []
                        sortid += 1
                    except:
                        pass
                # 取登录失败日志
                tmp_value = 'Authentication failed for user'
                if tmp_value in line:
                    user = line.split(tmp_value)[-1].replace('[', '').replace(']', '').strip()
                    if user == '?' or user != get.user_name:
                        continue
                    login_info['user'] = user
                    login_info['ip'] = ip
                    login_info['status'] = '登录失败'  # 0为登录失败，1为登录成功
                    login_info['in_time'] = exec_time
                    login_info['out_time'] = exec_time
                    login_info['sortid'] = sortid
                    login_all.append(login_info)
                    sortid += 1

        if tmp_dict:
            for item in tmp_dict.keys():
                if not tmp_dict[item]: continue
                user, ip = item.split("__")
                info = {
                    "status": "登录成功",
                    "in_time": tmp_dict[item][0],
                    "out_time": "正在连接中",
                    "user": user,
                    "ip": ip,
                    "sortid": sortid
                }
                sortid += 1
                login_all.append(info)

        data = []
        # 搜索过滤
        search_str = get.search.strip().lower() if 'search' in get and get.search else None

        if login_all and search_str:
            for info in login_all:
                try:
                    if any(search_str in str(info[key]).lower() for key in ['ip', 'user', 'status', 'in_time', 'out_time']):
                        data.append(info)
                except:
                    pass
        else:
            data = login_all

        data = sorted(data, key=lambda x: x['sortid'], reverse=True)
        return self.get_page(data, get)

    def get_page(self, data, get):
        """
            @name 取分页
            @author hezhihong
            @param data 需要分页的数据 list
            @param get.p 第几页
            @return 指定分页数据
            """
        # 包含分页类
        import page
        # 实例化分页类
        page = page.Page()

        info = {}
        info['count'] = len(data)
        info['row'] = int(getattr(get, "limit", 10))
        info['p'] = 1
        if hasattr(get, 'p'):
            info['p'] = int(get['p'])
        info['uri'] = {}
        info['return_js'] = ''
        # 获取分页数据
        result = {}
        result['page'] = page.GetPage(info, limit='1,2,3,4,5,8')
        n = 0
        result['data'] = []
        for i in range(info['count']):
            if n >= page.ROW: break
            if i < page.SHIFT: continue
            n += 1
            result['data'].append(data[i])
        return result

    def get_action_log(self, get):
        """
        @name 取操作日志
        @author hezhihong
        @param get.user_name ftp用户名
        return {"upload":[],"download":[],"rename":[],"delete":[]}
        """
        search_str = 'pure-ftpd'
        args = public.dict_obj()
        args.exec_name = 'getlog'
        file_name = self.__ftp_backup_path
        is_backup = True

        other_status = True if self.is_debian_12() else False

        if self.set_ftp_log(get) == 'stop':
            file_name = self.__messages_file
            is_backup = False
        # 取所有messages日志文件
        file_list = self.get_file_list(file_name, is_backup)
        if not hasattr(get, 'user_name'):
            return public.returnMsg(False, '参数不正确！')

        tmp_data = []
        sortid = 0

        for file in file_list:
            if not os.path.isfile(file['file']):
                continue

            conf = public.readFile(file['file'])
            # 过滤日志文件
            lines = [line for line in conf.strip().split('\n') if 'pure-ftpd' in line and '?@' not in line]
            for line in lines:
                if not line or search_str not in line:
                    continue

                action_info = {}
                tmp_v = line.split(search_str)
                user = ''

                if other_status:
                    try:
                        action_time = datetime.datetime.fromisoformat(tmp_v[0].split(" ")[0].split(".")[0])
                        action_info['time'] = action_time.strftime('%-m-%d %H:%M:%S')
                    except:
                        pass
                    import re
                    match = re.search(r'\((.*)@', line)
                    if match:
                        user = match.group(1)
                else:
                    hostname = tmp_v[0].strip().split()[3].strip()
                    action_time = tmp_v[0].replace(hostname, '').strip()
                    action_info['time'] = self.get_format_time(action_time)

                upload_value = ' uploaded '
                download_value = ' downloaded '
                rename_value = 'successfully renamed or moved:'
                delete_value = ' Deleted '

                ip = line[line.find('(') + 1:line.find(')')].split('@')[1]
                action_info['ip'] = ip
                action_info['type'] = ''

                # 取操作用户
                if any(value in line for value in [upload_value, download_value, rename_value, delete_value]):
                    user = line[line.find('(') + 1:line.find(')')].split('@')[0]

                action_info['sortid'] = sortid
                sortid += 1

                if not user or user != get.user_name:
                    continue

                # 取上传日志
                if (get.type == 'all' or get.type == 'upload') and upload_value in line:
                    action_info['file'] = line[line.find(']') + 1:line.rfind('(')].replace('uploaded', '').replace('//', '/').strip()
                    action_info['type'] = '上传'
                    tmp_data.append(action_info)
                # 取下载日志
                if (get.type == 'all' or get.type == 'download') and download_value in line:
                    line_list = line.split()
                    upload_index = line_list.index('downloaded')
                    action_info['file'] = line_list[upload_index - 1].replace('//', '/')
                    action_info['type'] = '下载'
                    tmp_data.append(action_info)
                # 取重命名日志
                if (get.type == 'all' or get.type == 'rename') and rename_value in line:
                    action_info['file'] = line.split(rename_value)[1].replace('->', '重命名为').strip().replace('//', '/')
                    action_info['type'] = '重命名'
                    tmp_data.append(action_info)
                # 取删除日志
                if (get.type == 'all' or get.type == 'delete') and delete_value in line:
                    action_info['file'] = line.split()[-1].strip().replace('//', '/')
                    action_info['type'] = '删除'
                    tmp_data.append(action_info)

        # 搜索过滤
        search_str = get.search.strip().lower() if 'search' in get and get.search else None

        if tmp_data and search_str:
            # 确保每条记录都有 'user' 键
            for info in tmp_data:
                info.setdefault('user', get.user_name)

            # 筛选数据
            data = [
                info for info in tmp_data
                if any(search_str in str(info[key]).lower() for key in ['ip', 'file', 'type', 'time', 'user'])
            ]

        else:
            data = tmp_data

        data = sorted(data, key=lambda x: x['sortid'], reverse=True)
        return self.get_page(data, get)

    def del_crontab(self):
        """
        @name 删除项目定时清理任务
        @auther hezhihong<2022-10-31>
        @return
        """
        cron_name = '[勿删]FTP审计日志切割任务'
        cron_path = public.GetConfigValue('setup_path') + '/cron/'
        cron_list = public.M('crontab').where("name=?", (cron_name,)).select()
        if cron_list:
            for i in cron_list:
                if not i: continue
                cron_echo = public.M('crontab').where(
                    "id=?", (i['id'],)).getField('echo')
                args = {"id": i['id']}
                import crontab
                crontab.crontab().DelCrontab(args)
                del_cron_file = cron_path + cron_echo
                public.ExecShell(
                    "crontab -u root -l| grep -v '{}'|crontab -u root -".
                    format(del_cron_file))

    def add_crontab(self):
        """
        @name 构造日志切割任务
        """
        python_path = ''
        try:
            python_path = public.ExecShell('which btpython')[0].strip("\n")
        except:
            try:
                python_path = public.ExecShell('which python')[0].strip("\n")
            except:
                pass
        if not python_path: return False
        if not public.M('crontab').where('name=?',
                                         ('[勿删]FTP审计日志切割',)).count():
            cmd = '{} {}'.format(python_path, self.__script_py)
            args = {
                "name": "[勿删]FTP审计日志切割任务",
                "type": 'day',
                "where1": '',
                "hour": '0',
                "minute": '1',
                "sName": "",
                "sType": 'toShell',
                "notice": '0',
                "notice_channel": '',
                "save": '',
                "save_local": '1',
                "backupTo": '',
                "sBody": cmd,
                "urladdress": ''
            }
            import crontab
            res = crontab.crontab().AddCrontab(args)
            if res and "id" in res.keys():
                return True
            return False
        return True



    def parse_exec_time(self, exec_time):
        from datetime import datetime
        """
        解析带有 ISO 8601 格式的时间字符串，并返回格式化的时间字符串
        """
        try:
            # 使用 strptime 来解析 ISO 格式时间
            dt = datetime.strptime(exec_time.split('+')[0], '%Y-%m-%dT%H:%M:%S.%f')  # 去掉时区信息
            return dt.strftime('%m-%d %H:%M:%S')  # 直接格式化为目标格式
        except ValueError:
            # print(f"时间解析失败: {exec_time}")
            return None

    # ftp日志分析
    def log_analysis(self, get):
        try:
            public.set_module_logs('ftp_log_analysis', 'ftp_log_analysis', 1)
            self.ftp_user = public.M('ftps').field('id,name').select()
            self.ftp_user = {i['name']: i['id'] for i in self.ftp_user}
            if not hasattr(get, 'search'):
                return public.returnMsg(False, '参数不正确！')
            day = 0
            if hasattr(get, 'day') and get.day:
                day = int(get.day)
                time = datetime.datetime.now() - datetime.timedelta(days=day)
                time = time - datetime.timedelta(hours=time.hour,
                                                 minutes=time.minute,
                                                 seconds=time.second)
                day = int(time.timestamp())
            username = []
            if hasattr(get, 'username') and get.username:
                username = json.loads(get.username)
            search = json.loads(get.search)
            file_name = self.__ftp_backup_path
            is_backup = True
            # 获取切割文件的日志文件列表
            file_list = self.get_file_list(file_name, is_backup)
            self.result = {}
            config = self.get_analysis_config(None)
            time, area, upload_shell, num = config['time'], config['area'], config['upload_shell'], config['login_error']
            self.login_error_dict = {}
            for file in file_list:
                if int(file['time']) < day: continue
                if not os.path.isfile(file['file']): continue
                log = public.readFile(file['file'])
                log = log.strip().split('\n')
                for i in log:
                    if not i: continue
                    if username:
                        user = i[i.find('(') + 1:i.find(')')].split('@')[0]
                        if user not in username:
                            continue
                    try:
                        hostname = i.split()[-1]
                        exec_time = i.split(hostname)[0].strip()
                        exec_time = self.get_format_time(exec_time)
                        exec_time = str(datetime.datetime.now().year) + '-' + exec_time
                        if '-' in exec_time and 'T' in exec_time:
                            # 处理 ISO 8601 格式的时间戳：2024-10-31T16:19:50.533842+08:00
                            dt = datetime.datetime.fromisoformat(exec_time.split('+')[0])  # 去掉时区部分
                            a_time = int(dt.timestamp())
                        else:
                            # 处理传统格式的时间戳：Oct 31 16:16:26
                            dt = datetime.datetime.strptime(f"{datetime.datetime.now().year} {exec_time}",
                                                            '%Y %b %d %H:%M:%S')
                            a_time = int(dt.timestamp())
                    except:
                        a_time = self._parse_log_time(i)

                    if day:
                        if not a_time or a_time < day:
                            continue

                    ip = i[i.find('(') + 1:i.find(')')].split('@')[1]
                    if ip == '?': continue
                    # print(self.result)
                    if 'anonymous' in search:
                        self.screening_anonymous(i)
                    if 'time' in search:
                        self.screening_time(i, a_time, time)
                    if 'area' in search:
                        self.screening_area(i, area)
                    if 'upload_shell' in search:
                        self.upload_shell(i, upload_shell)
            if 'login_error' in search:
                self.login_error(file_list, num, day, username)
            return self.result
        except:
            print(traceback.format_exc(), flush=True)

    # 获取筛选配置
    def get_analysis_config(self, get):
        if os.path.exists(self.analysis_config_path):
            data = json.loads(public.readFile(self.analysis_config_path))
        else:
            data = {
                'time': {'start_time': 8, 'end_time': 6},
                'area': {'country': ['中国'], 'city': []},
                'upload_shell': ['js', 'php', 'py', 'jar', 'sh', 'rb', 'pl', 'bat', 'vbs', 'ps1', 'lua', 'r', 'ts', 'cs', 'java', 'awk', 'swift', 'ksh', 'csh', 'fish'],
                'login_error': 5,
                'cron_task_status': 0
            }
            public.writeFile(self.analysis_config_path, json.dumps(data))
        # if not public.M('crontab').where('name=?', ('[勿删]FTP日志分析任务',)).count():
        #     data['cron_task_status'] = 0
        if "/www/server/panel" not in sys.path:
            sys.path.insert(0, "/www/server/panel")

        from mod.base.push_mod import TaskConfig
        res = TaskConfig().get_by_keyword('ftp_log', "ftp_log")
        if res:
            data["cron_task_status"] = int(res['status'])
            data["cron_task"] = {
                "task_type": {i: True for i in res["task_data"]['task_type']},
                "channel": ",".join(res["sender"])
            }
        else:
            data["cron_task_status"] = 0
        return data

    # 设置筛选配置
    def set_analysis_config(self, get):
        try:
            config = json.loads(public.readFile(self.analysis_config_path))
            if hasattr(get, 'time'):
                config['time'] = json.loads(get.time)
            if hasattr(get, 'area'):
                config['area'] = json.loads(get.area)
            if hasattr(get, 'upload_shell'):
                config['upload_shell'] = json.loads(get.upload_shell)
            if hasattr(get, 'login_error'):
                config['login_error'] = int(get.login_error)
            public.writeFile(self.analysis_config_path, json.dumps(config))
            return public.returnMsg(True, '设置成功')
        except:
            return public.returnMsg(False, '设置失败')

    # 匿名登录筛选
    def screening_anonymous(self, i):
        if '(?@' not in i and 'anonymous' not in i: return
        hostname = i.split()[-1]
        exec_time = i.split(hostname)[0].strip()
        if '-' in exec_time and 'T' in exec_time:
            exec_time_str = exec_time.split(' ')[0]
            exec_time = self.parse_exec_time(exec_time_str)                       
        else:
            exec_time = self.get_format_time(exec_time)  
        ip = i[i.find('(') + 1:i.find(')')].split('@')[1]
        user = i[i.find('(') + 1:i.find(')')].split('@')[0]
        self.write_result(ip, exec_time, user, '匿名登录')

    # 登录时间筛选
    def screening_time(self, i, a_time, time):
        start_time = int(time['start_time'])
        end_time = int(time['end_time'])
        hour = datetime.datetime.fromtimestamp(a_time).hour
        if start_time <= hour <= end_time:
            return
        p_time = datetime.datetime.fromtimestamp(a_time).strftime('%Y-%m-%d %H:%M:%S')
        ip = i[i.find('(') + 1:i.find(')')].split('@')[1]
        user = i[i.find('(') + 1:i.find(')')].split('@')[0]
        self.write_result(ip, p_time, user, '登录时间异常')

    # 地区筛选
    def screening_area(self, i, area):
        hostname = i.split()[-1]
        exec_time = i.split(hostname)[0].strip()
        exec_time = self.get_format_time(exec_time)
        # 如果标准格式转换失败，则尝试 ISO 8601 格式解析
        if '-' in exec_time and 'T' in exec_time:
            exec_time_str = exec_time.split(' ')[0]
            exec_time = self.parse_exec_time(exec_time_str)                       
        else:
            exec_time = self.get_format_time(exec_time)     
        ip = i[i.find('(') + 1:i.find(')')].split('@')[1]
        user = i[i.find('(') + 1:i.find(')')].split('@')[0]
        try:
            iparea = public.get_ip_location(ip)
        except:
            return
        if not iparea: return
        if not iparea["country"]["country"]: return
        if iparea["country"]["country"] == '内网地址': return
        if iparea["country"]["country"] in area['country'] or iparea["country"]["city"] in area['city']:
            return
        self.write_result(ip, exec_time, user, '登录地区异常')

    # 上传脚本文件检测
    def upload_shell(self, i, Suffix):
        if 'uploaded' not in i: return
        hostname = i.split()[-1]
        exec_time = i.split(hostname)[0].strip()
        if '-' in exec_time and 'T' in exec_time:
            exec_time_str = exec_time.split(' ')[0]
            exec_time = self.parse_exec_time(exec_time_str)                       
        else:
            exec_time = self.get_format_time(exec_time)
        ip = i[i.find('(') + 1:i.find(')')].split('@')[1]
        user = i[i.find('(') + 1:i.find(')')].split('@')[0]
        file = i[i.find(']') + 1:i.rfind('(')].replace('uploaded', '').replace('//', '/').strip()
        if file.split('.')[-1] not in Suffix: return
        self.write_result(ip, exec_time, user, '上传脚本文件')

    def login_error(self, file_list, num, day, username):
        # 时间窗口统计字典：{(ip, user, window_key): count}
        time_window_counts = defaultdict(int)
        data = self.parse_log(file_list, day, username)
        if not data:
            return

        for entry in data:
            try:
                # 解析时间
                dt = datetime.datetime.strptime(entry['exec_time'], '%Y-%m-%d %H:%M:%S')
                # 计算5分钟时间窗口的起始时间
                window_start = dt - datetime.timedelta(
                    minutes=dt.minute % 5,
                    seconds=dt.second,
                    microseconds=dt.microsecond
                )
                # 生成时间窗口键
                window_key = int(window_start.timestamp())

                # 统计计数
                key = (entry['ip'], entry['user'], window_key)
                time_window_counts[key] += 1
            except ValueError:
                # 跳过无效时间格式的记录
                continue

        # 用于记录已处理的IP（去重）
        processed_ips = set()

        # 检测超过阈值的记录
        for (ip, user, window_key), count in time_window_counts.items():
            if count >= num and ip not in processed_ips:
                processed_ips.add(ip)
                # 转换时间为显示格式
                window_time = datetime.datetime.fromtimestamp(window_key).strftime('%m-%d %H:%M:%S').lstrip('0')
                self.write_result(ip, window_time, user, '登录失败次数异常')

    # 写入结果
    def write_result(self, ip, exec_time, user, type):
        if ip in self.white_list['ip']: return
        if ip not in self.result.keys():
            self.result[ip] = {'exec_time': exec_time, 'user': user, 'type': type, 'id': self.ftp_user.get(user, 0)}
        else:
            self.result[ip]['exec_time'] = exec_time
            self.result[ip]['user'] = user
            if type not in self.result[ip]['type']:
                self.result[ip]['type'] += ',{}'.format(type)

                # 设置白名单

    def set_white_list(self, get):
        try:
            if not hasattr(get, 'type') or not hasattr(get, 'ip'):
                return public.returnMsg(False, '参数不正确！')
            if get.type == 'add':
                if get.ip in self.white_list['ip']: return public.returnMsg(True, '设置成功')
                self.white_list['ip'].append(get.ip)
            if get.type == 'del':
                if get.ip not in self.white_list['ip']: return public.returnMsg(True, '设置成功')
                self.white_list['ip'].remove(get.ip)
            public.writeFile(self.white_list_path, json.dumps(self.white_list))
            return public.returnMsg(True, '设置成功')
        except:
            return public.returnMsg(False, '设置失败')

    def get_white_list(self, get):
        if os.path.exists(self.white_list_path):
            white_list = json.loads(public.readFile(self.white_list_path))
        else:
            white_list = {'ip': ['127.0.0.1']}
        return white_list

    # 获取登录失败数据
    def parse_log(self, file_list, day, username):
        result = []
        for file in file_list:
            if file['time'] < day: continue
            if not os.path.isfile(file['file']): continue
            log = public.readFile(file['file'])
            log = log.strip().split('\n')
            for line in log:
                if 'Authentication failed for user' not in line: continue
                l = {}
                hostname = line.split()[-1]
                try:
                    exec_time = line.split(hostname)[0].strip()
                    l['exec_time'] = self.get_format_time(exec_time)
                    l['exec_time'] = str(datetime.datetime.now().year) + '-' + l['exec_time']
                    if '-' in exec_time and 'T' in exec_time:
                        # 处理 ISO 8601 格式的时间戳：2024-10-31T16:19:50.533842+08:00
                        dt = datetime.datetime.fromisoformat(exec_time.split('+')[0])  # 去掉时区部分
                        a_time = int(dt.timestamp())
                    else:
                        # 处理传统格式的时间戳：Oct 31 16:16:26
                        dt = datetime.datetime.strptime(f"{datetime.datetime.now().year} {exec_time}", '%Y %b %d %H:%M:%S')
                        a_time = int(dt.timestamp())
                except:
                    a_time = self._parse_log_time(line)
                    if not a_time:
                        continue

                if a_time < day: continue
                l['ip'] = line[line.find('(') + 1:line.find(')')].split('@')[1]
                l['user'] = line[line.find('(') + 1:line.find(')')].split('@')[0]
                if username and l['user'] not in username: continue
                l['status'] = False
                # 返回一个字典
                if len(l) >= 4:
                    result.append(l)
        return result

    def _parse_log_time(self, line):
        """
        通过正则匹配的方式处理日志，减少报错
        """
        exec_time = self._time_regex.search(line)
        if not exec_time:
            return
        exec_time = exec_time.group().replace("-", " ").replace("/", " ")
        for k, v in month_list.items():
            if k in exec_time:
                exec_time = exec_time.replace(k, v)

        if "+" in exec_time:
            exec_time = exec_time.split("+")[0]
        if not re.search("\d{4} ", exec_time):
            exec_time = str(datetime.datetime.now().year) + " " + exec_time

        a_time = 0
        try:
            dt = datetime.datetime.fromisoformat(exec_time)
            a_time = int(dt.timestamp())
        except:
            try:
                dt = datetime.datetime.strptime(exec_time, "%Y %m %d %H:%M:%S")
                a_time = int(dt.timestamp())
            except:
                pass

        if not a_time:
            return
        return a_time


    # 设置自动任务
    def set_cron_task(self, get):
        task_type = get.get("task_type/s", "{}")
        cycle = get.get("cycle/d", 1)
        status = get.get("status/d", 1)
        channel = get.get("channel/s", 1)

        try:
            task_type_list = [i for i, status in json.loads(task_type).items() if status]
        except:
            return public.returnMsg(False, '参数task_type不正确！')

        # 改用告警系统设置
        if "/www/server/panel" not in sys.path:
            sys.path.insert(0, "/www/server/panel")

        from mod.base.push_mod.ftp_push import FTPLogTask
        FTPLogTask.set_ftp_log_task(status, task_type_list, channel.split(","))
        return public.returnMsg(True, '设置成功')

        # try:
        #     if not hasattr(get, 'task_type') or not hasattr(get, 'cycle') or not hasattr(get, 'status') or not hasattr(get, 'channel'):
        #         return public.returnMsg(False, '参数不正确！')
        #     config = self.get_analysis_config(None)
        #     if int(get.status) == 1:
        #         config['cron_task_status'] = 1
        #         self.add_cron_task(get.cycle)
        #         config['cron_task'] = {'task_type': json.loads(get.task_type), 'cycle': int(get.cycle), 'channel': get.channel}
        #     else:
        #         if 'cron_task' in config.keys():
        #             del config['cron_task']
        #         config['cron_task_status'] = 0
        #         self.del_cron_task()
        #     public.writeFile(self.analysis_config_path, json.dumps(config))
        #     return public.returnMsg(True, '设置成功')
        # except:
        #     return public.returnMsg(False, '设置失败')

    # 添加计划任务
    def add_cron_task(self, day):
        name = '[勿删]FTP日志分析任务'
        if not public.M('crontab').where('name=?', (name,)).count():
            args = {
                "name": name,
                "type": 'day-n',
                "where1": day,
                "hour": '0',
                "minute": '0',
                "sName": "",
                "sType": 'toShell',
                "notice": '0',
                "notice_channel": '',
                "save": '',
                "save_local": '1',
                "backupTo": '',
                "sBody": 'btpython /www/server/panel/script/ftp_log_analysis.py',
                "urladdress": ''
            }
            res = crontab.crontab().AddCrontab(args)
            if res and "id" in res.keys():
                return True
            return False
        return True

    # 删除计划任务
    def del_cron_task(self):
        name = '[勿删]FTP日志分析任务'
        id = public.M('crontab').where("name=?", (name,)).getField('id')
        args = {"id": id}
        crontab.crontab().DelCrontab(args)

    def ftp_users(self, get):
        usrername = public.M('ftps').field('name').select()
        return [i['name'] for i in usrername]

    def is_debian_12(self):
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
