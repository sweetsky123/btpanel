# coding: utf-8
# -------------------------------------------------------------------
# 宝塔Linux面板
# -------------------------------------------------------------------
# Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
# -------------------------------------------------------------------
# Author: lkq <lkq@bt.cn>
# -------------------------------------------------------------------

# ------------------------------
# 安全检测模型
# ------------------------------


import os, sys, re, json, shutil, psutil, time
import stat
from datetime import datetime

from runconfig import timeout

os.chdir('/www/server/panel')
if not 'class/' in sys.path:
    sys.path.insert(0, 'class/')
import subprocess, hashlib
from projectModel.base import projectBase
import public, firewalls
from projectModel import totle_db
import db

try:
    from BTPanel import cache
except:
    pass


class mobj:
    port = ps = ''

_not_check = object()

class main(projectBase):
    _PLUGIN_PATH = "/www/server/panel/config"
    _LIST_FILE = _PLUGIN_PATH + '/scan_webshell_list.json'
    _WHITE_LIST_FILE = _PLUGIN_PATH + '/white_webshell_list.json'
    _WEBSHELl_BACK = "/www/server/panel/data/bt_security/webshell"
    _WEBSHELl_PATH = '/www/server/panel/data/bt_security/logs'
    _total = "/www/server/panel/data/bt_security/logs/total.json"
    _db_file = "/www/server/panel/data/bt_security/hash_db.txt"
    _scan_dir = "/www/server/panel/data/bt_security/monitor_dir.json"
    _check_webshell_config = _not_check

    def __init__(self):
        if not os.path.exists(self._WEBSHELl_PATH):
            os.makedirs(self._WEBSHELl_PATH, True)
        if not os.path.exists(self._total):
            public.WriteFile(self._total, '{"total":0}')
        if not os.path.exists(self._scan_dir):
            public.WriteFile(self._scan_dir, '{"scan_dir":["/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/"]}')
        
        # 服务器安全检测统计(安全检测)
        self.safe_scan_count = {
            "warning": 0,  # 告警 (2)
            "danger": 0     # 危险 (3)
        }
        # 文件监控的表
        self.__sql = db.Sql().dbfile("bt_security/file_detect.db")
        if not self.__sql.table('sqlite_master').where('type=? AND name=?', ('table', 'file_monitor')).count():
            msql = '''CREATE TABLE IF NOT EXISTS `file_monitor` (
               `id` INTEGER PRIMARY KEY AUTOINCREMENT,
               "File" VARCHAR(64) NULL,
               "OldHash" VARCHAR(64) NULL,
               "NewHash" VARCHAR(64) NULL,
               "Status" INTEGER NOT NULL,
               "Time" VARCHAR(50) NULL,
               "Mtime" VARCHAR(50) NULL,
               "Size" INTEGER NOT NULL,
               "Describe" TEXT NULL,
               "Suggestion" TEXT NULL
               )'''
            self.__sql.execute(msql)
        # else:
        #     self.__sql = totle_db.Sql()

    def __check_auth(self):
        from pluginAuth import Plugin
        plugin_obj = Plugin(False)
        plugin_list = plugin_obj.get_plugin_list()
        return int(plugin_list['ltd']) > time.time()

    def check_auth(self, get):
        return self.__check_auth()

    # 已处理的文件
    def set_handle_file(self, get):
        '''
        @name 已处理的文件
        @param md5 md5值
        @param path文件路径
        @param type
        '''

        if not 'type' in get: get.type = "remove"

        path = self._WEBSHELl_PATH + "/check.json"
        if not os.path.exists(path):
            return []
        f = open(path, 'r')
        ret = ''
        flag = False
        for i in f:
            try:
                data = json.loads(i)
                if data['md5'] == get.md5 and data['path'] == get.path:
                    flag = True
                    continue
                ret += i
            except:
                continue
        if flag:
            public.WriteFile(path, ret)

        if flag and get.type == "delete":
            if os.path.exists(get.path):
                os.remove(get.path)

        if os.path.exists(self._WEBSHELl_BACK + "/" + get.md5 + ".txt"):
            os.remove(self._WEBSHELl_BACK + "/" + get.md5 + ".txt")
        total = json.loads(public.ReadFile(self._total))
        total["total"] -= 1
        if total["total"] <= 0:
            total["total"] = 0
        public.WriteFile(self._total, json.dumps(total))
        return public.returnMsg(True, '已移除该文件')

    # 文件漏洞扫描
    def get_scan(self, get):
        '''
            @name 漏洞扫描
            @author lkq@bt.cn
            @time 2022-08-20
            @param 无
            @return 返回内容
        '''
        # from projectModel import scanningModel
        # scanningobj = scanningModel.main()
        import PluginLoader
        return PluginLoader.module_run('scanning', 'startScan', get)
        # if hasattr(scanningobj, 'startScan'):
        #     return scanningobj.startScan(get)
        # else:
        #     return {"info": [], "time": int(time.time()), "is_pay": True}

    def get_service_status(self, get=None):
        '''
            @name 获取服务状态
            @author lkq@bt.cn
            time:2022-08-20
            @return bool
        '''

        if public.ExecShell("ps aux |grep bt_check_shell|grep -v grep")[0]:
            return public.returnMsg(True, '')
        return public.returnMsg(False, '')

    def get_service_status2(self, get=None):
        '''
            @name 获取服务状态
            @author lkq@bt.cn
            time:2022-08-20
            @return bool
        '''

        if public.ExecShell("ps aux |grep bt_check_shell|grep -v grep")[0]:
            return True
        return False

    def start_service(self, get):
        '''
            @name 启动服务
            @author lkq@bt.cn
            time:2022-08-20
            @return dict
        '''
        if self.get_service_status2(): return public.returnMsg(False, '服务已启动!')
        self.wrtie_init()
        shell_info = '''#!/www/server/panel/pyenv/bin/python
#coding: utf-8
#-------------------------------------------------------------------
# 宝塔Linux面板
#-------------------------------------------------------------------
# Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
#-------------------------------------------------------------------
# Author: hwliang<hwl@bt.cn>
#-------------------------------------------------------------------
import os,sys
os.chdir('/www/server/panel')
sys.path.insert(0,'class/')
from cachelib import SimpleCache
import pyinotify,public,json,time


class MyEventHandler(pyinotify.ProcessEvent):
    _PLUGIN_PATH = "/www/server/panel/config"
    _LIST_FILE = _PLUGIN_PATH + '/scan_webshell_list.json'
    _WHITE_LIST_FILE=_PLUGIN_PATH+'/white_webshell_list.json'
    _WEBSHELl_PATH ='/www/server/panel/data/bt_security/logs'
    _WEBSHELl_BACK="/www/server/panel/data/bt_security/webshell"
    _total="/www/server/panel/data/bt_security/logs/total.json"
    __cache = None

    __count=0
    def __init__(self):
        if not self.__cache:
            self.__cache = SimpleCache(5000)
        if not os.path.exists(self._WEBSHELl_BACK):
            os.makedirs(self._WEBSHELl_BACK)
        if not os.path.exists(self._WEBSHELl_PATH):
            os.makedirs(self._WEBSHELl_PATH)
        if not os.path.exists(self._total):
            public.WriteFile(self._total,'{"total":0}')


    def get_white_config(self):
        if not os.path.exists(self._WHITE_LIST_FILE): return {"dir":[],"file":[]}
        try:
            config=json.loads(public.ReadFile(self._WHITE_LIST_FILE))
            return config
        except:
            return []

    def check(self,filename):
        try:
            print("check")
            info=public.ReadFile(filename)
            md5=public.md5(info)
            if self.__cache.get(md5):
                return False
            #判断md5文件是否存在
            if os.path.exists(self._WEBSHELl_BACK+"/"+md5+".txt"):return False
            import webshell_check
            webshell = webshell_check.webshell_check()
            res = webshell.upload_file_url2(filename, "http://w-check.bt.cn/check.php")
            print(res)
            self.__cache.set(md5, True, 360)
            if not res:return False
            public.WriteFile(self._WEBSHELl_BACK+"/"+md5+".txt",info)
            ret={}
            ret["path"]=filename
            ret["md5"]=md5
            ret["time"]=time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
            ret["md5_file"]=md5+".txt"
            logs_path=self._WEBSHELl_PATH+"/check.json"
            public.WriteFile(logs_path, json.dumps(ret)+ "\\n", "a+")
            try:
                total=json.loads(public.ReadFile(self._total))
                total["total"]+=1
                public.WriteFile(self._total,json.dumps(total))
            except:
                public.WriteFile(self._total, '{"total":0}')
        except:return False

    def process_IN_MODIFY(self, event):
        if type(event.pathname)==str and event.pathname.endswith("php"):
            if self.__cache.get(event.pathname): return False
            self.__cache.set(event.pathname, True, 2)
            if self.__cache.get("white_config"):
                white_config=self.__cache.get("white_config")
            else:
                white_config=self.get_white_config()
                self.__cache.set("white_config", white_config, 60)
            print(event.pathname)
            if len(white_config)>=1:
                if len(white_config['dir'])>0:
                    for i in white_config['dir']:
                        if event.pathname.startswith(i):
                            print("白名单目录")
                            return True
                if len(white_config['file'])>0:

                    if event.pathname in white_config['file']:
                        print("白名单文件")
                        return True
            public.run_thread(self.check,args=(event.pathname,))
            return True

def run():
    watchManager = pyinotify.WatchManager()
    event = MyEventHandler()
    mode = pyinotify.IN_MODIFY
    _list = {}
    try:
        _list = json.loads(public.readFile(event._LIST_FILE))
    except:
        _list={}
    for path_info in _list:
        if not path_info['open']: continue
        try:
            watchManager.add_watch(path_info['path'], mode ,auto_add=True, rec=True)
        except:
            continue
    notifier = pyinotify.Notifier(watchManager, event)
    notifier.loop()

if __name__ == '__main__':
    run()
        '''
        init_file = '/etc/init.d/bt_check_shell'
        public.WriteFile('/www/server/panel/class/projectModel/bt_check_shell', shell_info)
        time.sleep(0.3)
        public.ExecShell("{} start".format(init_file))
        if self.get_service_status2():
            # public.WriteLog('文件监控','启动服务')
            return public.returnMsg(True, '启动成功!')
        return public.returnMsg(False, '启动失败!')

    def stop_service(self, get):
        '''
            @name 停止服务
            @author lkq@bt.cn
            @time 2022-08-20
            @return dict
        '''
        if not self.get_service_status2(): return public.returnMsg(False, '服务已停止!')
        init_file = '/etc/init.d/bt_check_shell'
        public.ExecShell("{} stop".format(init_file))
        time.sleep(0.3)
        if not self.get_service_status2():
            public.WriteLog('文件监控', '停止服务')
            return public.returnMsg(True, '停止成功!')
        return public.returnMsg(False, '停止失败!')

    def wrtie_init(self):
        init_file = '/etc/init.d/bt_check_shell'
        init_info = '''#!/bin/bash
        # chkconfig: 2345 55 25
        # description: bt.cn file hash check

        ### BEGIN INIT INFO
        # Provides:          bt_check_shell
        # Required-Start:    $all
        # Required-Stop:     $all
        # Default-Start:     2 3 4 5
        # Default-Stop:      0 1 6
        # Short-Description: starts bt_check_shell
        # Description:       starts the bt_check_shell
        ### END INIT INFO

        panel_path=/www/server/panel/class/projectModel
        init_file=$panel_path/bt_check_shell
        chmod +x $init_file
        cd $panel_path
        panel_start()
        {
                isStart=$(ps aux |grep bt_check_shell|grep -v init.d|grep -v grep|awk '{print $2}'|xargs)
                if [ "$isStart" == '' ];then
                        echo -e "Starting Bt-check_shell service... \c"
                        nohup $init_file &> $panel_path/service.log &
                        sleep 0.5
                        isStart=$(ps aux |grep bt_check_shell|grep -v init.d|grep -v grep|awk '{print $2}'|xargs)
                        if [ "$isStart" == '' ];then
                                echo -e "\033[31mfailed\033[0m"
                                echo '------------------------------------------------------'
                                cat $panel_path/service.log
                                echo '------------------------------------------------------'
                                echo -e "\033[31mError: Bt-check_shell service startup failed.\033[0m"
                                return;
                        fi
                        echo -e "\033[32mdone\033[0m"
                else
                        echo "Starting  Bt-check_shell service (pid $isStart) already running"
                fi
        }

        panel_stop()
        {
        	echo -e "Stopping Bt-check_shell service... \c";
                pids=$(ps aux |grep bt_check_shell|grep -v grep|grep -v init.d|awk '{print $2}'|xargs)
                arr=($pids)

                for p in ${arr[@]}
                do
                        kill -9 $p
                done
                echo -e "\033[32mdone\033[0m"
        }

        panel_status()
        {
                isStart=$(ps aux |grep bt_check_shell|grep -v grep|grep -v init.d|awk '{print $2}'|xargs)
                if [ "$isStart" != '' ];then
                        echo -e "\033[32mBt-check_shell service (pid $isStart) already running\033[0m"
                else
                        echo -e "\033[31mBt-check_shell service not running\033[0m"
                fi
        }

        case "$1" in
                'start')
                        panel_start
                        ;;
                'stop')
                        panel_stop
                        ;;
                'restart')
                        panel_stop
                        sleep 0.2
                        panel_start
                        ;;
                'reload')
                        panel_stop
                        sleep 0.2
                        panel_start
                        ;;
                'status')
                        panel_status
                        ;;
                *)
                        echo "Usage: /etc/init.d/bt_check_shell {start|stop|restart|reload}"
                ;;
        esac'''
        public.WriteFile(init_file, init_info)
        public.ExecShell("chmod +x {}".format(init_file))

    def restart_service(self, get):
        '''
            @name 重启服务
            @author lkq@bt.cn
            @time 2022-08-20
            @return dict
        '''
        if not self.get_service_status2(): return self.start_service(get)
        self.wrtie_init()
        init_file = '/etc/init.d/bt_check_shell'
        public.ExecShell("{} restart".format(init_file))
        if self.get_service_status2():
            public.WriteLog('文件监控', '重启服务')
            return public.returnMsg(True, '重启成功!')
        return public.returnMsg(False, '重启失败!')

    # 更新病毒库
    def update_virus_lib(self, get):
        '''
            @name 更新病毒库
            @author lkq@bt.cn
            @time 2022-08-22
            @return bool
        '''
        pass

    def get_webshell_total(self, get):
        '''
            @name 获取webshell总数
            @author lkq@bt.cn
            @time 2022-08-22
            @return dict
        '''
        public.set_module_logs("safe_detect", "get_webshell_total")
        if not os.path.exists(self._total):
            return 0
        else:
            try:
                data = json.loads(public.ReadFile(self._total))
                return data['total']
            except:
                return 0

    '''获取当前用户的日志日期'''

    def get_webshell_logs(self, get):
        path = self._WEBSHELl_PATH
        if not os.path.exists(path): return []
        data = []
        for fname in os.listdir(path):
            if re.search('(\d+-\d+-\d+).txt$', fname):
                tmp = fname.replace('.txt', '')
                data.append(tmp)
        return sorted(data, reverse=True)

    # 木马隔离文件
    def webshell_file(self, get):
        '''
            @name 木马隔离文件
            @author lkq@bt.cn
            @time 2022-08-20
            @param 无
            @return list 木马文件列表
        '''
        if not 'day' in get: get.day = time.strftime("%Y-%m-%d", time.localtime())
        path = self._WEBSHELl_PATH + "/check.json"
        if not os.path.exists(path):
            return []
        f = open(path, 'r')
        a = f.readlines()
        data = a[::-1]
        ret = []
        for i in data:
            try:
                datas = json.loads(i)
                ret.append(datas)
            except:
                continue
        return ret

    def webshell_file_single(self, get):
        '''
            @name 获取木马隔离文件，根据网站目录
            @author lkq@bt.cn
            @time 2022-08-20
            @param 无
            @return list 木马文件列表
        '''
        if "path" not in get:
            return public.returnMsg('False', "缺少网站路径参数")
        if not 'day' in get: get.day = time.strftime("%Y-%m-%d", time.localtime())
        path = self._WEBSHELl_PATH + "/check.json"
        if not os.path.exists(path):
            return []
        f = open(path, 'r')
        a = f.readlines()
        data = a[::-1]
        ret = []
        for i in data:
            try:
                datas = json.loads(i)
                if datas["path"].startswith(get["path"]):
                    ret.append(datas)
            except:
                continue
        return ret

    # 监控目录
    def get_monitor_dir(self, get):
        '''
            @name 监控目录
            @author lkq@bt.cn
            @time 2022-08-20
            @param 无
            @return list 监控目录列表
            {"index":"Uadasdasd","open": true, "path": "/www/wwwroot/192.168.1.72","ps": "192.168.1.72"}
        '''
        if os.path.exists(self._LIST_FILE):
            try:
                config = json.loads(public.ReadFile(self._LIST_FILE))
                return config
            except:
                public.WriteFile(self._LIST_FILE, '[]')
        return []

    def check_monitor_dir(self, get):
        '''
            @name 检查某个网站是否在监控中
            @author lwh
            @time 2023-11-06
            @param path
            @return true or false
        '''
        data = {"is_monitor": False, "is_run": False}
        if 'path' not in get:
            return public.returnMsg(False, "缺少网站路径参数")
        if os.path.exists(self._LIST_FILE):
            try:
                config = json.loads(public.ReadFile(self._LIST_FILE))
                for v in config:
                    if "path" not in v:
                        continue
                    if "open" not in v:
                        continue
                    if get["path"] == v["path"]:
                        data["is_monitor"] = True
                        if v["open"]:
                            data["is_run"] = True
                        break
            except:
                pass
        return public.returnMsg(True, data)

    # 添加监控目录
    def add_monitor_dir(self, get):
        '''
            @name 添加监控目录
            @author lkq@bt.cn
            @time 2022-08-20
            @param 无
            @return list 监控目录列表
        '''
        public.set_module_logs("safe_detect", "add_monitor_dir")
        try:
            dirs = get.dirs

        except:
            return public.returnMsg(False, '参数错误!')
        if not os.path.exists(self._LIST_FILE):
            config = []
        else:
            config = self.get_monitor_dir(get)
        flag = False
        flag_list = []
        for i2 in dirs:
            # 不能添加的目录列表
            white_list = ["/etc", "/boot", "/dev", "/lib", "/lib64", "/proc", "/root", "/sbin", "/usr", "/var"]
            for i in white_list:
                if i2.startswith(i):
                    return public.returnMsg(False, '不能添加该目录!【%s】,包括该目录的子目录' % i)
            if i2 == '/www/' or i2 == '/www':
                return public.returnMsg(False, '不能添加/www目录添加网站根目录!')
            if i2 == '/www/wwwroot/' or i2 == '/www/wwwroot':
                return public.returnMsg(False, '不能添加/www/wwwroot目录,请添加网站根目录!')
            if not os.path.exists(i2): return public.returnMsg(False, '{}目录不存在!'.format(i2))
            if i2 in [i['path'] for i in config]: continue
            flag_list.append(i2)
            flag = True
        if flag:
            for i2 in flag_list:
                paths, file = os.path.split(i2)
                config.append({
                    'index': public.GetRandomString(16),
                    'open': True,
                    'path': i2,
                    'ps': public.xsssec(file)
                })
            self.save_config(config)
        return public.returnMsg(True, '添加成功!')

    # 修改备注
    def edit_monitor_dir(self, get):
        '''
            @name 修改监控目录
            @author lkq@bt.cn
            @time 2022-08-20
            @param 无
            @return list 监控目录列表
        '''
        if not os.path.exists(self._LIST_FILE):
            config = []
        else:
            config = self.get_monitor_dir(get)
        for i in config:
            if i['path'] == get.path.strip():
                i['ps'] = public.xsssec(get.ps)
                break
        public.writeFile(self._LIST_FILE, json.dumps(config))
        return public.returnMsg(True, '修改成功!')

    # 删除监控目录
    def del_monitor_dir(self, get):
        '''
            @name 删除监控目录
            @author lkq@bt.cn
            @time  2022-08-20
            @param 无
            @return list 监控目录列表
        '''
        if not os.path.exists(self._LIST_FILE): return public.returnMsg(False, '目录不存在!')
        config = self.get_monitor_dir(get)
        flag = False
        for i in config:
            if i['path'] == get.path.strip():
                config.remove(i)
                flag = True
                break
        if flag:
            self.save_config(config)
            return public.returnMsg(True, '删除成功!')
        else:
            return public.returnMsg(False, '目录不存在!')

    # 关闭监控目录
    def stop_monitor_dir(self, get):
        if not os.path.exists(self._LIST_FILE): return public.returnMsg(False, '目录不存在!')
        config = self.get_monitor_dir(get)
        for i in config:
            if i['path'] == get.path.strip():
                i['open'] = False
                break
        self.save_config(config)
        return public.returnMsg(True, '关闭成功!')

    # 关闭监控目录
    def start_monitor_dir(self, get):
        if not os.path.exists(self._LIST_FILE):
            public.WriteFile(self._LIST_FILE, '[]')
            # return public.returnMsg(False, '目录不存在!')
        config = self.get_monitor_dir(get)
        flag = False
        for i in config:
            if i['path'] == get.path.strip():
                i['open'] = True
                flag = True
                break
        # 判断配置文件是否有监控该目录
        if not flag:
            args = public.dict_obj()
            args.dirs = [get.path.strip()]
            self.add_monitor_dir(args)
        else:
            self.save_config(config)
        return public.returnMsg(True, '开启成功!')

    def save_config(self, data):
        '''
            @name 保存配置
            @author hwliang<2021-10-21>
            @param data<dict_obj>{
                data:<list> 校验列表
            }
            @return void
        '''
        public.writeFile(self._LIST_FILE, json.dumps(data))
        if self.get_service_status2():
            self.restart_service(None)

    # 添加白名单路径
    def add_white_path(self, get):
        '''
            @name 添加白名单路径
            @author lkq@bt.cn
            @time  2022-08-20
            @param path
            @param type
            @return list 白名单路径列表
        '''

        if 'path' not in get: return public.returnMsg(False, '请输入路径!')
        if not os.path.exists(get.path): return public.returnMsg(False, '文件或者目录不存在!')
        get.path = os.path.abspath(get.path)
        if 'type' not in get:
            if os.path.isfile(get.path):
                get.type = 'file'
            else:
                get.type = 'dir'

        if not os.path.exists(self._WHITE_LIST_FILE):
            public.WriteFile(self._WHITE_LIST_FILE, '{"dir":[],"file":[]}')

        config = self.get_white_path(get)

        # 判断是否是dict
        if not isinstance(config, dict):
            config = {"dir": [], "file": []}
        if get.type == 'file':
            if get.path.strip() in config['file']: return public.returnMsg(False, '路径已经存在!')
        elif get.type == "dir":
            if get.path.strip() in config['dir']: return public.returnMsg(False, '路径已经存在!')
        else:
            return public.returnMsg(False, '类型不对!')
        config[get.type].append(get.path.strip())
        public.WriteFile(self._WHITE_LIST_FILE, json.dumps(config))
        return public.returnMsg(True, '添加成功!')

    @classmethod
    def get_white_path(cls, get):
        '''
            @name 获取白名单路径
            @author lkq@bt.cn
            @time 2022-08-20
            @param 无
            @return list 白名单路径列表
        '''
        if not os.path.exists(cls._WHITE_LIST_FILE): return []
        try:
            config = json.loads(public.ReadFile(cls._WHITE_LIST_FILE))
            if cls._check_webshell_config is _not_check:
                cls._check_webshell_config = object()
                files, dirs = set(), set()
                for i in config['file']:
                    files.add(os.path.abspath(i))
                for i in config['dir']:
                    dirs.add(os.path.abspath(i))
                if len(files) != len(config['file']) or len(dirs) != len(config['dir']):
                    public.WriteFile(cls._WHITE_LIST_FILE, json.dumps({"dir": list(dirs), "file": list(files)}))
                return {"dir": list(dirs), "file": list(files)}
            return config
        except:
            return []

    def del_white_path(self, get):
        '''
            @name 删除白名单路径
            @author lkq@bt.cn
            @time 2022-08-20
            @param path
            @param type
            @return list 白名单路径列表
        '''
        if not os.path.exists(self._WHITE_LIST_FILE): return public.returnMsg(False, '路径不存在!')
        get.path = os.path.abspath(get.path)
        config = self.get_white_path(get)
        # 判断是否是dict
        if not isinstance(config, dict):
            config = {"dir": [], "file": []}
        if get.type == 'file':
            if not get.path.strip() in config['file']: return public.returnMsg(False, '路径不存在!')
        elif get.type == "dir":
            if not get.path.strip() in config['dir']: return public.returnMsg(False, '路径不存在!')
        else:
            return public.returnMsg(False, '类型不对!')
        config[get.type].remove(get.path.strip())
        public.WriteFile(self._WHITE_LIST_FILE, json.dumps(config))
        return public.returnMsg(True, '删除成功!')

    # 添加所有网站
    def add_all_site(self, get):
        '''
            @name 添加所有网站
            @author lkq@bt.cn
            @time  2022-08-20
        '''
        data = public.M("sites").select()
        ret = []
        if data:
            for i in data:
                if os.path.isdir(i['path']):
                    ret.append(i['path'])
        return ret

    # 递归目录返回文件名列表
    def gci(self, filepath, n=2):
        '''
            @name 递归目录返回文件名列表，默认只递归两层
            @author lwh@bt.cn
            @time  2023-08-08
        '''
        filename = []
        if n == 0:
            return []
        try:
            files = os.listdir(filepath)
            for fi in files:
                # 未知目录
                if fi == "X11":
                    continue
                fi_d = os.path.join(filepath, fi)
                if os.path.isdir(fi_d):
                    filename = filename + self.gci(fi_d, n=n-1)
                else:
                    filename.append(os.path.join(filepath, fi_d))
            return filename
        except:
            return filename

    # 分析字符串是否包含反弹shell或者恶意下载执行的特征
    def check_shell(self, content):
        '''
            @name 分析字符串是否包含反弹shell或者恶意下载执行的特征
            @author lwh@bt.cn
            @param content: 要检测的内容
            @return: False 或 匹配到的恶意内容
            @time  2023-08-08
        '''
        # try:
        #     # 防止安装脚本误判
        #     if "/www.aapanel.com/" in content:
        #         return False
        #     if "/download.bt.cn/" in content:
        #         return False
        #     # 反弹shell类
        #     if (('bash' in content) and (('/dev/tcp/' in content) or ('telnet ' in content) or ('nc ' in content) or (
        #             ('exe   c ' in content) and ('socket' in content)) or ('curl ' in content) or (
        #                                          'wget ' in content) or (
        #                                          'lynx ' in content) or ('bash -i' in content))) or (
        #             ".decode('base64')" in content) or ("exec(base64.b64decode" in content):
        #         return content
        #     elif ('/dev/tcp/' in content) and (('exec ' in content) or ('ksh -c' in content)):
        #         return content
        #     elif ('exec ' in content) and (('socket.' in content) or (".decode('base64')" in content)):
        #         return content
        #     # 下载执行类
        #     # elif (('wget ' in content) or ('curl ' in content)) and (
        #     #         (' -O ' in content) or (' -s ' in content)) and (
        #     #         ' http' in content) and (
        #     #         ('php ' in content) or ('perl' in content) or ('python ' in content) or ('sh ' in content) or (
        #     #         'bash ' in content)):
        #     #     return content
        #     return False
        # except:
        #     return False
        try:
            # 1. 空值检查
            if not content or not isinstance(content, str):
                return False
                
            # 2. 白名单域名检查
            TRUSTED_DOMAINS = [
                'www.aapanel.com',
                'download.bt.cn',
                'github.com',
                'raw.githubusercontent.com',
                'gitlab.com',
                'bitbucket.org',
                'npmjs.org',
                'npmjs.com',
                'pypi.org',
                'python.org',
                'rubygems.org',
                'api.rubyonrails.org',
                'mirrors.',  # 各种镜像站
                'archive.ubuntu.com',
                'dl-cdn.alpinelinux.org',
                'repo.',     # 各种软件源
            ]
            
            for domain in TRUSTED_DOMAINS:
                if domain in content:
                    return False

            # 3. 白名单命令组合
            SAFE_PATTERNS = [
                r'wget .* (git|npm|node|python|ruby|php|go)\.(sh|py|rb|php|js)',  # 常见安装脚本
                r'curl .* (install|setup|bootstrap)\.(sh|py|rb|php|js)',          # 常见安装脚本
                r'(npm|yarn|pnpm) install',                                       # 包管理器
                r'pip install',                                                   # Python包管理
                r'gem install',                                                   # Ruby包管理
                r'composer require',                                              # PHP包管理
                r'go get',                                                        # Go包管理
                r'docker (pull|run)',                                            # Docker操作
                r'git (clone|pull)',                                             # Git操作
            ]
            
            for pattern in SAFE_PATTERNS:
                if re.search(pattern, content, re.I):
                    return False

            # 4. 高危特征检测
            HIGH_RISK_PATTERNS = [
                # 反弹shell
                r'bash.*-i.*>.*dev/tcp',                    # bash反弹shell
                r'nc.*-e.*bash',                           # nc反弹shell
                r'python.*socket.*subprocess',             # Python反弹shell
                r'perl.*socket.*exec',                    # Perl反弹shell
                r'ruby.*socket.*exec',                    # Ruby反弹shell
                r'php.*fsockopen.*exec',                 # PHP反弹shell
                r'telnet.*\|.*bash',                     # telnet反弹shell
                
                # 编码执行
                r'base64\.b64decode.*exec',              # base64编码执行
                r'eval.*base64_decode',                  # base64编码执行
                r'exec.*decode\(.*base64',               # base64编码执行
                
                # 可疑网络行为
                r'wget.*-O.*\|.*bash',                   # 下载并执行
                r'curl.*\|.*bash',                       # 下载并执行
                r'wget.*-O.*&&.*bash',                   # 下载并执行
                
                # 可疑系统操作
                r'chmod.*\+x.*&&.*\/',                   # 可执行权限修改并执行
                r'chmod.*777.*&&.*\/',                   # 可疑权限修改
            ]
            
            # 5. 上下文感知检测
            for pattern in HIGH_RISK_PATTERNS:
                if re.search(pattern, content, re.I):
                    # 检查是否在注释中
                    if content.lstrip().startswith(('#', '//', '/*', '*', '--')):
                        continue
                        
                    # 检查是否是文档示例
                    if any(x in content.lower() for x in ['example', 'demo', 'test', 'sample']):
                        continue
                        
                    # 检查是否在安全的环境中(如Docker)
                    if 'dockerfile' in content.lower() or 'docker-compose' in content.lower():
                        continue
                        
                    return content

            return False
            
        except Exception as e:
            # public.print_log("检测shell特征失败: {}".format(str(e)))
            return False

    # 分析文件是否包含恶意特征、反弹shell特征
    # 存在返回恶意特征
    # 不存在返回空
    def analysis_file(self, file):
        '''
            @name 分析文件是否包含恶意特征、反弹shell特征
            @author lwh@bt.cn
            @time  2023-08-08
            @return string
        '''
        try:
            if not os.path.exists(file): return ""
            if os.path.isdir(file): return ""
            if (os.path.getsize(file) == 0) or (round(os.path.getsize(file) / float(1024 * 1024)) > 10): return ""
            strings = os.popen("strings %s 2>/dev/null" % file).read().splitlines()
            if len(strings) > 200: return ""
            time.sleep(0.01)
            for str in strings:
                if self.check_shell(str):
                    return u"反弹shell类：%s" % str
            return ""
        except:
            return ""

    # 分析一串字符串是否包含反弹shell。
    # 匹配成功则返回恶意特征信息
    # 否则返回空
    def analysis_strings(self, contents):
        # try:
        #     content = contents.replace('\n', '')
        #     # 反弹shell类
        #     if self.check_shell(content):
        #         return u"反弹shell类：%s" % content
        #     return ""
        # except:
        #     return ""
        try:
            if not contents:
                return ""
                
            content = contents.replace('\n', '')
            
            # 1. 检查是否是历史命令
            is_history = any(x in content.lower() for x in ['.bash_history', '.zsh_history', '.shell_history'])
            
            # 2. 如果是历史命令，使用更宽松的规则
            if is_history:
                # 只检查明确的高危命令
                if any(x in content.lower() for x in [
                    'dev/tcp',
                    'nc -e',
                    'bash -i',
                    '.decode(base64',
                    'exec(base64',
                    'fsockopen'
                ]):
                    return u"反弹shell类：%s" % content
                return ""
                
            # 3. 其他文件使用严格的规则
            shell_check = self.check_shell(content)
            if shell_check:
                return u"反弹shell类：%s" % content
                
            return ""
            
        except Exception as e:
            # public.print_log("分析字符串内容失败: {}".format(str(e)))
            return ""

    # 安全检测——服务器安全检测扫描
    def get_safe_scan(self, get):
        '''
            @name 服务器安全扫描
            @author lkq@bt.cn
            @time 2022-08-20
            @param 无
            @return 返回服务器扫描项 1安全  2警告  3危险
        '''
        # public.print_log("|====进入服务器安全扫描")
        public.set_module_logs("safe_detect", "get_safe_scan")
        if not '_ws' in get: return public.returnMsg(False, '只允许websocket连接!')
        get.security_count = 100
        self.safe_scan_count = {
            "warning": 0,  # 告警 (status=2)
            "danger": 0,   # 危险 (status=3)
        }

        self.get_sys_user(get)
        self.get_sshd_config(get)
        self.get_file_attr(get)
        self.get_soft_detect(get)
        # self.get_web_perm(get)
        self.get_other_detect(get)
        self.get_backdoor_detect(get)
        self.get_proc_detect(get)
        self.get_history_detect(get)
        self.get_log_detect(get)
        self.get_rootkit_detect(get)
        data = {
            "time": int(time.time()), 
            "security_count": get.security_count,
            "risk_count": self.safe_scan_count
        }
        public.WriteFile("/www/server/panel/data/safe_detect.json", json.dumps(data))

    def get_safe_count(self, get):
        if not os.path.exists("/www/server/panel/data/safe_detect.json"):
            msg = {"pay": self.__check_auth(), "msg": "未检测到安全扫描数据"}
            return public.returnMsg(False, msg)
        data = json.loads(public.ReadFile("/www/server/panel/data/safe_detect.json"))
        data["pay"] = self.__check_auth()
        return public.returnMsg(True, data)

    # 系统用户扫描
    def get_sys_user(self, get):
        '''
            @name 系统用户扫描
            @author lkq@bt.cn
            @time 2022-08-20
            @param 超级用户  空口令用户  新增的用户  账户密码策略
            @return 返回系统用户扫描项
        '''
        def send_check_result(progress, name, is_safe, msg="", points=3, operation=""):
            """统一的检测结果发送处理
            @param progress: 检测进度
            @param name: 检测项名称
            @param is_safe: 是否安全
            @param msg: 详细信息
            @param points: 不安全时扣除的分数
            @param operation: 处理建议
            """
            if is_safe:
                get._ws.send({
                    "progress": progress,
                    "topic": "system_account",
                    "item": "super_user",
                    "name": name,
                    "status": 1,
                    "operation": "",
                    "info": ""
                })
            else:
                get.security_count = max(0, get.security_count - points)
                if points <= 3:
                    self.safe_scan_count["warning"] += 1
                else:
                    self.safe_scan_count["danger"] += 1
                get._ws.send({
                    "progress": progress,
                    "topic": "system_account",
                    "item": "super_user",
                    "name": name,
                    "status": 2 if points <= 3 else 3, 
                    "points": points,
                    "operation": operation,
                    "info": msg
                })

        try:
            # 1. 检测后门用户
            def check_backdoor_users():
                try:
                    ret = []
                    with open('/etc/passwd', 'r') as f:
                        for line in f:
                            parts = line.strip().split(":")
                            if len(parts) >= 4 and parts[2] == '0' and parts[3] == '0' and parts[0] != 'root':
                                ret.append(parts[0])
                    return not bool(ret), '存在后门用户%s' % '、'.join(ret) if ret else ''
                except Exception as e:
                    # public.print_log("检测后门用户失败: {}".format(str(e)))
                    return True, ''

            is_safe, msg = check_backdoor_users()
            
            send_check_result(1, "后门用户", is_safe, msg, points=30)
            time.sleep(0.1)

            # 2. 检测空口令用户
            def check_empty_passwords():
                try:
                    ret = []
                    with open('/etc/shadow', 'r') as f:
                        for line in f:
                            parts = line.strip().split(":")
                            if len(parts) > 4 and parts[1] == '':
                                ret.append(parts[0])
                    return not bool(ret), '存在空口令用户%s' % ''.join(ret) if ret else ''
                except Exception as e:
                    # public.print_log("检测空口令用户失败: {}".format(str(e)))
                    return True, ''

            is_safe, msg = check_empty_passwords()
            send_check_result(2, "空口令用户", is_safe, msg, operation="删除用户或者给用户设置密码")
            time.sleep(0.1)

            # 3. 用户权限检测
            send_check_result(3, "用户权限检测", True)
            time.sleep(0.2)

            # 4. 检测密码策略
            def check_password_policy():
                try:
                    p_file = '/etc/login.defs'
                    p_body = public.readFile(p_file)
                    if not p_body:
                        return True, ''

                    tmp = re.findall(r"\nPASS_MIN_LEN\s+(.+)", p_body, re.M)
                    if not tmp:
                        return True, ''

                    min_len = int(tmp[0].strip())
                    return min_len >= 7, '【{}】文件中把PASS_MIN_LEN 参数设置为大于等于7'.format(p_file)
                except Exception as e:
                    # public.print_log("检测密码策略失败: {}".format(str(e)))
                    return True, ''

            is_safe, msg = check_password_policy()
            send_check_result(4, "账户密码策略", is_safe, msg)
            time.sleep(0.3)

            # 5. 账户密码复杂度
            send_check_result(5, "账户密码复杂度", True)

            # 6. 检测sudo权限异常账户
            def check_sudo_privileges():
                try:
                    if not os.path.exists('/etc/sudoers'):
                        return True, ''

                    cmd = "cat /etc/sudoers 2>/dev/null |grep -v '#'|grep 'ALL=(ALL)'|awk '{print $1}'"
                    users = public.ExecShell(cmd)[0].strip().splitlines()

                    irregular_users = [user.strip() for user in users
                                     if user.strip() and user.strip() != 'root' and not user.startswith('%')]

                    if irregular_users:
                        return False, '用户 【{}】 可通过sudo命令获取特权\nvi /etc/sudoers #更改sudo设置'.format(
                            '、'.join(irregular_users))
                    return True, ''
                except Exception as e:
                    # public.print_log("检测sudo权限失败: {}".format(str(e)))
                    return True, ''

            is_safe, msg = check_sudo_privileges()
            send_check_result(6, "sudo权限异常账户", is_safe, msg)

            # 7. 检测免密登录账户公钥
            def check_passwordless_login():
                try:
                    for user_dir in os.listdir('/home/'):
                        auth_keys_file = os.path.join('/home/', user_dir, '.ssh/authorized_keys')
                        if not os.path.exists(auth_keys_file):
                            continue

                        with open(auth_keys_file, 'r') as f:
                            content = f.read()
                        keys = [line.split()[2] for line in content.splitlines()
                               if line.strip() and len(line.split()) > 2]

                        if keys:
                            msg = ('用户{}存在免密登录的证书，证书客户端名称：{}\n'
                                   '处理方案：vi {} 删除证书设置').format(
                                user_dir, ' & '.join(keys), auth_keys_file)
                            return False, msg
                    return True, ''
                except Exception as e:
                    # public.print_log("检测免密登录失败: {}".format(str(e)))
                    return True, ''

            is_safe, msg = check_passwordless_login()
            send_check_result(7, "免密登录账户", is_safe, msg)

        except Exception as e:
            # public.print_log("系统用户扫描失败: {}".format(str(e)))
            pass
        
    # SSHD配置扫描
    def get_sshd_config(self, get):
        '''
            @name SSHD配置扫描
            @author lkq@bt.cn
            @time 2022-08-20
            @param SSHD服务端口 SSHD可登录用户 STFP子系统服务  SSH协议版本 远程访问策略
            @return 返回SSHD配置扫描项
        '''

        # def get_port():
        #     try:
        #         file = '/etc/ssh/sshd_config'
        #         conf = public.readFile(file)
        #         if not conf: conf = ''
        #         rep = r"#*Port\s+([0-9]+)\s*\n"
        #         tmp1 = re.search(rep, conf)
        #         if tmp1:
        #             port = tmp1.groups(0)[0]
        #             return port
        #         return '0'
        #     except:
        #         return '0'

        # if get_port() == '22':
        #     time.sleep(0.1)
        #     get.security_count -= 5
        #     if get.security_count < 0: get.security_count = 0
        #     get._ws.send(
        #         {"progress": 8, "topic": "sshd_service", "item": "super_user", "points": 5, "name": "SSHD服务端口",
        #          "status": 2,
        #          "operation": "", "info": "当前默认端口为：22 ，建议修改！"})
        # else:
        #     time.sleep(0.2)
        #     get._ws.send(
        #         {"progress": 8, "topic": "sshd_service", "item": "super_user", "name": "SSHD服务端口", "status": 1,
        #          "operation": "", "info": ""})
        # time.sleep(0.3)
        # get._ws.send(
        #     {"progress": 9, "topic": "sshd_service", "item": "super_user", "name": "SSHD可登录用户", "status": 1,
        #      "operation": "", "info": ""})
        # time.sleep(0.1)
        # get._ws.send(
        #     {"progress": 10, "topic": "sshd_service", "item": "super_user", "name": "SFTP子系统服务", "status": 1,
        #      "operation": "", "info": ""})
        # time.sleep(0.1)
        # get._ws.send({"progress": 11, "topic": "sshd_service", "item": "super_user", "name": "SSH协议版本", "status": 1,
        #               "operation": "", "info": ""})
        # time.sleep(0.3)

        # def check_run():
        #     '''
        #         @name 检测禁止SSH空密码登录
        #         @author lkq<2020-08-10>
        #         @return tuple (status<bool>,msg<string>)
        #     '''

        #     if os.path.exists('/etc/ssh/sshd_config'):
        #         try:
        #             info_data = public.ReadFile('/etc/ssh/sshd_config')
        #             if info_data:
        #                 if re.search('PermitEmptyPasswords\s+no', info_data):
        #                     return True, '无风险'
        #                 else:
        #                     return False, 'SSH存在空密码登录 当前配置文件/etc/ssh/sshd_config 【PermitEmptyPasswords】配置为：yes，请设置为no'
        #         except:
        #             return True, '无风险'
        #     return True, '无风险'

        # flag, msg = check_run()
        # if flag:
        #     get._ws.send(
        #         {"progress": 15, "topic": "sshd_service", "item": "super_user", "name": "SSH空密码登录", "status": 1,
        #          "operation": "", "info": ""})
        # else:
        #     get.security_count -= 5
        #     if get.security_count < 0: get.security_count = 0
        #     get._ws.send(
        #         {"progress": 15, "topic": "sshd_service", "points": 5, "item": "super_user", "name": "SSH空密码登录",
        #          "status": 2,
        #          "operation": "", "info": msg})
        def send_check_result(progress, name, is_safe, msg="", points=5):
            """统一的检测结果发送处理
            @param progress: 检测进度
            @param name: 检测项名称
            @param is_safe: 是否安全
            @param msg: 详细信息
            @param points: 不安全时扣除的分数
            """
            try:
                if not is_safe:
                    get.security_count = max(0, get.security_count - points)
                # 只统计告警
                if not is_safe:
                    self.safe_scan_count["warning"] += 1

                get._ws.send({
                    "progress": progress,
                    "topic": "sshd_service",
                    "item": "super_user",
                    "name": name,
                    "status": 1 if is_safe else 2,
                    "points": points if not is_safe else 0,
                    "operation": "",
                    "info": msg if not is_safe else ""
                })
            except Exception as e:
                # public.print_log("发送SSHD检测结果失败: {}".format(str(e)))
                pass

        def check_ssh_port():
            """检查SSH端口配置
            @return: (is_safe, port, message)
            """
            try:
                sshd_config = '/etc/ssh/sshd_config'
                if not os.path.exists(sshd_config):
                    return True, '0', 'SSH配置文件不存在'
                    
                conf = public.readFile(sshd_config)
                if not conf:
                    return True, '0', 'SSH配置文件为空'
                    
                # 查找非注释的Port配置
                port_match = re.search(r"^Port\s+([0-9]+)\s*$", conf, re.MULTILINE)
                if not port_match:
                    # 查找可能被注释的Port配置
                    port_match = re.search(r"#*Port\s+([0-9]+)\s*$", conf, re.MULTILINE)
                    
                if port_match:
                    port = port_match.group(1)
                    is_safe = port != '22'
                    msg = "当前默认端口为：{} ，建议修改！".format(port) if not is_safe else ""
                    return is_safe, port, msg
                return True, '0', 'SSH端口配置未找到'
            except Exception as e:
                # public.print_log("检测SSH端口失败: {}".format(str(e)))
                return True, '0', '检测SSH端口出错'

        def check_empty_password():
            """检测SSH空密码登录设置
            @return: (is_safe, message)
            """
            try:
                sshd_config = '/etc/ssh/sshd_config'
                if not os.path.exists(sshd_config):
                    return True, 'SSH配置文件不存在'
                    
                conf = public.readFile(sshd_config)
                if not conf:
                    return True, 'SSH配置文件为空'
                    
                # 查找非注释的PermitEmptyPasswords配置
                empty_pass = re.search(r"^PermitEmptyPasswords\s+(yes|no)\s*$", conf, re.MULTILINE | re.I)
                if empty_pass:
                    is_safe = empty_pass.group(1).lower() == 'no'
                    msg = ('SSH存在空密码登录风险，当前配置文件/etc/ssh/sshd_config中'
                        '【PermitEmptyPasswords】配置为：yes，请设置为no') if not is_safe else ''
                    return is_safe, msg
                    
                # 如果没有找到配置，默认为no（安全）
                return True, ''
            except Exception as e:
                # public.print_log("检测SSH空密码登录失败: {}".format(str(e)))
                return True, '检测SSH空密码登录出错'

        try:
            # 1. 检测SSH端口
            is_safe, port, msg = check_ssh_port()
            send_check_result(8, "SSHD服务端口", is_safe, msg)
            time.sleep(0.1)

            # 2. SSHD可登录用户检测
            send_check_result(9, "SSHD可登录用户", True)
            time.sleep(0.1)

            # 3. SFTP子系统服务检测
            send_check_result(10, "SFTP子系统服务", True)
            time.sleep(0.1)

            # 4. SSH协议版本检测
            send_check_result(11, "SSH协议版本", True)
            time.sleep(0.1)

            # 5. SSH空密码登录检测
            is_safe, msg = check_empty_password()
            send_check_result(15, "SSH空密码登录", is_safe, msg)

        except Exception as e:
            # public.print_log("SSHD配置扫描失败: {}".format(str(e)))
            pass

    def get_file_attr(self, get):
        """
        重要文件权限及其属性检查
        @param get: 请求对象
        """
        # 定义需要检查的重要系统文件及其建议权限
        IMPORTANT_FILES = {
            '/etc/passwd': {'required_owner': 'root', 'required_mode': '644', 'points': 5},
            '/etc/shadow': {'required_owner': 'root', 'required_mode': '640', 'points': 5},
            '/etc/group': {'required_owner': 'root', 'required_mode': '644', 'points': 5},
            '/etc/gshadow': {'required_owner': 'root', 'required_mode': '600', 'points': 5}
        }

        def send_check_result(progress, name, status, points=0, info=""):
            """发送检查结果
            @param progress: 进度
            @param name: 文件名
            @param status: 状态码(1:安全 2:警告 3:危险)
            @param points: 扣分点数
            @param info: 详细信息
            """
            try:
                if status != 1:
                    get.security_count = max(0, get.security_count - points)
                # 只统计告警+危险
                if status == 2:
                    self.safe_scan_count["warning"] += 1
                elif status == 3:
                    self.safe_scan_count["danger"] += 1

                get._ws.send({
                    "progress": progress,
                    "topic": "file_mode",
                    "item": os.path.basename(name),
                    "name": name,
                    "status": status,
                    "points": points if status != 1 else 0,
                    "operation": "",
                    "info": info
                })
            except Exception as e:
                # public.print_log("发送文件检查结果失败: {}".format(str(e)))
                pass

        def check_file_security(file_path, config, progress):
            """检查单个文件的安全性
            @param file_path: 文件路径
            @param config: 安全配置
            @param progress: 检查进度
            """
            try:
                if not os.path.exists(file_path):
                    send_check_result(progress, file_path, 2, config['points'],
                                    "文件不存在: {}".format(file_path))
                    return

                file_attr = public.get_mode_and_user(file_path)
                if not file_attr:
                    send_check_result(progress, file_path, 2, config['points'],
                                    "无法获取文件属性: {}".format(file_path))
                    return

                # 检查文件所有者
                if file_attr['user'] != config['required_owner']:
                    send_check_result(progress, file_path, 2, config['points'],
                                        "当前文件所有者为：{}，建议修改为{}".format(file_attr['user'], config['required_owner']))
                    return

                # 检查文件权限
                if file_attr['mode'] in ['755', '777']:
                    send_check_result(progress, file_path, 2, config['points'],
                                        "当前文件权限为：{}，建议修改为{}".format(file_attr['mode'], config['required_mode']))
                    return

                # 文件安全
                send_check_result(progress, file_path, 1)

            except Exception as e:
                # public.print_log("检查文件{}失败: {}".format(file_path, str(e)))
                send_check_result(progress, file_path, 2, config['points'],
                                "检查失败: {}".format(str(e)))

        def check_system_binaries():
            """检查系统二进制文件完整性"""
            BINARY_PATHS = ['/usr/bin/', '/usr/sbin/', '/usr/local/sbin/', '/usr/local/bin/']
            SYSTEM_FILES = set([
                "depmod", "fsck", "fuser", "ifconfig", "ifdown", "ifup", "init", "insmod",
            ])

            try:
                for dir_path in BINARY_PATHS:
                    if not os.path.exists(dir_path):
                        continue

                    for file_path in self.gci(dir_path):
                        try:
                            filename = os.path.basename(file_path)
                            if filename not in SYSTEM_FILES:
                                continue

                            # 使用超时装饰器防止分析卡住
                            with timeout(5):
                                malware = self.analysis_file(file_path)
                                
                            if malware:
                                send_check_result(38, file_path, 3, 5,
                                                "发现文件{}存在恶意特征\n建议排查文件内容，删除恶意代码".format(file_path))
                            else:
                                send_check_result(38, file_path, 1)

                        except TimeoutError:
                            # public.print_log("分析文件{}超时".format(file_path))
                            continue
                        except Exception as e:
                            # public.print_log("分析文件{}失败: {}".format(file_path, str(e)))
                            continue

            except Exception as e:
                # public.print_log("检查系统二进制文件失败: {}".format(str(e)))
                pass
        def check_tmp_files():
            """检查临时目录文件"""
            TMP_DIRS = ['/tmp/', '/var/tmp/', '/dev/shm/']
            # 白名单路径，这些路径下的文件不需要检查
            WHITELIST_PATHS = [
                '/tmp/panel_9.0.0-lts/panel/BTPanel/static/vite/'
            ]

            try:
                for dir_path in TMP_DIRS:
                    if not os.path.exists(dir_path):
                        continue

                    for file_path in self.gci(dir_path):
                        try:
                            # 白名单路径检查
                            if any(white_path in file_path for white_path in WHITELIST_PATHS):
                                continue

                            # 使用超时装饰器防止分析卡住
                            with timeout(5):
                                malware = self.analysis_file(file_path)
                                
                            if malware:
                                send_check_result(40, file_path, 3, 5,
                                                "发现文件{}存在恶意特征\n建议排查文件内容，删除恶意代码".format(file_path))
                            else:
                                send_check_result(40, file_path, 1)

                        except TimeoutError:
                            # public.print_log("分析文件{}超时".format(file_path))
                            continue
                        except Exception as e:
                            # public.print_log("分析文件{}失败: {}".format(file_path, str(e)))
                            continue

            except Exception as e:
                # public.print_log("检查临时目录文件失败: {}".format(str(e)))
                pass

        try:
            # 1. 检查重要系统文件
            progress = 20
            for file_path, config in IMPORTANT_FILES.items():
                check_file_security(file_path, config, progress)
                progress += 5
                time.sleep(0.1)

            # 2. 检查系统二进制文件
            check_system_binaries()

            # 3. 检查临时目录文件
            check_tmp_files()

        except Exception as e:
            # public.print_log("文件属性检查失败: {}".format(str(e)))
            pass
    def get_soft_detect(self, get):
        """
        重点软件安全检测
        @param get: 请求对象
        """
        def send_check_result(progress, name, status, points=0, info=""):
            """发送检测结果
            @param progress: 进度
            @param name: 软件名称
            @param status: 状态码(1:安全 -1:未安装 2:警告 3:危险)
            @param points: 扣分点数
            @param info: 详细信息
            """
            try:
                if status not in [1, -1]:
                    get.security_count = max(0, get.security_count - points)
                # 只统计告警+危险
                if status == 2:
                    self.safe_scan_count["warning"] += 1
                elif status == 3:
                    self.safe_scan_count["danger"] += 1
                get._ws.send({
                    "progress": progress,
                    "topic": "software",
                    "item": name.lower(),
                    "name": name,
                    "status": status,
                    "points": points if status not in [1, -1] else 0,
                    "operation": "",
                    "info": info
                })
            except Exception as e:
                # public.print_log("发送软件检测结果失败: {}".format(str(e)))
                pass

        def check_nginx_version_leak():
            """检测nginx版本泄露"""
            nginx_conf = '/www/server/nginx/conf/nginx.conf'
            try:
                if not os.path.exists(nginx_conf):
                    return True, '配置文件不存在'
                    
                content = public.ReadFile(nginx_conf)
                if not content:
                    return True, '配置文件为空'
                    
                if re.search('server_tokens off;', content):
                    return True, ''
                return False, '当前Nginx存在版本泄露请在Nginx配置文件中添加或者修改参数server_tokens 为off;，例：server_tokens off;'
            except Exception as e:
                # public.print_log("检测Nginx版本泄露失败: {}".format(str(e)))
                return True, '检测失败'

        def check_redis_security():
            """检测Redis安全配置"""
            redis_conf = '/www/server/redis/redis.conf'
            try:
                if not os.path.exists(redis_conf):
                    return True, '配置文件不存在'
                    
                content = public.readFile(redis_conf)
                if not content:
                    return True, '配置文件为空'

                # 检查密码设置
                pass_match = re.findall(r"^\s*requirepass\s+(.+)", content, re.M)
                if pass_match:
                    redis_pass = pass_match[0].strip()
                    weak_passes = public.ReadFile("/www/server/panel/config/weak_pass.txt")
                    if weak_passes and redis_pass in weak_passes.split('\n'):
                        return False, '当前Redis密码【{}】为弱密码，请修改密码'.format(redis_pass)

                # 检查绑定地址
                bind_match = re.findall(r"^\s*bind\s+(0\.0\.0\.0)", content, re.M)
                if bind_match and not pass_match:
                    return False, 'Reids允许外网连接，但未设置Redis密码，极度危险，请立即处理'
                    
                return True, ''
            except Exception as e:
                # public.print_log("检测Redis安全配置失败: {}".format(str(e)))
                return True, '检测失败'

        def check_ftp_weak_password():
            """检测FTP弱口令"""
            try:
                weak_passes = public.ReadFile("/www/server/panel/config/weak_pass.txt")
                if not weak_passes:
                    return True, ''
                    
                weak_pass_list = weak_passes.split('\n')
                ftp_accounts = public.M("ftps").select()
                
                weak_accounts = []
                for account in ftp_accounts:
                    if account['password'] in weak_pass_list:
                        weak_accounts.append("FTP：{}存在弱口密码：{}".format(
                            account['name'], account['password']))
                        
                if weak_accounts:
                    return False, "\n".join(weak_accounts)
                return True, ''
            except Exception as e:
                # public.print_log("检测FTP弱口令失败: {}".format(str(e)))
                return True, '检测失败'

        try:
            # 1. 检测Apache
            apache_exists = os.path.exists("/www/server/apache/bin/httpd")
            send_check_result(42, "Apache", 1 if apache_exists else -1)
            time.sleep(0.1)

            # 2. 检测Nginx
            if os.path.exists("/www/server/nginx/conf/nginx.conf"):
                flag, msg = check_nginx_version_leak()
                send_check_result(44, "Nginx", 1 if flag else 2, 5, msg)
            else:
                send_check_result(44, "Nginx", -1)
            time.sleep(0.2)

            # 3. 检测Redis
            if os.path.exists("/www/server/redis/redis.conf"):
                flag, msg = check_redis_security()
                send_check_result(47, "Redis", 1 if flag else 3, 20, msg)
            else:
                send_check_result(47, "Redis", -1)
            time.sleep(0.1)

            # 4. 检测FTP
            flag, msg = check_ftp_weak_password()
            send_check_result(50, "FTP", 1 if flag else 3, 10, msg)
            time.sleep(0.3)

            # 5. 检测MySQL/MongoDB
            send_check_result(50, "MySQL/MongoDB", 1)

        except Exception as e:
            # public.print_log("软件安全检测失败: {}".f ormat(str(e)))
            pass

    # 网站权限检测
    def get_web_perm(self, get):
        """
        网站权限检测
        @param get: 请求对象
        """
        def send_check_result(progress, name, status, points=0, info=""):
            """发送检测结果
            @param progress: 进度
            @param name: 检测项名称
            @param status: 状态码(1:安全 2:警告 3:危险)
            @param points: 扣分点数
            @param info: 详细信息
            """
            try:
                if status != 1:
                    get.security_count = max(0, get.security_count - points)
                # 只统计告警+危险
                if status == 2:
                    self.safe_scan_count["warning"] += 1
                elif status == 3:
                    self.safe_scan_count["danger"] += 1
                get._ws.send({
                    "progress": progress,
                    "topic": "website_permissions",
                    "item": "web" if "Web 服务" in name else "permissions",
                    "name": name,
                    "status": status,
                    "points": points if status != 1 else 0,
                    "operation": "",
                    "info": info
                })
            except Exception as e:
                # public.print_log("发送网站权限检测结果失败: {}".format(str(e)))
                pass

        def check_web_service():
            """检测Web服务状态"""
            try:
                web_server = public.get_webserver()
                if not web_server:
                    return False, "未安装Web服务器"

                if web_server.lower() == "nginx":
                    is_running = public.is_nginx_process_exists()
                    service_name = "Nginx"
                elif web_server.lower() == "apache":
                    is_running = public.is_httpd_process_exists()
                    service_name = "Apache"
                else:
                    return False, "未知的Web服务器类型: {}".format(web_server)

                if is_running:
                    return True, ""
                return False, "{}未启动".format(service_name)

            except Exception as e:
                # public.print_log("检测Web服务状态失败: {}".format(str(e)))
                return False, "检测Web服务状态失败"

        def check_site_permissions(site_info):
            """检测单个网站目录权限
            @param site_info: 网站信息字典
            @return: (is_safe, message)
            """
            try:
                if not site_info.get('path') or not site_info.get('name'):
                    return True, "站点信息不完整"

                site_path = site_info['path']
                site_name = site_info['name']

                # 检查路径合法性
                if not os.path.exists(site_path):
                    return False, "网站目录不存在: {}".format(site_path)

                if not os.path.isdir(site_path):
                    return False, "路径不是目录: {}".format(site_path)

                # 获取目录权限
                file_attr = public.get_mode_and_user(site_path)
                if not file_attr:
                    return False, "无法获取目录权限: {}".format(site_path)

                # 检查危险权限
                dangerous_modes = ['777', '766', '776', '767']
                if file_attr['mode'] in dangerous_modes:
                    return False, "网站{}目录权限为{} 请修改为755".format(
                        site_name, file_attr['mode'])

                # 检查所有者权限
                if file_attr['user'] not in ['root', 'www']:
                    return False, "网站{}目录所有者异常: {}".format(
                        site_name, file_attr['user'])

                return True, ""

            except Exception as e:
                # public.print_log("检测网站{}目录权限失败: {}".format(
                #     site_info.get('name', '未知'), str(e)))
                return False, "检测失败"

        try:
            # 1. 检测Web服务状态
            is_service_ok, service_msg = check_web_service()
            send_check_result(
                52, 
                "Web 服务",
                1 if is_service_ok else 2,
                5,
                service_msg
            )
            time.sleep(0.2)

            # 2. 检测网站目录权限
            try:
                sites = public.M('sites').field('id,name,path').select()
                if not sites:
                    send_check_result(
                        53,
                        "网站目录权限",
                        1,
                        info="未发现网站"
                    )
                    return

                # 限制检测站点数量，避免过度消耗资源
                MAX_SITES = 30
                for index, site in enumerate(sites[:MAX_SITES], 1):
                    try:
                        is_safe, msg = check_site_permissions(site)

                        send_check_result(
                            53,
                            "分析网站{}目录权限".format(site['name']),
                            1 if is_safe else 2,
                            3 if not is_safe else 0,
                            msg
                        )
                    except Exception as e:
                        # public.print_log("检测站点{}失败: {}".format(site.get('name', '未知'), str(e)))
                        continue

                    # 添加适当延时，避免消息发送过快
                    time.sleep(0.1)

            except Exception as e:
                # public.print_log("获取网站列表失败: {}".format(str(e)))
                send_check_result(
                    53,
                    "网站目录权限",
                    2,
                    3,
                    "获取网站列表失败"
                )

        except Exception as e:
            # public.print_log("网站权限检测失败: {}".format(str(e)))
            pass
    
    # 其他项目检测
    def get_other_detect(self, get):
        """
        其他安全项目检测
        @param get: 请求对象
        """
        def send_check_result(progress, name, status, points=0, info=""):
            """发送检测结果
            @param progress: 进度
            @param name: 检测项名称
            @param status: 状态码(1:安全 2:警告 3:危险)
            @param points: 扣分点数
            @param info: 详细信息
            """
            try:
                if status != 1:
                    get.security_count = max(0, get.security_count - points)
                # 只统计告警+危险
                if status == 2:
                    self.safe_scan_count["warning"] += 1
                elif status == 3:
                    self.safe_scan_count["danger"] += 1
                get._ws.send({
                    "progress": progress,
                    "topic": "other",
                    "item": "firewall",
                    "name": name,
                    "status": status,
                    "points": points if status != 1 else 0,
                    "operation": "",
                    "info": info
                })
            except Exception as e:
                # public.print_log("发送检测结果失败: {}".format(str(e)))
                pass

        def check_firewall():
            """检测系统防火墙状态
            @return: (is_safe, message)
            """
            try:
                firewall_status = public.get_firewall_status()
                if firewall_status is None:
                    return False, "获取防火墙状态失败"
                    
                if firewall_status == 0:
                    return False, "防火墙未启动"
                elif firewall_status == 1:
                    return True, ""
                else:
                    return False, "防火墙状态异常: {}".format(firewall_status)
            except Exception as e:
                # public.print_log("检测防火墙状态失败: {}".format(str(e)))
                return False, "检测防火墙失败"

        def check_umask_setting(file_path):
            """检测umask设置
            @param file_path: 配置文件路径
            @return: (is_safe, message)
            """
            try:
                if not os.path.exists(file_path):
                    return True, ""
                    
                content = public.ReadFile(file_path)
                if not content:
                    return True, "文件为空"

                # 检查umask设置
                umask_pattern = r"\s*umask\s+([0-9]+)"
                umask_match = re.search(umask_pattern, content)
                
                if not umask_match:
                    return True, ""
                    
                umask_value = umask_match.group(1)
                unsafe_values = ['000', '001', '002', '003', '004', '005', '006', '007']
                
                if umask_value in unsafe_values:
                    return False, "{} umask {} 设置过于宽松，建议修改为022".format(
                        file_path, umask_value)
                        
                return True, ""

            except Exception as e:
                # public.print_log("检测{}的umask设置失败: {}".format(file_path, str(e)))
                return True, "检测失败"

        def check_startup():
            suspicious, malice = False, False
            try:
                init_path = ['/etc/init.d/', '/etc/rc.d/', '/etc/rc.local', '/usr/local/etc/rc.d',
                             '/usr/local/etc/rc.local', '/etc/conf.d/local.start', '/etc/inittab',
                             '/etc/systemd/system']
                for path in init_path:
                    if not os.path.exists(path): continue
                    if os.path.isfile(path):
                        content = self.analysis_file(path)
                        if content:
                            get.security_count -= 3
                            if get.security_count < 0: get.security_count = 0
                            get._ws.send({"progress": 78, "topic": "backdoor", "points": 3, "item": "backdoor",
                                          "name": "{}启动文件".format(path), "status": 3, "operation": "",
                                          "info": "启动文件{}存在恶意代码\n建议删除文件".format(path)})
                            malice = True
                        else:
                            get._ws.send({"progress": 78, "topic": "backdoor", "item": "backdoor",
                                          "name": "{}启动文件".format(path), "status": 1, "operation": "",
                                          "info": ""})
                    else:
                        for file in self.gci(path):
                            suspicious, malice = False, False
                            content = self.analysis_file(file)
                            if content:
                                get.security_count -= 3
                                if get.security_count < 0: get.security_count = 0
                                get._ws.send({"progress": 78, "topic": "backdoor", "points": 3, "item": "backdoor",
                                              "name": "{}启动文件".format(file), "status": 3, "operation": "",
                                              "info": "启动文件{}存在恶意代码\n建议删除文件".format(file)})
                            else:
                                get._ws.send({"progress": 78, "topic": "backdoor", "item": "backdoor",
                                              "name": "{}启动文件".format(file), "status": 1, "operation": "",
                                              "info": ""})
                return suspicious, malice
            except:
                return suspicious, malice

        try:
            # 1. 检测防火墙
            is_safe, msg = check_firewall()
            send_check_result(55, "系统默认防火墙保护", 1 if is_safe else 2, 3, msg)
            time.sleep(0.1)

            # 2. 检测bashrc的umask设置
            is_safe, msg = check_umask_setting("/etc/bashrc")
            send_check_result(57, "/etc/bashrc Umask设置", 1 if is_safe else 2, 3, msg)
            time.sleep(0.2)

            # 3. 检测profile的umask设置
            is_safe, msg = check_umask_setting("/etc/profile")
            send_check_result(58, "/etc/profile Umask设置", 1 if is_safe else 2, 3, msg)
            time.sleep(0.1)

            # 4. 检测系统启动项
            check_startup()
            time.sleep(0.1)

            # 5. 检测定时任务
            send_check_result(59, "定时任务", 1)

        except Exception as e:
            # public.print_log("其他安全项目检测失败: {}".format(str(e)))
            pass

    # 后门检测
    def get_backdoor_detect(self, get):
        """
        系统后门检测
        @param get: 请求对象
        """
        def send_check_result(progress, name, status, points=0, info=""):
            """发送检测结果
            @param progress: 进度
            @param name: 检测项名称
            @param status: 状态码(1:安全 2:警告 3:危险)
            @param points: 扣分点数
            @param info: 详细信息
            """
            try:
                if status not in [1, -1]:
                    get.security_count = max(0, get.security_count - points)
                # 只统计告警+危险
                if status == 2:
                    self.safe_scan_count["warning"] += 1
                elif status == 3:
                    self.safe_scan_count["danger"] += 1
                get._ws.send({
                    "progress": progress,
                    "topic": "backdoor",
                    "item": "backdoor",
                    "name": name,
                    "status": status,
                    "points": points if status not in [1, -1] else 0,
                    "operation": "",
                    "info": info
                })
            except Exception as e:
                # public.print_log("发送后门检测结果失败: {}".format(str(e)))
                pass

        def check_cron_backdoor():
            """检测定时任务后门"""
            CRON_DIRS = [
                '/var/spool/cron/',
                '/var/spool/cron/crontabs/',
                '/etc/cron.d/',
                '/etc/cron.daily/',
                '/etc/cron.weekly/',
                '/etc/cron.hourly/',
                '/etc/cron.monthly/'
            ]
            
            try:
                for cron_dir in CRON_DIRS:
                    if not os.path.exists(cron_dir) or not os.path.isdir(cron_dir):
                        continue
                        
                    for file_path in self.gci(cron_dir):
                        try:
                            if not os.path.exists(file_path) or not os.path.isfile(file_path):
                                continue
                                
                            # 检查文件大小
                            # if os.path.getsize(file_path) > 1024 * 1024:  # 大于1MB的定时任务文件可疑
                            #     send_check_result(
                            #         64,
                            #         "{}定时任务后门".format(file_path),
                            #         2,
                            #         3,
                            #         "文件大小异常，请检查文件内容"
                            #     )
                            #     continue

                            with open(file_path, 'r') as f:
                                for line in f:
                                    content = self.analysis_strings(line)
                                    if content:
                                        send_check_result(
                                            64,
                                            "{}定时任务后门".format(file_path),
                                            3,
                                            3,
                                            "{}文件存在后门代码:{}\n建议删除该定时任务".format(
                                                file_path,
                                                content.replace("反弹shell类：", "")
                                            )
                                        )
                                        break
                                else:
                                    send_check_result(
                                        64,
                                        "{}定时任务后门".format(file_path),
                                        1,
                                        0,
                                        ""
                                    )
                        except Exception as e:
                            # public.print_log("检测定时任务文件{}失败: {}".format(file_path, str(e)))
                            continue
                            
            except Exception as e:
                # public.print_log("检测定时任务后门失败: {}".format(str(e)))
                pass

        def check_ssh_backdoor():
            """检测SSH后门"""
            try:
                # 使用更安全的方式获取网络连接信息
                cmd = "ss -ntpl 2>/dev/null | grep -v ':22 ' | awk '{if (NR>1){print $5,$7}}'"
                result = public.ExecShell(cmd)[0]
                
                for line in result.splitlines():
                    try:
                        if not line.strip():
                            continue
                            
                        parts = line.split()
                        if len(parts) < 2:
                            continue
                            
                        port = parts[0].split(":")[-1]
                        process = parts[1].split("/")[0]
                        
                        if not process.isdigit():
                            continue
                            
                        exe_path = '/proc/{}/exe'.format(process)
                        if not os.path.exists(exe_path):
                            continue
                            
                        if 'sshd' in os.readlink(exe_path):
                            send_check_result(
                                66,
                                "排查进程{}".format(process),
                                3,
                                3,
                                "发现非22端口的sshd服务，进程pid：{}，端口：{}\n建议执行【kill {}】关闭异常sshd进程".format(
                                    process, port, process
                                )
                            )
                        else:
                            send_check_result(
                                66,
                                "排查进程{}".format(process),
                                1,
                                0,
                                ""
                            )
                    except Exception as e:
                        # public.print_log("检测SSH进程{}失败: {}".format(process, str(e)))
                        continue
                        
            except Exception as e:
                # public.print_log("检测SSH后门失败: {}".format(str(e)))
                pass

        def check_ssh_wrapper():
            """检测SSH wrapper后门"""
            SSHD_PATH = '/usr/sbin/sshd'
            try:
                if not os.path.exists(SSHD_PATH):
                    return
                    
                cmd = "file {} 2>/dev/null".format(SSHD_PATH)
                result = public.ExecShell(cmd)[0]
                
                if not result:
                    send_check_result(68, "SSHwrapper后门", 2, 3, "无法获取{}文件信息".format(SSHD_PATH))
                    return
                    
                if ('ELF' not in result):
                    send_check_result(68, "SSHwrapper后门", 3, 3, "{}被篡改\n建议删除文件，并重新安装ssh服务".format(SSHD_PATH))
                else:
                    send_check_result(68, "SSHwrapper后门", 1, 0, "")
                    
            except Exception as e:
                # public.print_log("检测SSH wrapper后门失败: {}".format(str(e)))
                pass
        
        def check_inetd():
            """检测inetd后门"""
            try:
                inetd_path = '/etc/inetd.conf'
                if not os.path.exists(inetd_path) or not os.path.isfile(inetd_path):
                    return
                    
                try:
                    # # 检查文件大小
                    # if os.path.getsize(inetd_path) > 1024 * 1024:  # 大于1MB可疑
                    #     send_check_result(
                    #         70,
                    #         "inetd后门",
                    #         2,
                    #         3,
                    #         "inetd配置文件大小异常，请检查"
                    #     )
                    #     return
                        
                    with open(inetd_path, 'r') as f:
                        for line_num, line in enumerate(f, 1):
                            try:
                                line = line.strip()
                                if not line or line.startswith('#'):
                                    continue
                                    
                                content = self.analysis_strings(line)
                                if content:
                                    send_check_result(
                                        70,
                                        "inetd后门",
                                        3,
                                        3,
                                        "发现可疑配置(第{}行): {}\n建议删除该配置".format(
                                            line_num, content
                                        )
                                    )
                                    return
                                    
                            except Exception as e:
                                # public.print_log("分析inetd配置第{}行失败: {}".format(line_num, str(e)))
                                continue
                                
                    # 未发现异常
                    send_check_result(70, "inetd后门", 1)
                    
                except Exception as e:
                    # public.print_log("读取inetd配置失败: {}".format(str(e)))
                    pass
                    
            except Exception as e:
                # public.print_log("检测inetd后门失败: {}".format(str(e)))
                pass

        def check_setuid():
            """检测setuid后门"""
            CRITICAL_FILES = [
                '/usr/bin/chage',
                '/usr/bin/gpasswd',
                '/usr/bin/wall',
                '/usr/bin/chfn',
                '/usr/bin/chsh',
                '/usr/bin/newgrp',
                '/usr/bin/find',
                '/usr/bin/write',
                '/usr/sbin/usernetctl',
                '/bin/mount',
                '/bin/umount',
                '/bin/ping',
                '/sbin/netreport'
            ]
            
            try:
                for file_path in CRITICAL_FILES:
                    try:
                        if not os.path.exists(file_path):
                            continue
                            
                        if not os.path.isfile(file_path):
                            send_check_result(
                                75,
                                "{}文件suid特权".format(file_path),
                                2,
                                3,
                                "文件类型异常"
                            )
                            continue
                            
                        # 使用stat获取文件权限
                        try:
                            st = os.stat(file_path)
                            if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                                send_check_result(
                                    75,
                                    "{}文件suid特权".format(file_path),
                                    3,
                                    5,
                                    "文件被设置suid/sgid权限\n建议执行【chmod u-s {} && chmod g-s {}】".format(
                                        file_path, file_path
                                    )
                                )
                            else:
                                send_check_result(
                                    75,
                                    "{}文件suid特权".format(file_path),
                                    1
                                )
                        except Exception as e:
                            # public.print_log("获取文件{}权限失败: {}".format(file_path, str(e)))
                            continue
                            
                    except Exception as e:
                        # public.print_log("检查文件{}失败: {}".format(file_path, str(e)))
                        continue
                        
            except Exception as e:
                # public.print_log("检测setuid后门失败: {}".format(str(e)))
                pass

        def check_startup():
            """检测系统启动项后门"""
            STARTUP_PATHS = [
                '/etc/init.d',
                '/etc/rc.d/rc.local',
                '/etc/rc.local',
                '/etc/rc.d/rc0.d',
                '/etc/rc.d/rc1.d',
                '/etc/rc.d/rc2.d',
                '/etc/rc.d/rc3.d',
                '/etc/rc.d/rc4.d',
                '/etc/rc.d/rc5.d',
                '/etc/rc.d/rc6.d'
            ]

            try:
                for path in STARTUP_PATHS:
                    if not os.path.exists(path):
                        continue

                    if os.path.isfile(path):
                        try:
                            # # 检查文件大小
                            # if os.path.getsize(path) > 1024 * 1024:  # 大于1MB可疑
                            #     send_check_result(
                            #         78,
                            #         "{}启动文件".format(path),
                            #         2,
                            #         3,
                            #         "文件大小异常，请检查"
                            #     )
                            #     continue

                            content = self.analysis_file(path)
                            if content:
                                send_check_result(
                                    78,
                                    "{}启动文件".format(path),
                                    3,
                                    3,
                                    "启动文件{}存在恶意代码\n建议删除文件".format(path)
                                )
                            else:
                                send_check_result(
                                    78,
                                    "{}启动文件".format(path),
                                    1,
                                    0,
                                    ""
                                )
                        except Exception as e:
                            # public.print_log("检查启动文件{}失败: {}".format(path, str(e)))
                            continue
                    else:
                        # 目录情况下遍历检查
                        for file_path in self.gci(path):
                            try:
                                if not os.path.isfile(file_path):
                                    continue

                                # if os.path.getsize(file_path) > 1024 * 1024:
                                #     send_check_result(
                                #         78,
                                #         "{}启动文件".format(file_path),
                                #         2,
                                #         3,
                                #         "文件大小异常，请检查"
                                #     )
                                #     continue

                                content = self.analysis_file(file_path)
                                if content:
                                    send_check_result(
                                        78,
                                        "{}启动文件".format(file_path),
                                        3,
                                        3,
                                        "启动文件{}存在恶意代码\n建议删除文件".format(file_path)
                                    )
                                else:
                                    send_check_result(
                                        78,
                                        "{}启动文件".format(file_path),
                                        1,
                                        0,
                                        ""
                                    )
                            except Exception as e:
                                # public.print_log("检查启动文件{}失败: {}".format(file_path, str(e)))
                                continue

            except Exception as e:
                # public.print_log("检测系统启动项后门失败: {}".format(str(e)))
                pass

        def check_alias():
            """检测可疑alias配置"""
            try:
                bashrc_path = '/root/.bashrc'
                if not os.path.exists(bashrc_path) or not os.path.isfile(bashrc_path):
                    return

                try:
                    content = public.readFile(bashrc_path)
                    if not content:
                        return

                    # 检查危险的rm别名配置
                    dangerous_rm = re.search(r'alias(\s*)rm(\s*)=(\s*)[\'\"]rm(\s*)-.*[i?].*', content)
                    if dangerous_rm:
                        send_check_result(
                            80,
                            "{}配置文件".format(bashrc_path),
                            2,
                            3,
                            "{}文件中rm命令配置不当，可能导致误删除".format(bashrc_path)
                        )
                    else:
                        send_check_result(
                            80,
                            "{}配置文件".format(bashrc_path),
                            1,
                            0,
                            ""
                        )

                except Exception as e:
                    # public.print_log("读取bashrc文件失败: {}".format(str(e)))
                    pass

            except Exception as e:
                # public.print_log("检测alias配置失败: {}".format(str(e)))
                pass

        def check_LD_PRELOAD():
            """检测LD_PRELOAD后门"""
            SYSTEM_FILES = [
                '/root/.bashrc',
                '/root/.tcshrc',
                '/root/.bash_profile',
                '/root/.cshrc',
                '/root/.tcshrc',
                '/etc/bashrc',
                '/etc/profile',
                '/etc/profile.d/',
                '/etc/csh.login',
                '/etc/csh.cshrc'
            ]
            HOME_FILES = [
                '/.bashrc',
                '/.bash_profile',
                '/.tcshrc',
                '/.cshrc',
                '/.tcshrc'
            ]

            try:
                # 检查用户目录
                for user_dir in os.listdir('/home/'):
                    user_path = os.path.join('/home/', user_dir)
                    if not os.path.isdir(user_path):
                        continue

                    for config_file in HOME_FILES:
                        file_path = os.path.join(user_path, config_file)
                        try:
                            if not os.path.isfile(file_path):
                                continue

                            info = self.check_conf("LD_PRELOAD", file_path)
                            if info:
                                send_check_result(
                                    81,
                                    "常规LD_PRELOAD后门检测",
                                    3,
                                    3,
                                    "发现{}文件存在恶意配置{}\n建议删除该配置".format(
                                        file_path, info
                                    )
                                )
                        except Exception as e:
                            # public.print_log("检查用户配置文件{}失败: {}".format(file_path, str(e)))
                            continue

                # 检查系统配置文件
                for sys_path in SYSTEM_FILES:
                    try:
                        if os.path.isdir(sys_path):
                            for file_path in self.gci(sys_path):
                                if not os.path.isfile(file_path):
                                    continue

                                info = self.check_conf("LD_PRELOAD", file_path)
                                if info:
                                    send_check_result(
                                        81,
                                        "常规LD_PRELOAD后门检测",
                                        3,
                                        3,
                                        "发现{}文件存在恶意配置{}\n建议删除该配置".format(
                                            file_path, info
                                        )
                                    )
                        else:
                            if not os.path.isfile(sys_path):
                                continue

                            info = self.check_conf("LD_PRELOAD", sys_path)
                            if info:
                                send_check_result(
                                    81,
                                    "常规LD_PRELOAD后门检测",
                                    3,
                                    3,
                                    "发现{}文件存在恶意配置{}\n建议删除该配置".format(
                                        sys_path, info
                                    )
                                )

                    except Exception as e:
                        # public.print_log("检查系统配置文件{}失败: {}".format(sys_path, str(e)))
                        continue

            except Exception as e:
                # public.print_log("检测LD_PRELOAD后门失败: {}".format(str(e)))
                pass
        
        try:
            # 1. 检测定时任务后门
            check_cron_backdoor()
            
            # 2. 检测SSH后门
            check_ssh_backdoor()
            
            # 3. 检测SSH wrapper后门
            check_ssh_wrapper()
            
            # 4. 检测inetd后门
            check_inetd()
            
            # 5. 检测setuid后门
            check_setuid()
            
            # 6. 检测系统启动项后门
            check_startup()
            
            # # 7. 检测可疑alias
            # check_alias()
            
            # 8. 检测LD_PRELOAD后门
            check_LD_PRELOAD()
            
        except Exception as e:
            # public.print_log("后门检测失败: {}".format(str(e)))
            pass

    # 环境变量检测
    def check_conf(self, tag, file):
        try:
            if not os.path.exists(file): return ""
            if os.path.isdir(file): return ""
            with open(file) as f:
                for line in f:
                    if len(line) < 3: continue
                    if line[0] == '#': continue
                    if 'export ' + tag in line:
                        return line
            return ""
        except:
            return ""

    def get_proc_detect(self, get):
        """
        进程安全检测
        @param get: 请求对象
        """
        def send_check_result(progress, name, status, points=0, info=""):
            """发送检测结果
            @param progress: 进度
            @param name: 检测项名称
            @param status: 状态码(1:安全 2:警告 3:危险)
            @param points: 扣分点数
            @param info: 详细信息
            """
            try:
                if status != 1:
                    get.security_count = max(0, get.security_count - points)
                # 只统计告警+危险
                if status == 2:
                    self.safe_scan_count["warning"] += 1
                elif status == 3:
                    self.safe_scan_count["danger"] += 1
                get._ws.send({
                    "progress": progress,
                    "topic": "proc",
                    "item": "proc",
                    "name": name,
                    "status": status,
                    "points": points if status != 1 else 0,
                    "operation": "",
                    "info": info
                })
            except Exception as e:
                # public.print_log("发送进程检测结果失败: {}".format(str(e)))
                pass

        def check_executable_files():
            """检测进程可执行文件"""
            try:
                proc_dir = '/proc'
                if not os.path.exists(proc_dir) or not os.path.isdir(proc_dir):
                    return

                for pid in os.listdir(proc_dir):
                    try:
                        if not pid.isdigit():
                            continue

                        exe_path = os.path.join(proc_dir, pid, 'exe')
                        if not os.path.islink(exe_path) or not os.path.exists(exe_path):
                            continue

                        # # 检查文件大小
                        # try:
                        #     if os.path.getsize(exe_path) > 100 * 1024 * 1024:  # 大于100MB的可执行文件可疑
                        #         send_check_result(
                        #             82,
                        #             "{}进程文件".format(exe_path),
                        #             2,
                        #             3,
                        #             "进程文件大小异常，请检查"
                        #         )
                        #         continue
                        # except OSError:
                        #     continue

                        # 分析可执行文件
                        try:
                            malware = self.analysis_file(exe_path)
                            if malware:
                                real_path = os.readlink(exe_path)
                                send_check_result(82, "{}进程文件".format(exe_path), 3, 3,
                                    "进程文件{}存在恶意代码\n建议执行【kill {}】关闭恶意进程".format(
                                        real_path, pid
                                    )
                                )
                            else:
                                send_check_result(82, "{}进程文件".format(exe_path), 1, 0, "")
                        except Exception as e:
                            # public.print_log("分析进程{}可执行文件失败: {}".format(pid, str(e)))
                            continue

                    except Exception as e:
                        # public.print_log("检查进程{}失败: {}".format(pid, str(e)))
                        continue

            except Exception as e:
                # public.print_log("检测进程可执行文件失败: {}".format(str(e)))
                pass

        def check_hidden_processes():
            """检测隐藏进程"""
            try:
                # 获取ps命令的进程列表
                ps_output = public.ExecShell("ps ax -o pid= 2>/dev/null")[0]
                ps_pids = set(pid.strip() for pid in ps_output.splitlines() if pid.strip())

                # 获取/proc目录的进程列表
                proc_pids = set()
                for pid in os.listdir('/proc'):
                    if pid.isdigit():
                        proc_pids.add(pid)

                # 检测隐藏进程
                hidden_pids = proc_pids - ps_pids
                for pid in hidden_pids:
                    try:
                        # 检查进程是否仍然存在
                        if not os.path.exists(os.path.join('/proc', pid)):
                            continue

                        send_check_result(84, "扫描进程ID{}".format(pid), 3, 3,
                            "进程ID【{}】隐藏了进程信息\n建议执行【umount /proc/{} && kill {}】".format(
                                pid, pid, pid
                            )
                        )
                    except Exception as e:
                        # public.print_log("检查隐藏进程{}失败: {}".format(pid, str(e)))
                        continue

            except Exception as e:
                # public.print_log("检测隐藏进程失败: {}".format(str(e)))
                pass

        def check_suspicious_processes():
            """检测可疑进程"""
            SUSPICIOUS_PATTERNS = [
                # 挖矿程序特征
                r'\b(minerd|xmrig|cryptonight|stratum\+tcp)\b',  

                # 恶意工具
                r'\b(sqlmap|nmap -p|hydra -l|aircrack-ng)\b',  

                # 反弹shell
                r'bash -i >& /dev|(nc|netcat) .* -e .*/bin/(\w+sh)',  
                
                # 避免匹配所有socket，只匹配socket+exec/shell等组合
                r'\bpython.*socket.*?(exec|subprocess|pty|system)\b',  
                r'\bperl.*socket.*?(exec|system|fork)\b'  
            ]
            # 已知合法进程名单
            LEGITIMATE_PROCESSES = [
                'fail2ban-server',
                '/www/server/panel/pyenv/bin/fail2ban-server',
                '/www/server/mysql/bin/mysqld',
                '/usr/bin/btpython',
                '/www/server/bt_sync/bin/btsync',
                '/panel/BTPanel/'
                # 可添加其他已知的合法程序
            ]

            try:
                cmd = "ps -ewwo user,pid,ppid,args 2>/dev/null"
                output = public.ExecShell(cmd)[0]

                for line in output.splitlines():
                    try:
                        if not line.strip():
                            continue

                        fields = line.strip().split(None, 3)
                        if len(fields) < 4:
                            continue

                        user, pid, ppid, args = fields

                        # 跳过系统进程
                        if user in ['root', 'system'] and int(pid) < 1000:
                            continue
                        if user in ['mysql', 'mysqld']:
                            continue

                        # 过滤内部合法进程
                        is_legitimate = False
                        for legit_proc in LEGITIMATE_PROCESSES:
                            if legit_proc in args:
                                is_legitimate = True
                                break

                        if is_legitimate:
                            continue

                        # 检查可疑特征
                        for pattern in SUSPICIOUS_PATTERNS:
                            if re.search(pattern, args, re.I):
                                send_check_result(
                                    86,
                                    "可疑进程扫描",
                                    3,
                                    10,
                                    "发现可疑进程: [{}] {}\n建议执行【kill {}】关闭进程".format(
                                        user, args, pid
                                    )
                                )
                                break

                    except Exception as e:
                        # public.print_log("分析进程行{}失败: {}".format(line[:100], str(e)))
                        continue

            except Exception as e:
                # public.print_log("检测可疑进程失败: {}".format(str(e)))
                pass

        try:
            # 1. 检测进程可执行文件
            check_executable_files()

            # 2. 检测隐藏进程
            check_hidden_processes()

            # 3. 检测可疑进程
            check_suspicious_processes()

        except Exception as e:
            # public.print_log("进程安全检测失败: {}".format(str(e)))
            pass

    # 历史指令记录检测
    def get_history_detect(self, get):
        try:
            # 待检测的目录和文件
            file_path = ['/home/', '/root/.bash_history', '/Users/', '/var/log/bthis/bthis.his']
            for path in file_path:
                suspicious, malice = False, False
                if not os.path.exists(path): continue
                # 目录类，获取目录下的.bash_history文件
                if os.path.isdir(path):
                    for dir in os.listdir(path):
                        file = os.path.join('%s%s%s' % (path, dir, '/.bash_history'))
                        if not os.path.exists(file): continue
                        with open(file) as f:
                            for line in f:
                                contents = self.analysis_strings(line)
                                if not contents: continue
                                malice = True
                                break
                        if malice:
                            get.security_count -= 3
                            if get.security_count < 0: get.security_count = 0
                            # 只统计危险
                            self.safe_scan_count["danger"] += 1
                            get._ws.send({"progress": 90, "topic": "history", "points": 3, "item": "history",
                                          "name": "扫描{}用户历史操作".format(dir), "status": 3, "operation": "",
                                          "info": "发现{}中存在恶意命令{}".format(file, contents.replace('"', "”"))})
                        else:
                            get._ws.send({"progress": 90, "topic": "history", "item": "history",
                                          "name": "扫描{}用户历史操作".format(dir), "status": 1, "operation": "",
                                          "info": ""})
                # 文件类，进行文件的操作分析
                else:
                    suspicious, malice = False, False
                    with open(path) as f:
                        for line in f:
                            contents = self.analysis_strings(line)
                            if not contents: continue
                            malice = True
                            break
                        if malice:
                            get.security_count -= 5
                            if get.security_count < 0: get.security_count = 0
                            # 只统计危险
                            self.safe_scan_count["danger"] += 1
                            get._ws.send({"progress": 92, "topic": "history", "points": 5, "item": "history",
                                          "name": "扫描root用户历史操作", "status": 3, "operation": "",
                                          "info": "发现{}中存在恶意命令{}".format(path, contents.replace('"', "”"))})
                        else:
                            get._ws.send({"progress": 92, "topic": "history", "item": "history",
                                          "name": "扫描root用户历史操作", "status": 1, "operation": "",
                                          "info": ""})
        except:
            pass

    # 日志检测
    def get_log_detect(self, get):
        # 排查secure SSH的爆破记录
        def check_sshlog():
            files = [os.path.join('/var/log/', i) for i in os.listdir('/var/log/') if
                     (not os.path.isdir(i)) and ('secure' in i)]
            if not files:
                get._ws.send({"progress": 94, "topic": "log", "item": "log",
                              "name": "{}日志排查".format("secure"), "status": -1, "operation": "", "info": ""})
            for log in files:
                msg = []
                suspicious, malice = False, False
                try:
                    correct_baopo_infos = attack_detect(log)
                    if len(correct_baopo_infos) > 0:
                        for info in correct_baopo_infos:
                            user = info['user']
                            time = os.popen(
                                "date -d '" + info['time'] + "' '+%Y-%m-%d %H:%M:%S' 2>/dev/null").read().splitlines()[
                                0]
                            ip = info['ip']
                            msg.append(
                                "主机SSH被外部爆破且成功登陆，时间：{}，攻击IP：{}，登录用户：{}".format(time, ip, user))
                            # get._ws.send({"progress": 94, "topic": "log", "points": 2, "item": "log",
                            #                   "name": "{}日志排查".format(log), "status": 2, "operation": "",
                            #                   "info": "主机SSH被外部爆破且成功登陆，时间：{}，攻击IP：{}，登录用户：{}".format(time, ip, user)})
                            malice = True
                except:
                    pass
                if malice:
                    get.security_count -= 2
                    if get.security_count < 0: get.security_count = 0
                    # 只统计告警
                    self.safe_scan_count["warning"] += 1
                    get._ws.send({"progress": 94, "topic": "log", "points": 2, "item": "log",
                                  "name": "{}日志排查".format(log), "status": 2, "operation": "",
                                  "info": '\n'.join(msg)})
                else:
                    get._ws.send({"progress": 94, "topic": "log", "item": "log",
                                  "name": "{}日志排查".format(log), "status": 1, "operation": "", "info": ""})

        def attack_detect(log):
            # 单IP错误的次数，超过此错误代表发生了爆破行为
            ip_failed_count = 50
            # IP C端错误的次数，超过此错误代表发生了爆破行为
            ips_failed_count = 200
            # 记录爆破成功的信息
            correct_baopo_infos = []
            # 账户错误特征
            username_error = 'Invalid user'
            # 账户正确密码错误特征
            username_correct = 'Failed password for'
            # 成功登陆
            username_password_correct = 'Accepted password for'
            # 所有错误登陆日志ip
            failed_ip = []
            # 登陆成功日志
            correct_infos = []
            # C端ip登陆错误日志
            failed_c_ips = []
            filename = os.path.basename(log)
            year = ''
            if 'secure-' in filename and len(filename) == 15:
                year = filename[7:11]
            # 打开日志文件
            f = open(log, 'r')

            for i in f:
                if (username_error in i) and ('from' in i) and ('sshd' in i):
                    try:
                        failed_ip.append(i.split(': ')[1].split()[4])
                    except:
                        continue
                elif (username_correct in i) and ('from' in i) and ('sshd' in i):
                    try:
                        failed_ip.append(i.split(': ')[1].rsplit()[-4])
                    except:
                        continue
                elif username_password_correct in i and ('sshd' in i):
                    ip = i.split(': ')[1].split()[5]
                    user = i.split(': ')[1].split()[3]
                    # time = i.split(' sshd[')[0]
                    time = ' '.join(i.replace('  ', ' ').split(' ', 4)[:3]) + " " + year
                    # 获取所有登陆成功的记录
                    correct_infos.append({'ip': ip, 'user': user, 'time': time})
            # 记录登陆失败攻击源IP地址和尝试次数
            # 1.1 判断是否发生了爆破行为,failed_ip_dict为存在爆破的失败ip列表:次数
            failed_ip_dict = filter(dict(Counter(failed_ip)), ip_failed_count)

            # 1.2 判断是否发生了C端类的爆破行为，
            for key in failed_ip:
                failed_c_ips.append(key.rsplit('.', 1)[0])
            failed_c_ips_dict = filter(dict(Counter(failed_c_ips)), ips_failed_count)

            # 2、判断爆破行为是否成功，
            for correct_info in correct_infos:
                for failed in failed_ip_dict:
                    if correct_info['ip'] in failed: correct_baopo_infos.append(correct_info)
                for failed in failed_c_ips_dict:
                    if correct_info['ip'].rsplit('.', 1)[0] in failed: correct_baopo_infos.append(correct_info)

            correct_baopo_infos = reRepeat(correct_baopo_infos)
            return correct_baopo_infos

        # 数组去重
        def reRepeat(old):
            new_li = []
            for i in old:
                if i not in new_li:
                    new_li.append(i)
            return new_li

        def filter(old, count):
            new_li = []
            for key in old:
                if old[key] > count:
                    new_li.append({key: old[key]})
            return new_li

        # 实现counter函数，由于某些版本不支持，又不想过多引入库
        def Counter(old):
            count_dict = dict()
            for item in old:
                if item in count_dict:
                    count_dict[item] += 1
                else:
                    count_dict[item] = 1
            return count_dict

        check_sshlog()

    # rootkit检测
    def get_rootkit_detect(self, get):
        # 检测恶意so文件
        def check_bad_LKM():
            suspicious, malice = False, False
            LKM_BADNAMES = ['adore.o', 'bkit-adore.o', 'cleaner.o', 'flkm.o', 'knark.o', 'modhide.o', 'mod_klgr.o',
                            'phide_mod.o', 'vlogger.o', 'p2.ko', 'rpldev.o', 'xC.o', 'strings.o', 'wkmr26.o']
            try:
                if not os.path.exists('/lib/modules/'): return suspicious, malice
                infos = os.popen(
                    'find /lib/modules/ -name "*.o" 2>/dev/null').read().splitlines()
                if not infos:
                    get._ws.send({"progress": 98, "topic": "rootkit", "item": "rootkit",
                                  "name": "LKM内核模块", "status": 1, "operation": "",
                                  "info": ""})
                for file in infos:
                    for lkm in LKM_BADNAMES:
                        if lkm == os.path.basename(file):
                            get.security_count -= 5
                            if get.security_count < 0: get.security_count = 0
                            # 只统计危险
                            self.safe_scan_count["danger"] += 1
                            get._ws.send({"progress": 98, "topic": "rootkit", "points": 5, "item": "rootkit",
                                          "name": "LKM内核模块{}".format(file), "status": 3, "operation": "",
                                          "info": "匹配文件{}具有恶意特征{}\n执行【rm {}】删除rootkit文件".format(file,
                                                                                                                lkm,
                                                                                                                file)})
                        else:
                            get._ws.send({"progress": 98, "topic": "rootkit", "item": "rootkit",
                                          "name": "LKM内核模块{}".format(file), "status": 1, "operation": "",
                                          "info": ""})
            except:
                pass

        check_bad_LKM()
        # get._ws.send({"progress": 100, "topic": "rootkit", "item": "rootkit",
        #               "name": "LKM内核模块{}".format(".ko"), "status": 1, "operation": "",
        #               "info": ""})
        # get._ws.send({"progress": 100, "topic": "rootkit", "item": "rootkit",
        #               "name": "检测完毕", "status": 1, "operation": "",
        #               "info": ""})

    #  文件完整性扫描
    #  对比文件的新旧hash值，并存入数据库
    def file_detect(self, get):
        try:
            with open(self._scan_dir, 'r') as f:
                result_conf = json.load(f)
        except FileNotFoundError:
            return public.returnMsg(False, "监控目录不存在，请刷新页面，再检测！")
        except json.JSONDecodeError:
            return public.returnMsg(False, "监控目录为空，请添加监控目录！")

        checkDir = result_conf.get('scan_dir', [])

        fileInfos = []
        if not os.path.exists(self._db_file):
            print("初始化数据库")
            hash_slice = self.file_check(checkDir)
            err = self.updateHashDB(hash_slice)
            if err is not None:
                print(err)

        # public.print_log("开始进行文件完整性检测")
        hashSlice = self.file_check(checkDir)
        oldHashMap = self.readHashDB()

        # 新hash列表的哈希映射，方便查找
        newHashMap = {hash_struct["name"]: hash_struct for hash_struct in hashSlice}
        # 遍历旧的哈希映射
        for old_name, old_hash in oldHashMap.items():
            # 如果旧的文件名不在新的哈希映射中，那么删除该条目
            if old_name not in newHashMap:
                db.Sql().dbfile("bt_security/file_detect.db").table('file_monitor').where("File = ?", old_name).delete()
                continue

                # 对比新旧哈希值
            if old_hash != newHashMap[old_name]["hash"]:
                # 如果哈希值不同，那么更新数据库并添加到异常文件信息中
                fileInfos.append({"File": newHashMap[old_name]["name"],
                                  "OldHash": old_hash,
                                  "NewHash": newHashMap[old_name]["hash"],
                                  "Time": newHashMap[old_name]["time"],
                                  "Size": newHashMap[old_name]["size"],
                                  "Mtime": newHashMap[old_name]["mtime"],
                                  "Status": 1,  # 异常
                                  "Describe": "发现系统执行文件被非法篡改",
                                  "Suggestion": "建议查看【{}】文件信息，检查文件是否存在病毒，并重新安装。\n若是个人进行版本更新迭代，请忽略！".format(
                                      newHashMap[old_name]["name"])})
            else:
                # 如果哈希值相同，那么添加到正常文件信息中
                fileInfos.append({"File": newHashMap[old_name]["name"],
                                  "OldHash": old_hash,
                                  "NewHash": newHashMap[old_name]["hash"],
                                  "Time": newHashMap[old_name]["time"],
                                  "Size": newHashMap[old_name]["size"],
                                  "Mtime": newHashMap[old_name]["mtime"],
                                  "Status": 0,  # 正常
                                  "Describe": "文件正常",
                                  "Suggestion": "无风险"})

        #  更新存储md5文件的md5信息
        err = self.updateHashDB(hashSlice)
        if err is not None:
            print(err)
        #  将所有数据存入，如果是异常情况，则告警
        err_list = []
        if len(fileInfos) != 0:
            for value in fileInfos:
                file_infos_map = {}
                file_infos_map["File"] = value["File"]
                file_infos_map["Time"] = value["Time"] # 创建时间
                file_infos_map["Size"] = value["Size"] # 文件大小
                file_infos_map["Mtime"] = value["Mtime"] # 最近修改时间
                file_infos_map["NewHash"] = value["NewHash"]
                file_infos_map["OldHash"] = value["OldHash"]
                file_infos_map["Status"] = value["Status"]
                file_infos_map["Describe"] = value["Describe"]
                file_infos_map["Suggestion"] = value["Suggestion"]

                exist = db.Sql().dbfile("bt_security/file_detect.db").table('file_monitor').where("File = ?",file_infos_map["File"]).find()

                if not exist:

                    db.Sql().dbfile("bt_security/file_detect.db").table('file_monitor').insert(file_infos_map)
                elif exist and (file_infos_map["NewHash"] != file_infos_map["OldHash"]):

                    db.Sql().dbfile("bt_security/file_detect.db").table('file_monitor').where("File = ?",file_infos_map["File"]).update({
                        "File": value["File"],
                        "Size": value["Size"],
                        "Mtime":  value["Mtime"],
                        "NewHash": value["NewHash"],
                        "OldHash": value["OldHash"],
                        "Status": value["Status"],
                        "Describe":value["Describe"],
                        "Suggestion":value["Suggestion"]
                    })

                if value["Status"] == 1:
                    file_event = {"Brief": "检测到关键文件被篡改",
                                  "Path": value["File"],
                                  "Level": 2,
                                  "DateTime": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                  "Status": 3}
                    err_list.append(file_event)
                    # self.send_mail_data(file_event["Brief"], file_event["Path"], file_event["Level"],
                    #                     file_event["DateTime"], file_event["Status"])

        res = public.returnMsg(True, "检测完毕")
        res["err_list"] = err_list
        return res

    #  获取文件md5
    def read_file_md5(self, filename):
        if os.path.exists(filename):
            with open(filename, 'rb') as fp:
                data = fp.read()
            file_md5 = hashlib.md5(data).hexdigest()
            file_size = os.path.getsize(filename)  # 获取文件大小
            file_mtime = time.strftime('%Y-%m-%d %X', time.localtime(os.path.getmtime(filename)))  # 获取文件当前状态
            file_info = {
                "name": filename,
                "hash": file_md5,
                "time": file_mtime,
                "size": file_size,  # 添加文件大小
                "mtime": file_mtime  # 添加文件最后修改时间
            }
            return file_info
        else:
            return False

    #  获取监控下的文件md5
    def file_check(self, dirs):
        hash_slice = []
        check_files = ["depmod", "fsck", "fuser", "ifconfig", "ifdown", "ifup", "init", "insmod", "ip",
                       "lsmod", "modinfo", "modprobe", "nologin", "rmmod", "route", "rsyslogd", "runlevel",
                       "sulogin", "sysctl", "awk", "basename", "bash", "cat", "chmod", "chown", "cp", "cut",
                       "date", "df", "dmesg", "echo", "egrep", "env", "fgrep", "find", "grep", "kill",
                       "logger", "login", "ls", "mail", "mktemp", "more", "mount", "mv", "netstat", "ping",
                       "ps", "pwd", "readlink", "rpm", "sed", "sh", "sort", "su", "touch", "uname", "gawk",
                       "mailx", "adduser", "chroot", "groupadd", "groupdel", "groupmod", "grpck", "lsof",
                       "pwck", "sestatus", "sshd", "useradd", "userdel", "usermod", "vipw", "chattr", "curl",
                       "diff", "dirname", "du", "file", "groups", "head", "id", "ipcs", "killall", "last",
                       "lastlog", "ldd", "less", "lsattr", "md5sum", "newgrp", "passwd", "perl", "pgrep",
                       "pkill", "pstree", "runcon", "sha1sum", "sha224sum", "sha256sum", "sha384sum",
                       "sha512sum", "size", "ssh", "stat", "strace", "strings", "sudo", "tail", "test", "top",
                       "tr", "uniq", "users", "vmstat", "w", "watch", "wc", "wget", "whereis", "which", "who",
                       "whoami", "test"]
        for dir in dirs:
            for file in check_files:
                file_path = os.path.join(dir, file)
                if os.path.isfile(file_path):
                    file_hash = self.read_file_md5(file_path)
                    hash_slice.append(file_hash)
        return hash_slice

    #   读取hash数据库
    def readHashDB(self):
        try:
            with open(self._db_file, 'r') as file:
                hash_map = {}
                for line in file:
                    fields = line.split('||')
                    if len(fields) != 5:
                        print("无效格式：{}".format(line))
                        continue
                    hash_map[fields[0]] = fields[1]
                return hash_map
        except IOError as e:
            print("Error opening file: {}".format(e))

    #   更新hash数据库
    def updateHashDB(self, hash_slice):
        try:
            with open(self._db_file, 'w') as file:
                for fh in hash_slice:
                    line = "{}||{}||{}||{}||{}\n".format(fh['name'], fh['hash'], fh['time'], fh['size'], fh['mtime'])
                    file.write(line)
        except IOError as e:
            print("Error writing to file: {}".format(e))
            return e

    #  web接口
    #  获取检测结果
    def get_scan_res(self, get):
        public.set_module_logs("safe_detect", "get_scan_res")
        if 'limit' in get:
            limit = int(get.limit.strip())
        else:
            limit = 10
        import page
        page = page.Page()
        count = db.Sql().dbfile("bt_security/file_detect.db").table('file_monitor').order("id desc").count()
        info = {}
        info['count'] = count
        info['row'] = limit
        info['p'] = 1
        if hasattr(get, 'p'):
            info['p'] = int(get['p'])
        info['uri'] = get
        info['return_js'] = ''
        if hasattr(get, 'tojs'):
            info['return_js'] = get.tojs

        data = {}
        # 获取分页数据
        data['page'] = page.GetPage(info, '1,2,3,4,5,8')
        data['data'] = db.Sql().dbfile("bt_security/file_detect.db").table('file_monitor').order('Status desc').limit(str(page.SHIFT) + ',' + str(page.ROW)).select()
        return data

    #  获取扫描目录列表
    def get_scan_dir(self, get):
        try:
            with open(self._scan_dir, 'r') as f:
                result_conf = json.load(f)
            return public.returnMsg(True, result_conf)
        except FileNotFoundError:
            return public.returnMsg(False, "监控目录不存在，请刷新页面！")

    # 增加扫描目录列表
    def add_scan_dir(self, get):
        m_dir = re.sub('/+', '/', get.dir)

        # 不能添加的目录列表
        white_list = ["/etc", "/boot", "/dev", "/lib", "/lib64", "/proc", "/root", "/usr", "/var"]
        for i in white_list:
            if m_dir.startswith(i):
                return public.returnMsg(False, '不能添加该目录!【%s】,包括该目录的子目录' % i)
        if m_dir == '/www/' or m_dir == '/www':
            return public.returnMsg(False, '不能添加/www目录添加网站根目录!')
        if m_dir == '/www/wwwroot/' or m_dir == '/www/wwwroot':
            return public.returnMsg(False, '不能添加/www/wwwroot目录,请添加网站根目录!')

        with open(self._scan_dir, 'r') as f:
            result_conf = json.load(f)
        if not os.path.exists(m_dir): return public.returnMsg(False, '{}目录不存在!'.format(m_dir))
        old_scan_dir = result_conf.get('scan_dir', [])
        for dir in m_dir.split(','):
            if dir not in old_scan_dir:
                old_scan_dir.append(dir)
            else:
                return public.returnMsg(False, "该目录已存在，请勿重复添加！")
        result_conf['scan_dir'] = old_scan_dir
        with open(self._scan_dir, 'w') as f:
            json.dump(result_conf, f)
        return public.returnMsg(True, "添加成功")

    # 修改

    # 删除扫描目录
    def del_scan_dir(self, get):
        scan_dir = json.loads(get.path)
        if not os.path.exists(self._scan_dir): return public.returnMsg(False, '目录不存在，请刷新下页面！')
        try:
            with open(self._scan_dir, 'r') as f:
                result_conf = json.load(f)
        except FileNotFoundError:
            return public.returnMsg(False, "监控目录不存在，请刷新页面！")

        old_scan_dir = result_conf.get('scan_dir', [])

        for dir in scan_dir:
            if dir not in old_scan_dir:
                return public.returnMsg(False, "该目录已被删除，请勿重复操作！")
            old_scan_dir.remove(dir)
        result_conf['scan_dir'] = old_scan_dir
        with open(self._scan_dir, 'w') as f:
            json.dump(result_conf, f)
        return public.returnMsg(True, "删除成功")

    # 处理告警数据
    def opt_dir(self, get):
        file_path = get.path
        # 获取该文件的最新md5值
        hash_info = self.read_file_md5(file_path)

        # 数据更新，并改变数据的状态、hash值
        db.Sql().dbfile("bt_security/file_detect.db").table('file_monitor').where("File = ?", file_path).update(
            {"Status": 0,
             "OldHash": hash_info['hash'],
             "NewHash": hash_info['hash'],
             "Time": hash_info['time'],
             "Describe": "文件正常",
             "Suggestion": "无风险"})

        # 更新下db.json的数据
        with open(self._db_file, 'r') as file:
            lines = file.readlines()
        with open(self._db_file, 'w') as file:
            for line in lines:
                path = line.split('||')[0]
                if path == hash_info['name']:
                    update_info = "{}||{}||{}||{}||{}\n".format(hash_info['name'], hash_info['hash'], hash_info['time'], hash_info['size'], hash_info['mtime'])

                    file.write(update_info)
                else:
                    file.write(line)
        return public.returnMsg(True, "处理成功！")

    # 获取定时任务信息
    def get_cron_file_M(self, get):
        if "/www/server/panel" not in sys.path:
            sys.path.insert(0, '/www/server/panel')

        from mod.base.push_mod import TaskConfig
        res = TaskConfig().get_by_keyword("file_detect", "file_detect")
        if not res:
            return {"hour": 22, "minute": 30, "channel": "", "status": 0}
        else:
            return {
                "hour": res['task_data']["hour"],
                "minute": res['task_data']["minute"],
                "channel": ",".join(res['sender']),
                "status": int(res['status'])
            }

    # 开启/关闭定时任务
    def set_cron_file_info(self, get):
        if not (hasattr(get, 'status') and hasattr(get, 'channel') and hasattr(get, 'hour') and hasattr(get, 'minute')):
            return public.returnMsg(False, '参数错误')
        status = get.status
        channel = get.channel
        hour = get.hour
        minute = get.minute

        if "/www/server/panel" not in sys.path:
            sys.path.insert(0, '/www/server/panel')

        from mod.base.push_mod.safe_mod_push import FileDetectTask
        res = FileDetectTask().set_push_task(bool(int(status)), int(hour), int(minute), channel.split(','))
        if res:
            return public.returnMsg(False, res)

        if int(status) == 0:
            return public.returnMsg(True, '关闭成功')

        return public.returnMsg(True, '开启成功')

    # 发送告警  title, body, login_type
    def send_mail_data(self, brief, filepath, level, datetime, status):
        cron_list = public.M('crontab').where("name=?", ("[勿删]文件完整性监控定时任务",)).select()
        if cron_list:
            login_type = cron_list[0]['notice_channel']
        else:
            login_type = ''

        path = '/www/server/panel/class/msg/' + login_type + '_msg.py'
        if not os.path.exists(path):
            return False
        body = '检测到关键执行文件{}被篡改，请及时查看！'.format(filepath)
        object = public.init_msg(login_type)
        if login_type == "mail":
            data = {}
            data['title'] = brief
            data['msg'] = body
            object.push_data(data)
        elif login_type == "wx_account":
            object.send_msg(body)
        else:
            msg = public.get_push_info("文件完整性检测告警", ['>发送内容：' + body])
            object.push_data(msg)
        return True
