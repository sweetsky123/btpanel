# coding: utf-8
# -------------------------------------------------------------------
# 宝塔Linux面板
# -------------------------------------------------------------------
# Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
# -------------------------------------------------------------------
# Author: sww <cjxin@bt.cn>
# -------------------------------------------------------------------

# 定时从git同步站点
# ------------------------------

import datetime
import json
import os
import sys
import time
import traceback

if not '/www/server/panel/class' in sys.path:
    sys.path.insert(0, '/www/server/panel/class')
import public
from panelModel.base import panelBase


class main(panelBase):
    config_path = '/www/server/panel/data/syncsite.json'

    def __init__(self):
        if os.path.exists(self.config_path):
            if json.loads(public.readFile(self.config_path)):
                self.add_crontab()

    def add_task(self, get):
        try:
            if not hasattr(get, 'site_id') or not hasattr(get, 'git_addr') or not hasattr(get, 'cycle'):
                return public.returnMsg(False, '参数错误!')
            if not os.path.exists(self.config_path):
                public.writeFile(self.config_path, '{}')
            conf_data = json.loads(public.readFile(self.config_path))
            path = public.M('sites').where('id=?', (get.site_id,)).getField('path')
            if not path:
                return public.returnMsg(False, '站点不存在!')
            branch = ''
            if hasattr(get, 'branch') and get.branch:
                branch = '-b {}'.format(get.branch)
            exec = 'rm -rf {}/git_bt && mkdir -p {}/git_bt && git clone {} {} {}/git_bt/ && cp -rf {}/git_bt/* {} && rm -rf {}/git_bt'.format(path, path, branch, get.git_addr, path, path, path, path)
            conf_data[str(get.site_id)] = {'exec': exec, 'cycle': get.cycle, 'last_time': 0, 'git_addr': get.git_addr, 'branch': get.branch}
            public.writeFile(self.config_path, json.dumps(conf_data))
            return public.returnMsg(True, '添加成功!')
        except:
            return public.returnMsg(False, '添加失败!')

    def del_task(self, get):
        try:
            if not hasattr(get, 'site_id'):
                return public.returnMsg(False, '参数错误!')
            if not os.path.exists(self.config_path):
                return public.returnMsg(False, '配置文件不存在!')
            conf_data = json.loads(public.readFile(self.config_path))
            if not conf_data:
                return public.returnMsg(False, '配置文件不存在!')

            if str(get.site_id) in conf_data.keys():
                conf_data.pop(str(get.site_id))
                public.writeFile(self.config_path, json.dumps(conf_data))
                return public.returnMsg(True, '删除成功!')
            return public.returnMsg(False, '任务不存在!')
        except:
            return public.returnMsg(False, traceback.format_exc())

    def get_task(self, get):
        if not hasattr(get, 'site_id'):
            return public.returnMsg(False, '参数错误!')
        if not os.path.exists(self.config_path):
            return public.returnMsg(False, '配置文件不存在!')
        conf_data = json.loads(public.readFile(self.config_path))
        if not conf_data:
            return public.returnMsg(False, '配置文件不存在!')
        if str(get.site_id) in conf_data.keys():
            return public.returnMsg(True, conf_data[str(get.site_id)])
        return public.returnMsg(False, '任务不存在!')

    def add_crontab(self):
        name = '[勿删]git同步网站服务'
        if not os.path.exists(self.config_path):
            return
        if not json.loads(public.readFile(self.config_path)):
            return
        if not public.M('crontab').where('name=?', (name,)).count():
            args = {
                "name": name,
                "type": 'day',
                "where1": '1',
                "hour": '1',
                "minute": '30',
                "sName": "",
                "sType": 'toShell',
                "notice": '0',
                "notice_channel": '',
                "save": '',
                "save_local": '1',
                "backupTo": '',
                "sBody": "btpython /www/server/panel/script/sync_site.py",
                "urladdress": ''
            }
            import crontab
            res = crontab.crontab().AddCrontab(args)
            if res and "id" in res.keys():
                return True
            return False
        return True

    def del_crontab(self):
        cron_name = '[勿删]git同步网站服务'
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

    def run_task(self,args=None):
        if not os.path.exists(self.config_path):
            return public.returnMsg(False, '配置文件不存在!')
        conf_data = json.loads(public.readFile(self.config_path))
        if not conf_data:
            return public.returnMsg(False, '配置文件不存在!')
        for k, v in conf_data.items():
            if not v['cycle']:
                continue
            # if time.time() - int(v['last_time']) < int(v['cycle']) * 86400:
            #     continue
            v['last_time'] = int(time.time()) - 100
            res = public.ExecShell(v['exec'])
            log = 'history_time:{}\n{}\n'.format(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), res[0] + res[1])
            print(log)
            if not os.path.exists('/www/wwwlogs/syncsite/'):
                os.makedirs('/www/wwwlogs/syncsite/')
            public.writeFile('/www/wwwlogs/syncsite/{}.log'.format(k), log, mode='a+')
            public.writeFile(self.config_path, json.dumps(conf_data))
            # 日志大小检查，只保留最新的500KB
            self.trim_large_file('/www/wwwlogs/syncsite/{}.log'.format(k))
        public.writeFile(self.config_path, json.dumps(conf_data))
        return public.returnMsg(True, '任务执行成功!')

    def trim_large_file(self, file_path):
        size_threshold = 1024 * 1024  # 1MB
        file_size = os.path.getsize(file_path)

        if file_size > size_threshold:
            with open(file_path, 'rb') as file:
                content = file.read()
            trimmed_content = content[500 * 1024:]
            with open(file_path, 'wb') as file:
                file.write(trimmed_content)

    def run_site_task(self, get):
        if not hasattr(get, 'site_id'):
            return public.returnMsg(False, '参数错误!')
        if not os.path.exists(self.config_path):
            return public.returnMsg(False, '未配置拉取地址!')
        conf_data = json.loads(public.readFile(self.config_path))
        if not conf_data:
            return public.returnMsg(False, '未配置拉取地址!')
        if str(get.site_id) in conf_data.keys():
            res = public.ExecShell(conf_data[str(get.site_id)]['exec'])
            log = 'history_time:{}\n{}\n执行结束\n'.format(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), res[0] + res[1])
            if not os.path.exists('/www/wwwlogs/syncsite/'):
                os.makedirs('/www/wwwlogs/syncsite/')
            public.writeFile('/www/wwwlogs/syncsite/{}.log'.format(get.site_id), log, mode='a+')
            # 日志大小检查，只保留最新的500KB
            self.trim_large_file('/www/wwwlogs/syncsite/{}.log'.format(get.site_id))
            return public.returnMsg(True, '执行成功!')
        return public.returnMsg(False, '任务不存在!')


if __name__ == '__main__':
    main().run_task()
