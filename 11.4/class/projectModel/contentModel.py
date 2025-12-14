#!/usr/bin/python
# coding: utf-8
# Date 2022/3/29
# -------------------------------------------------------------------
# 宝塔Linux面板
# -------------------------------------------------------------------
# Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
# -------------------------------------------------------------------
# Author: lkq <lkq@bt.cn>
# contentModel.py
# 内容安全-内容检测模型
# -------------------------------------------------------------------
import os, sys, re
import traceback

os.chdir('/www/server/panel')
if not 'class/' in sys.path:
    sys.path.insert(0, 'class/')
import json
from projectModel.base import projectBase
import re, time
import public
from projectModel import totle_db
import time
import requests
from bs4 import BeautifulSoup as Bs4
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from cachelib import SimpleCache

depthDict = {}
import threading

cache = SimpleCache(500000)
if not __name__ == '__main__':
    try:
        import crontab
    except:
        pass


class main(projectBase):
    __sql = None  # 监控数据库连接
    __path = "/www/server/panel/config"

    def __init__(self):
        # 初始化数据库信息

        if not os.path.exists("class/projectModel/content/content.db"):
            self.__sql = totle_db.Sql()  # 初始化数据库
            # 监控网站的表
            if not self.__sql.table('sqlite_master').where('type=? AND name=?', ('table', 'monitor_site')).count():
                msql = '''CREATE TABLE IF NOT EXISTS `monitor_site` (
                   `id` INTEGER PRIMARY KEY AUTOINCREMENT,
                   `name` varchar(500),
                   `method` INTEGER,
                   `site_name` varchar(256) ,
                   `url` varchar(500),
                   `time` INTEGER,
                   `is_local` INTEGER,
                   `send_msg` INTEGER,
                   `send_type` varchar(256),
                    `cron_id`  INTEGER,
                    `scan_config` varchar(1000)
                   )'''
                self.__sql.execute(msql)
                '''
                监控网站的表
                monitor_site
                id  主键
                name  监控名称
                method  监控方式 1 全站扫描 2 快速扫描 3 指定URl扫描
                site_name  网站名称
                url  监控的url
                time  添加时间
                is_local  是否本地 1 代表本地 0 代表远程  默认0
                send_msg  是否发送消息 1 代表发送 0 代表不发送   默认0
                send_type  发送类型 1 代表邮件 2 代表钉钉 3 代表微信 4 代表短信  默认0
                cron_id  计划任务的ID
                scan_config 扫描的配置
                    scan_thread  扫描的线程数  默认20
                    scan_level  扫描的层次    默认3
                    scan_ua  扫描的ua        默认百度ua
                    scan_args  URl是否带参数     默认0
                    title   1 代表检测到标题 0 代表不检测标题   默认0
                    descriptions 1 代表检测到描述 0 代表不检测描述  默认0
                    keywords 1 代表检测到关键词 0 代表不检测关键词  默认0
                    title_hash 1 代表检测到标题hash 0 代表不检测标题hash   默认1
                    tail_hash   1 代表检测到尾部hash 0 代表不检测尾部hash  默认1
                    access    1 代表检测到访问 0 代表不检测访问           默认0
                    search_monitor 1 代表开启搜索引擎监控 0 代表关闭搜索引擎监控  默认0
                    thesaurus    1 代表默认词库+自定义词库 2 代表默认词库 3 代表自定义词库  默认1
                '''

                # 风险表
            if not self.__sql.table('sqlite_master').where('type=? AND name=?', ('table', 'risk')).count():
                msql = '''CREATE TABLE IF NOT EXISTS `risk` (
                       `id` INTEGER PRIMARY KEY AUTOINCREMENT,
                       `site_id` INTEGER,
                       `site_name` varchar(256),
                       `url` varchar(1000),
                       `testing_id` varchar(32),
                       `content` TEXT,
                       `risk_content` varchar(64),
                       `risk_type` varchar(64),
                        `source_file` varchar(256) DEFAULT '',
                       `source_content_file` varchar(256) DEFAULT '',
                       `new_content_file` varchar(256) DEFAULT '',
                       `time` INTEGER
                       )'''
                self.__sql.execute(msql)

                '''
                风险表  risk
                id  主键
                site_id  网站id
                site_name  网站名称
                url  风险url
                testing_id  测试id
                content  风险内容
                risk_content  风险类型
                risk_type  风险位置
                source_file 风险文件存放位置            #当风险位置为title,descriptions,keywords,body时才使用
                source_content_file   更改原始内容文件路径  #当风险位置不为title,descriptions,keywords,body的时候使用
                new_content_file  更改后的内容文件路径     #当风险位置不为title,descriptions,keywords,body的时候使用
                time  添加时间
                '''

                # 检测表
            if not self.__sql.table('sqlite_master').where('type=? AND name=?', ('table', 'testing')).count():
                msql = '''CREATE TABLE IF NOT EXISTS `testing` (
                       `id` INTEGER PRIMARY KEY AUTOINCREMENT,
                       `site_id` INTEGER,
                       `site_name` varchar(256),
                       `testing_id` varchar(32),
                       `start_time` INTEGER,
                       `end_time` INTEGER,
                       `risks` INTEGER,
                       `pid` INTEGER,
                       `scans` INTEGER,
                       `time` INTEGER)
                       '''
                self.__sql.execute(msql)

                '''
                检测表 testing
                id  主键
                site_id  网站id
                site_name  网站名称
                testing_id  测试id
                start_time  开始时间
                end_time  结束时间
                risks  风险数
                scans  扫描数
                time  添加时间

                '''

                # 敏感词排行榜
            if not self.__sql.table('sqlite_master').where('type=? AND name=?', ('table', 'works')).count():
                msql = '''CREATE TABLE IF NOT EXISTS `works` (
                       `id` INTEGER PRIMARY KEY AUTOINCREMENT,
                       `words` varchar(64),
                       `count` INTEGER,
                       `time` INTEGER,
                       `update_time` INTEGER)
                       '''
                self.__sql.execute(msql)

                '''
                敏感词排行榜 works
                id  主键
                words  敏感词
                count  敏感词数量
                time  添加时间
                update_time  更新时间
                '''

                # 告警表
            if not self.__sql.table('sqlite_master').where('type=? AND name=?', ('table', 'notice')).count():
                msql = '''CREATE TABLE IF NOT EXISTS `notice` (
                       `id` INTEGER PRIMARY KEY AUTOINCREMENT,
                       `site_id` INTEGER,
                       `site_name` varchar(256),
                       `title` varchar(64),
                       `body` TEXT,
                       `type` varchar(16),
                       `is_notice` INTEGER DEFAULT 0)
                       '''
                self.__sql.execute(msql)

                '''
                告警表
                id  主键
                site_id  网站id
                site_name  网站名称
                title  标题
                body  内容
                type  类型
                is_notice  是否通知 1 代表通知 0 代表未通知
                '''
        else:
            self.__sql = totle_db.Sql()
        # 二次检查，是否出现有数据库，缺少表的情况
        self.ensure_content_schema()

    #取数据列表
    def GetDataList(self,get):
        return public.M("sites").where("project_type=?","PHP").select()

    def get_report(self,get):
        '''
            @name 获取扫描报告
            @author lkq@bt.cn
            @time 2022-10-10
            @param get.testing_id 测试id
            @return socre 评分
            @return risk 风险列表
            @return risk_update 风险更新列表
        '''

        testing_id=get.testing_id
        if self.M("testing").where("testing_id=?",(testing_id,)).count() ==0:
            return public.ReturnMsg(False,'不存在该扫描')
        result ={}
        result['info']=self.M("testing").where("testing_id=?",(testing_id,)).select()[0]
        #评分 99-100 优秀 90-98 良好 80-89 中等 70-79 较差 60-69 差 0-59 很差
        result['score'] = 100
        #查看风险数
        risks = self.M("risk").where("testing_id=?",(testing_id,)).select()
        risk_list=[]
        risk_update=[]
        for i in risks:
            if i['risk_type'] in ['title','descriptions','keywords','body']:
                if i['risk_content']=='涉政' or i['risk_content']=='国家领导人':
                    result['score'] = result['score'] - 10
                elif i['risk_content']=='赌博' or i['risk_content']=='色情':
                    result['score'] = result['score'] - 5
                else:
                    result['score'] = result['score'] - 3
                risk_list.append(i)
            else:
                risk_update.append(i)

        if result['score'] < 0:
            result['score'] = 0
        result['risk']=risk_list
        result['risk_update'] = risk_update
        return result


    def __check_auth(self):
        '''
            @name 检测授权
            @author lkq@bt.cn
            @time 2022-10-10
            @return bool
        '''
        from pluginAuth import Plugin
        plugin_obj = Plugin(False)
        plugin_list = plugin_obj.get_plugin_list()
        return int(plugin_list['ltd']) > time.time()

    def check_auth(self, get):
        '''
            @name 检测授权
            @author lkq@bt.cn
            @time 2022-10-10
            @return bool
        '''
        if self.__check_auth():
            return public.ReturnMsg(True, "ok")
        else:
            return public.ReturnMsg(False, "未授权")

    def init_site_db(self, site_name):
        '''
            @name 初始化数据库
            @authr lkq@bt.cn
            @time 2022-09-23
            @return bool
        '''
        # 监控网站的表
        with totle_db.Sql(site_name) as sql:
            if not sql.table('sqlite_master').where('type=? AND name=?', ('table', 'url')).count():
                msql = '''CREATE TABLE IF NOT EXISTS `url` (
                `id` INTEGER PRIMARY KEY AUTOINCREMENT,
                `url` varchar(1000),
                `level` INTEGER,
                `time` varchar(16),
                `update_time` varchar(16),
                `father_id` INTEGER
                )'''
                sql.execute(msql)
                sql.execute("CREATE INDEX urls ON url(url)")
                sql.execute("CREATE INDEX father_id ON url(father_id)")

        with totle_db.Sql(site_name + "_info") as sql:
            if not sql.table('sqlite_master').where('type=? AND name=?', ('table', 'urlinfo')).count():
                msql = '''CREATE TABLE IF NOT EXISTS `urlinfo` (
                `id` INTEGER PRIMARY KEY AUTOINCREMENT,
                `urlid` INTEGER,
                `time` varchar(16),
                `update_time` varchar(16),
                `title` varchar(1024),
                `keywords` varchar(1024),
                `description` varchar(1024),
                `title_hash` varchar(64),
                `tail_hash` varchar(64),
                `is_status` INTEGER
                )'''
                sql.execute(msql)
                sql.execute("CREATE INDEX info_urlid ON urlinfo(urlid)")
                sql.execute("CREATE INDEX info_title ON urlinfo(title)")
                sql.execute("CREATE INDEX info_keywords ON urlinfo(keywords)")
                sql.execute("CREATE INDEX info_description ON urlinfo(description)")
                sql.execute("CREATE INDEX info_title_hash ON urlinfo(title_hash)")
                sql.execute("CREATE INDEX info_tail_hash ON urlinfo(tail_hash)")

    def site_M(self, site_name, table):
        '''
            @name 获取网站数据库信息
            @authr lkq@bt.cn
            @time 2022-10-10
            @param site_name 网站名称
            @param table 表名
            @return 数据库对象
        '''
        with totle_db.Sql(site_name) as sql:
            return sql.table(table)

    def M(self, table):
        '''
            @数据库操作对象
            @authr lkq@bt.cn
            @time 2022-10-10
            @param table 表名
            @return 数据库对象
        '''
        return self.__sql.table(table)

    def test(self):
        pass

    def M_info(self, table):
        '''
            @name 获取网站数据库信息
            @authr lkq@bt.cn
            @time 2022-10-10
            @param table 表名
            @return 数据库对象
        '''
        with totle_db.Sql() as sql:
            return sql.table(table)

    def ensure_content_schema(self):
        # 确保数据库表存在，二次检测，避免数据库表不存在导致的错误
        if self.__sql is None:
            self.__sql = totle_db.Sql()
        if not self.__sql.table('sqlite_master').where('type=? AND name=?', ('table', 'monitor_site')).count():
            msql = '''CREATE TABLE IF NOT EXISTS `monitor_site` (
                   `id` INTEGER PRIMARY KEY AUTOINCREMENT,
                   `name` varchar(500),
                   `method` INTEGER,
                   `site_name` varchar(256) ,
                   `url` varchar(500),
                   `time` INTEGER,
                   `is_local` INTEGER,
                   `send_msg` INTEGER,
                   `send_type` varchar(256),
                    `cron_id`  INTEGER,
                    `scan_config` varchar(1000)
                   )'''
            self.__sql.execute(msql)
        if not self.__sql.table('sqlite_master').where('type=? AND name=?', ('table', 'risk')).count():
            msql = '''CREATE TABLE IF NOT EXISTS `risk` (
                   `id` INTEGER PRIMARY KEY AUTOINCREMENT,
                   `site_id` INTEGER,
                   `site_name` varchar(256),
                   `url` varchar(1000),
                   `testing_id` varchar(32),
                   `content` TEXT,
                   `risk_content` varchar(64),
                   `risk_type` varchar(64),
                    `source_file` varchar(256) DEFAULT '',
                   `source_content_file` varchar(256) DEFAULT '',
                   `new_content_file` varchar(256) DEFAULT '',
                   `time` INTEGER
                   )'''
            self.__sql.execute(msql)
        if not self.__sql.table('sqlite_master').where('type=? AND name=?', ('table', 'testing')).count():
            msql = '''CREATE TABLE IF NOT EXISTS `testing` (
                   `id` INTEGER PRIMARY KEY AUTOINCREMENT,
                   `site_id` INTEGER,
                   `site_name` varchar(256),
                   `testing_id` varchar(32),
                   `start_time` INTEGER,
                   `end_time` INTEGER,
                   `risks` INTEGER,
                   `pid` INTEGER,
                   `scans` INTEGER,
                   `time` INTEGER)
                   '''
            self.__sql.execute(msql)
        if not self.__sql.table('sqlite_master').where('type=? AND name=?', ('table', 'works')).count():
            msql = '''CREATE TABLE IF NOT EXISTS `works` (
                   `id` INTEGER PRIMARY KEY AUTOINCREMENT,
                   `words` varchar(64),
                   `count` INTEGER,
                   `time` INTEGER,
                   `update_time` INTEGER)
                   '''
            self.__sql.execute(msql)
        if not self.__sql.table('sqlite_master').where('type=? AND name=?', ('table', 'notice')).count():
            msql = '''CREATE TABLE IF NOT EXISTS `notice` (
                   `id` INTEGER PRIMARY KEY AUTOINCREMENT,
                   `site_id` INTEGER,
                   `site_name` varchar(256),
                   `title` varchar(64),
                   `body` TEXT,
                   `type` varchar(16),
                   `is_notice` INTEGER DEFAULT 0)
                   '''
            self.__sql.execute(msql)

    def _select_monitor_sites(self):
        # 获取所有监控网站
        monitr_sites = self.M("monitor_site").order("time desc").select()
        if isinstance(monitr_sites, str):
            self.ensure_content_schema()
            monitr_sites = self.M("monitor_site").order("time desc").select()
            if isinstance(monitr_sites, str):
                return []
        return monitr_sites

    def get_time(self, tiems):
        '''
            @name 获取当前时间
            @authr lkq@bt.cn
            @param tiems 日期 2020-10-10
            @time 2022-10-10
            @return 时间戳
        '''
        timeArray = time.strptime(tiems, "%Y-%m-%d")
        timeStamp = int(time.mktime(timeArray))
        return timeStamp

    def risk_list(self, get):
        '''
            @name 概览风险列表
            @authr lkq@bt.cn
            @time 2022-10-10
            @return 风险列表
        '''
        result = {}
        # 今天和 7天前的时间
        today = time.strftime("%Y-%m-%d", time.localtime())
        today_int = self.get_time(today)
        # 获取7天前的时间
        result[today] = self.M("risk").where("time>=? and time<=?", (today_int, today_int + 86399)).count()
        # return result
        for i in range(1, 7):
            seven_day_ago = time.strftime("%Y-%m-%d", time.localtime(time.time() - (24 * 60 * 60) * i))
            today_int = self.get_time(seven_day_ago)
            result[seven_day_ago] = self.M("risk").where("time>=? and time<=?", (today_int, today_int + 86399)).count()
        return result

    def get_risk(self, get):
        '''
            @name 获取风险列表 带分页
            @authr lkq@bt.cn
            @time 2022-10-10
            @get.p int 页码
            @get.limit int 每页显示条数
            @return 风险列表
        '''
        import page
        page = page.Page()
        count = self.M('testing').count()
        limit = 20
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
        data['data'] = self.M('testing').order('id desc').limit(str(page.SHIFT) + ',' + str(page.ROW)).select()

        for i in data['data']:
            pid = i['pid']
            # 判断pid是否存在
            if os.path.exists("/proc/{}/cmdline".format(pid)):
                ddd = public.ReadFile("/proc/{}/cmdline".format(pid))
                if 'python' in ddd:
                    i['is_status'] = 1
                else:
                    i['is_status'] = 0
            else:
                i['is_status'] = 0
        return data
    def get_single_site_risk(self, get):
        '''
            @name 获取单个网站检测历史 带分页
            @authr lwh
            @time 2023-10-30
            @get.p int 页码
            @get.limit int 每页显示条数
            @get.site_name 网站名
            @return 风险列表
        '''
        import page
        page = page.Page()
        count = self.M('testing').where("site_name = ?", (get.site_name,)).count()
        limit = 20
        if hasattr(get, 'limit'):
            limit = int(get['limit'])
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
        data['data'] = self.M('testing').where("site_name = ?", (get.site_name,)).order('id desc').limit(str(page.SHIFT) + ',' + str(page.ROW)).select()

        for i in data['data']:
            pid = i['pid']
            # 判断pid是否存在
            if os.path.exists("/proc/{}/cmdline".format(pid)):
                ddd = public.ReadFile("/proc/{}/cmdline".format(pid))
                if 'python' in ddd:
                    i['is_status'] = 1
                else:
                    i['is_status'] = 0
            else:
                i['is_status'] = 0
        return data

    def get_risk_list(self, get):
        '''
            @name 获取风险列表 带分页
            @authr lkq@bt.cn
            @time 2022-10-10
            @get.p int 页码
            @get.limit int 每页显示条数
            @return 风险列表
        '''
        import page
        page = page.Page()
        count = self.M('risk').count()
        get.limit = get.get("limit", 20)
        info = {}
        info['count'] = count
        info['row'] = int(get.limit)
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
        data['data'] = self.M('risk').order('id desc').limit(str(page.SHIFT) + ',' + str(page.ROW)).select()
        return data

    def get_single_site_risk_list(self, get):
        '''
        @name 获取单个网站的风险列表 带分页
        @author lwh
        @time 2023-10-30
        @get.p int 页码
        @get.limit int 每页显示条数
        @get.site_name 网站名
        @return 风险列表
        '''
        import page
        page = page.Page()
        count = self.M('risk').where("site_name = ?", (get.site_name,)).count()
        limit = 20
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
        data['data'] = self.M('risk').where("site_name = ?", (get.site_name,)).order('id desc').limit(str(page.SHIFT) + ',' + str(page.ROW)).select()
        return data

    def get_risk_info(self, get):
        '''
            @name 获取告警信息
            @authr lkq@bt.cn
            @time 2022-10-10
            @param get 请求参数
            @return 告警信息
        '''
        if not 'testing_id' in get:
            return public.ReturnMsg(False, "请传递参数")

        import page
        page = page.Page()
        count = self.M('risk').where('testing_id=?', (get.testing_id,)).count()
        limit = 10
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
        data['data'] = self.M('risk').where('testing_id=?', (get.testing_id,)).order('id desc').limit(
            str(page.SHIFT) + ',' + str(page.ROW)).select()

        return data
        # return self.M('risk').where('testing_id=?', (get.testing_id,)).select()

    # 内容监控概览
    def get_content_monitor_overview(self, args):
        # 获取内容监控概览
        '''
            @name 内容监控概览
            @author lkq@bt.cn
            @time 2022-09-23
            @param {}
            @return
            1.  监控的数量  今日巡检次数 风险出现次数
            2. 网站内容检测的异常列表
            3. 敏感词排行
            4. 网站可用性
            5. 近7日巡检情况
        '''
        result = {}
        result['site_count'] = self.M('monitor_site').count()
        result['today_count'] = self.M('testing').where('time>=?', self.get_time(
            time.strftime("%Y-%m-%d", time.localtime()))).count()
        result['risk_count'] = self.M('risk').count()
        result['day_risk'] = self.M('risk').where('time>=?',
                                                  self.get_time(time.strftime("%Y-%m-%d", time.localtime()))).count()
        count2 = 0
        for i in self.get_cron_list_status(None):
            if not i['crontab_status']:
                count2 += 1
        result['crontab_count'] = result['site_count'] - count2
        result['not_crontab_count'] = count2

        # 检测异常列表
        info = self.M('testing').where('end_time>=?', 2).order('time desc').limit("10").select()
        for i in info:
            i['method'] = self.M('monitor_site').where('id=?', i['site_id']).getField('method')

        result['site_info'] = info
        # 敏感词排行

        infos = self.M('works').order('count desc').limit("10").select()
        ret = []
        for i in infos:
            if i['words'] == "title发生更改" or i['words'] == "description发生更改" or i['words'] == "keywords发生更改" or i[
                'words'] == "头部head发生更改" or i['words'] == "尾部script发生更改":
                continue
            else:
                if len(ret) >= 10:
                    break
                ret.append(i)

        result['sensitive_word'] = ret

        # 7天的风险出现次数
        result["7day_risk"] = self.risk_list(None)

        # 异常动态
        result['risk_info'] = self.M('risk').order('time desc').limit("10").select()

        # 计划任务数量

        return result

    # 获取监控列表
    def get_cron_list_status(self, args):
        '''
            @name 获取监控列表
            @author lkq@bt.cn
            @time 2022-09-23
            @return list
        '''
        monitr_sites = self.M("monitor_site").order("time desc").select()
        # monitr_sites = self._select_monitor_sites()
        for i in monitr_sites:
            cronte_id = i['cron_id']
            if public.M("crontab").where("id=?", cronte_id).count() == 0:
                i['crontab_status'] = 0
            else:
                i['crontab_status'] = 1
            # 上一次扫描时间
        return monitr_sites

    # 获取监控列表
    def get_content_monitor_list(self, args):
        '''
            @name 获取监控列表
            @author lkq@bt.cn
            @time 2022-09-23
            @return list
        '''
        monitr_sites = self.M("monitor_site").order("time desc").select()
        # monitr_sites = self._select_monitor_sites()
        for i in monitr_sites:
            try:
                i['scan_config'] = json.loads(i['scan_config'])
            except:
                i['scan_config'] = self.default_config(i['method'])
            cronte_id = i['cron_id']
            if public.M("crontab").where("id=?", cronte_id).count() == 0:
                i['crontab_status'] = 0
            else:
                i['crontab_status'] = 1
                args.id = cronte_id
                i['crontab_info'] = self.get_cron(args)
            # 上一次扫描时间
            if self.M("testing").where("site_id=?", i['id']).order("time desc").getField("time"):
                i['last_scan_time'] = self.M("testing").where("site_id=?", i['id']).order("time desc").getField("time")
            else:
                i['last_scan_time'] = []
            # 上一次风险数
            counts = self.M("testing").where("site_id=?", i['id']).order("time desc").getField("risks")
            testing_id = self.M("testing").where("site_id=?", i['id']).order("time desc").getField("testing_id")
            if testing_id:
                i['testing_id'] = testing_id
            else:
                i['testing_id'] = ""
            if counts:
                i['last_risk_count'] = counts
            else:
                i['last_risk_count'] = 0

        return monitr_sites
    # 获取监控列表

    def get_single_site_content_monitor_list(self, args):
        '''
            @name 获取单个网站监控列表
            @author lwh
            @time 2023-10-30
            @return list
        '''
        monitr_sites = self.M("monitor_site").where("site_name=?", (args.site_name,)).order("time desc").select()
        for i in monitr_sites:
            try:
                i['scan_config'] = json.loads(i['scan_config'])
            except:
                i['scan_config'] = self.default_config(i['method'])
            cronte_id = i['cron_id']
            if public.M("crontab").where("id=?", cronte_id).count() == 0:
                i['crontab_status'] = 0
            else:
                i['crontab_status'] = 1
                args.id = cronte_id
                i['crontab_info'] = self.get_cron(args)
            # 上一次扫描时间
            if self.M("testing").where("site_id=?", i['id']).order("time desc").getField("time"):
                i['last_scan_time'] = self.M("testing").where("site_id=?", i['id']).order("time desc").getField("time")
            else:
                i['last_scan_time'] = []
            # 上一次风险数
            counts = self.M("testing").where("site_id=?", i['id']).order("time desc").getField("risks")
            testing_id = self.M("testing").where("site_id=?", i['id']).order("time desc").getField("testing_id")
            if testing_id:
                i['testing_id'] = testing_id
            else:
                i['testing_id'] = ""
            if counts:
                i['last_risk_count'] = counts
            else:
                i['last_risk_count'] = 0

        return monitr_sites

    def ModifyCron(self, get, id,start_id):
        '''
            @name 添加监控的计划任务
            @authr lkq@bt.cn
            @time 2022-10-10
            @param get 计划任务信息
            @param id 计划任务id
            @return 返回中文格式的计划任务
        '''
        if get.method == 1:
            name = "[勿删]{}网站全站扫描风险关键词".format(get.site_name)
        elif get.method == 2:
            name = "[勿删]{}网站快速扫描风险关键词".format(get.site_name)
        elif get.method == 3:
            name = "[勿删]{}网站指定URl扫描风险关键词".format(get.site_name)
        else:
            name = "[勿删]{}网站扫描风险关键词".format(get.site_name)
        if not 'week' in get:
            get.week = ""
        args = {
            "id": id,
            "name": name,
            "type": get.type,
            "where1": get.where1,
            "hour": get.hour,
            "minute": get.minute,
            "sType": 'toShell',
            "sName": '',
            "backupTo": '',
            "save": '',
            "save_local": '1',
            "notice": '',
            "week": get.week,
            "notice_channel": '',
            "datab_name": '',
            "tables_name": '',
            "sBody": '{} /www/server/panel/class/projectModel/start_content.py {}'.format(public.get_python_bin(), start_id),
            "urladdress": ''
        }
        cron = crontab.crontab()
        return cron.modify_crond(args)

    # 修改监控信息
    def set_content_monitor_info(self, args):
        '''
            @name 修改监控信息
            @authr lkq@bt.cn
            @time 2022-09-23
            @return bool
        '''
        '''
            @name 添加监控信息
            @authr lkq@bt.cn
            @time 2022-09-23
            @param {
                type  计划任务的类型
                where1  计划任务的执行时间
                hour  计划任务的小时
                minute  计划任务的分钟
                method 监控方式
                site_name 站点名称
                site_url 站点地址
                scan_config 扫描配置
                    {
                        scan_thread: 20,   #扫描线程
                        scan_level: 20,  #扫描层次
                        scan_ua: 'ua',   #扫描ua
                        scan_args: 0,  #扫描参数
                        title: 0,     #扫描标题
                        descriptions: 0,  #扫描描述
                        keywords: 0,     #扫描关键字
                        title_hash: 1,  #扫描标题hash
                        tail_hash: 1, #扫描尾部hash
                        access: 0,   #扫描访问
                        search_monitor: 0, #搜索引擎监控
                        thesaurus: 1   #同义词
                        }
            }
            @return bool
        '''
        if not args.get('id'):
            return public.ReturnMsg(False, '请选择站点id')
        if not args.get('type'):
            return public.ReturnMsg(False, '请选择时间的类型')
        if not args.get('hour'):
            args.hour = ""
        if not args.get('minute'):
            return public.ReturnMsg(False, '请选择时间的分钟')
        if not args.get('where1'):
            args.where1 = ""

        if not args.get('method'):
            return public.ReturnMsg(False, '请选择监控方式')
        if not args.get('site_name'):
            return public.ReturnMsg(False, '请输入网站名称')
        if not args.get('url'):
            return public.ReturnMsg(False, '请输入网站的url')
        if not args.get('name'):
            args.name = "{}风险检测".format(args.site_name)

        if not args.get('is_local'):
            args.is_local = 0
        if not args.get('send_msg'):
            args.send_msg = 0
        if not args.get('send_type'):
            args.send_type = ""
        if not args.get('scan_config'):
            args.scan_config = self.default_config(args.method)
        else:
            try:
                scan_config = json.loads(args.scan_config)
            except:
                scan_config = self.default_config(args.method)
            if args.method == 1:
                scan_config['scan_level'] = 20
            if not 'scan_thread' in scan_config:
                scan_config['scan_thread'] = 20
            if not 'scan_level' in scan_config:
                scan_config['scan_level'] = 3
            if not 'scan_ua' in scan_config:
                scan_config[
                    'scan_ua'] = 'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)'
            if not 'scan_args' in scan_config:
                scan_config['scan_args'] = 0
            if not 'title' in scan_config:
                scan_config['title'] = 0
            if not 'descriptions' in scan_config:
                scan_config['descriptions'] = 0
            if not 'keywords' in scan_config:
                scan_config['keywords'] = 0
            if not 'title_hash' in scan_config:
                scan_config['title_hash'] = 1
            if not 'tail_hash' in scan_config:
                scan_config['tail_hash'] = 0
            if not 'access' in scan_config:
                scan_config['access'] = 0
            if not 'search_monitor' in scan_config:
                scan_config['search_monitor'] = 0
            if not 'thesaurus' in scan_config:
                scan_config['thesaurus'] = 1

        if self.M("monitor_site").where("id=?", args.id).count() == 0:
            return public.ReturnMsg(True, '当前项目不存在')

        # # 判断域名是否存在
        # if self.M("monitor_site").where('site_name=? and method=? and url=?',(args.site_name, args.method, args.url,)).count() == 0:
        #     return public.ReturnMsg(True, '当前项目不存在')
        monitor_site = self.M("monitor_site").where("id=?", args.id).find()
        monitor_site['scan_config'] = json.loads(monitor_site['scan_config'])
        if public.M('crontab').where('id=?',(monitor_site['cron_id'],)).count()>0:
            croninfo = self.ModifyCron(args, monitor_site['cron_id'], args.id)
            if not croninfo['status']:
                return public.ReturnMsg(False, '计划任务修改失败{}'.format(croninfo['msg']))
        # 修改计划任务

        if args.method in [1, 2, 3]:
            infos = {"name": args.name, "method": args.method, "site_name": args.site_name, "url": args.url,
                     "time": int(time.time()),
                     "is_local": args.is_local, "send_msg": args.send_msg, "send_type": args.send_type,
                     "scan_config": json.dumps(args.scan_config)}
            self.M("monitor_site").where("id=?", monitor_site['id']).update(infos)
            self.set_mod_push_conf(monitor_site['id'], infos["site_name"], bool(int(args.send_msg)), infos["send_type"])
            return public.ReturnMsg(True, '修改成功')
        else:
            return public.ReturnMsg(False, '修改失败')

    # 删除监控信息
    def del_content_monitor_info(self, args):
        '''
            @name 删除监控信息
            @authr lkq@bt.cn
            @time 2022-09-23
            @return bool
        '''
        if not args.get('id'):
            return public.ReturnMsg(False, '参数错误')
        id = args.id
        if self.M("monitor_site").where('id=?', (id,)).count() == 0:
            return public.ReturnMsg(False, '未找到该监控信息')
        # 首先删除计划任务
        monitor_sites = self.M("monitor_site").where('id=?', (id,)).find()

        # 删除监控表  monitor_site
        cront_id = monitor_sites['cron_id']
        if cront_id:
            # 删除计划任务
            args.id = cront_id
            crontab.crontab().DelLogs(args)
            crontab.crontab().DelCrontab(args)

        # 删除敏感词排行榜 works
        risk_info = self.M("risk").where('site_id=?', (id,)).select()
        for i in risk_info:
            counts = i['content']
            if self.M("works").where('words=?', (counts,)).count() >= 1:
                count = self.M("works").where('words=?', (counts,)).getField("count")
                if count <= 1:
                    self.M("works").where('words=?', (counts,)).delete()
                else:
                    self.M("works").where('words=?', (counts,)).setField("count", count - 1)

        # 然后删除风险表  risk
        self.M("risk").where('site_id=?', (id,)).delete()
        # 删除检测表  检测表 testing
        self.M("testing").where('site_id=?', (id,)).delete()
        # 删除监控表  monitor_site
        self.M("monitor_site").where('id=?', (id,)).delete()
        self.remove_mod_push_conf(id)
        return public.ReturnMsg(True, "删除成功")

    def AddCron(self, get, id):
        '''
            @name 添加监控的计划任务
            @authr lkq@bt.cn
            @time 2022-10-10
            @param get.method 扫描类型
            @param get.type 时间类型
            @param get.where1 计划任务的where1
            @param get.hour 小时
            @param get.minute 分钟
        '''
        if get.method == 1:
            name = "[勿删]{}网站全站扫描风险关键词".format(get.site_name)
        elif get.method == 2:
            name = "[勿删]{}网站快速扫描风险关键词".format(get.site_name)
        elif get.method == 3:
            name = "[勿删]{}网站指定URl扫描风险关键词".format(get.site_name)
        else:
            name = "[勿删]{}网站扫描风险关键词".format(get.site_name)
        args = {
            "name": name,
            "type": get.type,
            "where1": get.where1,
            "hour": get.hour,
            "minute": get.minute,
            "sType": 'toShell',
            "sName": '',
            "backupTo": '',
            "save": '',
            "save_local": '1',
            "notice": '',
            "notice_channel": '',
            "datab_name": '',
            "tables_name": '',
            "sBody": '{} /www/server/panel/class/projectModel/start_content.py {}'.format(public.get_python_bin(), id),
            "urladdress": ''
        }
        cron = crontab.crontab()
        return cron.AddCrontab(args)

    # 修复计划任务
    def repair_cron(self, get):
        '''
            @name 修复计划任务
            @authr lkq@bt.cn
            @param {
                id  当前扫描网站的id
                type  计划任务的类型
                where1  计划任务的执行时间
                hour  计划任务的小时
                minute  计划任务的分钟
            }
            @return  {"status":True|False,"msg":"成功|失败"}
        '''
        if not get.id:
            return public.ReturnMsg(False, '参数错误')
        if self.M("monitor_site").where('id=?', (get.id,)).count() == 0:
            return public.ReturnMsg(False, '没有当前网站的监控信息')
        if not get.get('type'):
            return public.ReturnMsg(False, '请选择时间的类型')
        if not get.get('hour'):
            get.hour = ""
        if not get.get('minute'):
            return public.ReturnMsg(False, '请选择时间的分钟')
        if not get.get('where1'):
            get.where1 = ""
        get.method = self.M("monitor_site").where('id=?', (get.id,)).getField('method')
        get.site_name = self.M("monitor_site").where('id=?', (get.id,)).getField('site_name')
        Cron = self.AddCron(get, get.id)
        if Cron['status']:
            self.M("monitor_site").where('id=?', (get.id,)).setField('cron_id', Cron['id'])
            return public.ReturnMsg(True, '修复成功')

    # 转换大写星期
    def toWeek(self, num):
        '''
            @name 转换大写星期
            @authr lkq@bt.cn
            @time 2022-10-10
            @param num  星期的数字
            @return  星期的大写
        '''
        wheres = {
            0: public.getMsg('CRONTAB_SUNDAY'),
            1: public.getMsg('CRONTAB_MONDAY'),
            2: public.getMsg('CRONTAB_TUESDAY'),
            3: public.getMsg('CRONTAB_WEDNESDAY'),
            4: public.getMsg('CRONTAB_THURSDAY'),
            5: public.getMsg('CRONTAB_FRIDAY'),
            6: public.getMsg('CRONTAB_SATURDAY')
        }
        try:
            return wheres[num]
        except:
            return ''

    def get_cron(self, get):
        '''
            @name 获取计划任务
            @authr lkq@bt.cn
            @time 2022-10-09
            @param {
                id  当前计划任务的id
                }
            @return {"status":True|False,"msg":"成功|失败"}
        '''

        if public.M("crontab").where("id=?", (get.id,)).count() == 0:
            return False
        else:
            cront = public.M("crontab").where("id=?", (get.id,)).find()
            # tmp = {}
            tmp = cront
            if cront['type'] == "day":
                tmp['type'] = public.getMsg('CRONTAB_TODAY')
                tmp['cycle'] = public.getMsg('CRONTAB_TODAY_CYCLE',
                                             (str(cront['where_hour']), str(cront['where_minute'])))
            elif cront['type'] == "day-n":
                tmp['type'] = public.getMsg('CRONTAB_N_TODAY', (str(cront['where1']),))
                tmp['cycle'] = public.getMsg('CRONTAB_N_TODAY_CYCLE', (
                    str(cront['where1']), str(cront['where_hour']), str(cront['where_minute'])))
            elif cront['type'] == "hour":
                tmp['type'] = public.getMsg('CRONTAB_HOUR')
                tmp['cycle'] = public.getMsg('CRONTAB_HOUR_CYCLE', (str(cront['where_minute']),))
            elif cront['type'] == "hour-n":
                tmp['type'] = public.getMsg('CRONTAB_N_HOUR', (str(cront['where1']),))
                tmp['cycle'] = public.getMsg('CRONTAB_N_HOUR_CYCLE',
                                             (str(cront['where1']), str(cront['where_minute'])))
            elif cront['type'] == "minute-n":
                tmp['type'] = public.getMsg('CRONTAB_N_MINUTE', (str(cront['where1']),))
                tmp['cycle'] = public.getMsg('CRONTAB_N_MINUTE_CYCLE', (str(cront['where1']),))
            elif cront['type'] == "week":
                tmp['type'] = public.getMsg('CRONTAB_WEEK')
                if not cront['where1']: cront['where1'] = '0'
                tmp['cycle'] = public.getMsg('CRONTAB_WEEK_CYCLE', (
                    self.toWeek(int(cront['where1'])), str(cront['where_hour']), str(cront['where_minute'])))
            elif cront['type'] == "month":
                tmp['type'] = public.getMsg('CRONTAB_MONTH')
                tmp['cycle'] = public.getMsg('CRONTAB_MONTH_CYCLE', (
                    str(cront['where1']), str(cront['where_hour']), str(cront['where_minute'])))
            log_file = '/www/server/cron/{}.log'.format(tmp['echo'])
            if os.path.exists(log_file):
                tmp['addtime'] = public.format_date(times=int(os.path.getmtime(log_file)))
            return tmp

    def default_config(self, method):
        '''
            @name 获取默认配置
            @authr lkq@bt.cn
            @time 2022-10-09
            @param method 代表扫描类型
            @return dict 返回默认配置
        '''
        if method == 1:
            scan_config = {
                'scan_thread': 20,
                'scan_level': 20,
                'scan_ua': 'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
                'scan_args': 0,
                'title': 0,
                'descriptions': 0,
                'keywords': 0,
                'title_hash': 1,
                'tail_hash': 0,
                'access': 0,
                'search_monitor': 0,
                'thesaurus': 1
            }
        else:
            scan_config = {
                'scan_thread': 20,
                'scan_level': 3,
                'scan_ua': 'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
                'scan_args': 0,
                'title': 0,
                'descriptions': 0,
                'keywords': 0,
                'title_hash': 1,
                'tail_hash': 0,
                'access': 0,
                'search_monitor': 0,
                'thesaurus': 1
            }
        return scan_config

    # 添加监控信息
    def add_content_monitor_info(self, args):
        '''
            @name 添加监控信息
            @authr lkq@bt.cn
            @time 2022-09-23
            @param {
                type  计划任务的类型
                where1  计划任务的执行时间
                hour  计划任务的小时
                minute  计划任务的分钟
                method 监控方式
                site_name 站点名称
                site_url 站点地址
                scan_config 扫描配置
                    {
                        scan_thread: 20,   #扫描线程
                        scan_level: 20,  #扫描层次
                        scan_ua: 'ua',   #扫描ua
                        scan_args: 0,  #扫描参数
                        title: 0,     #扫描标题
                        descriptions: 0,  #扫描描述
                        keywords: 0,     #扫描关键字
                        title_hash: 1,  #扫描标题hash
                        tail_hash: 1, #扫描尾部hash
                        access: 0,   #扫描访问
                        search_monitor: 0, #搜索引擎监控
                        thesaurus: 1   #同义词
                        }
            }
            @return bool
        '''
        if not args.get('type'):
            return public.ReturnMsg(False, '请选择时间的类型')
        if not args.get('hour'):
            args.hour = ""
        if not args.get('minute'):
            return public.ReturnMsg(False, '请选择时间的分钟')
        if not args.get('where1'):
            args.where1 = ""
        if not args.get('method'):
            return public.ReturnMsg(False, '请选择监控方式')
        if not args.get('url'):
            return public.ReturnMsg(False, '请输入网站的url')
        if args.method == 3 or args.method == "3":
            if not args.url.startswith("http://"):
                if not args.url.startswith("https://"):
                    return public.ReturnMsg(False, 'url需要以http://或者https://开头')
            url = args.url
            if url.startswith("https://"):
                url = url.replace("https://", "")
            else:
                url = url.replace("http://", "")
            site_name = url.split("/")[0]
            args.site_name = site_name
        if not args.get('site_name'):
            return public.ReturnMsg(False, '请输入网站名称')
        if not args.get('name'):
            args.name = "{}风险检测".format(args.site_name)
        if not args.get('is_local'):
            args.is_local = 0
        if not args.get('send_msg'):
            args.send_msg = 0
        if not args.get('send_type'):
            args.send_type = ""
        if not args.get('scan_config'):
            args.scan_config = self.default_config(args.method)
            #return  args.scan_config
        else:
            try:
                scan_config = json.loads(args.scan_config)
            except:
                scan_config = self.default_config(args.method)
            if args.method == 1:
                scan_config['scan_level'] = 20
            if not 'scan_thread' in scan_config:
                scan_config['scan_thread'] = 20
            if not 'scan_level' in scan_config:
                scan_config['scan_level'] = 3
            if not 'scan_ua' in scan_config:
                scan_config[
                    'scan_ua'] = 'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)'
            if not 'scan_args' in scan_config:
                scan_config['scan_args'] = 0
            if not 'title' in scan_config:
                scan_config['title'] = 0
            if not 'descriptions' in scan_config:
                scan_config['descriptions'] = 0
            if not 'keywords' in scan_config:
                scan_config['keywords'] = 0
            if not 'title_hash' in scan_config:
                scan_config['title_hash'] = 1
            if not 'tail_hash' in scan_config:
                scan_config['tail_hash'] = 0
            if not 'access' in scan_config:
                scan_config['access'] = 0
            if not 'search_monitor' in scan_config:
                scan_config['search_monitor'] = 0
            if not 'thesaurus' in scan_config:
                scan_config['thesaurus'] = 1

        #return args.scan_config
        # 判断域名是否存在
        if self.M("monitor_site").where('site_name=? and method=? and url=?',
                                        (args.site_name, args.method, args.url,)).count() > 0:
            return public.ReturnMsg(True, '已经存在,请勿重复添加')

        if args.method in [1, 2, 3]:
            infos = {"name": args.name, "method": args.method, "site_name": args.site_name, "url": args.url,
                     "time": int(time.time()), "is_local": args.is_local, "send_msg": args.send_msg,
                     "send_type": args.send_type, "scan_config": json.dumps(args.scan_config)}
            id = self.M("monitor_site").insert(infos)
            cron_info = self.AddCron(args, id)
            if cron_info['status']:
                cron_id = cron_info['id']
                self.M("monitor_site").where('id=?', (id,)).update({"cron_id": cron_id})
                if bool(infos["send_msg"]):
                    self.set_mod_push_conf(id, infos["site_name"], True, infos["send_type"])
                return public.ReturnMsg(True, '添加成功')
            else:
                self.M("monitor_site").where('id=?', (id,)).delete()
                return public.ReturnMsg(False, '计划任务添加失败,{}'.format(cron_info['msg']))
        else:
            return public.ReturnMsg(False, '请选择监控方式')

    def get_thesaurus(self, get):
        '''
            @name 获取自定义词库
            @param get
            @time 2022-10-12
            @return list
        '''
        if os.path.exists(self.__path + "/thesaurus.json"):
            try:
                thesaurus = json.loads(public.ReadFile(self.__path + "/thesaurus.json"))
            except:
                public.WriteFile(self.__path + "/thesaurus.json", "[]")
                return []
            #过滤xss
            for i in range(len(thesaurus)):
                thesaurus[i] =public.xsssec(thesaurus[i])
            return thesaurus
        else:
            public.WriteFile(self.__path + "/thesaurus.json", "[]")
            return []

    # 添加关键词
    def add_thesaurus(self, get):
        '''
            @name 获取自定义词库
            @param get.key 关键词
            @time 2022-10-12
            @return {"status":True|False,"msg":"提示信息"}
        '''
        if not get.get('key'):
            return public.ReturnMsg(False, '请输入关键词')
        thesaurus = self.get_thesaurus(get)
        if len(thesaurus) > 100:
            return public.ReturnMsg(False, '自定义词库最多100个')
        if get.key.strip() in thesaurus:
            return public.ReturnMsg(False, '关键词已经存在')
        if len(get.key.strip()) < 2:
            return public.ReturnMsg(False, '关键词长度不能小于2')
        thesaurus.append(get.key.strip())
        public.WriteFile(self.__path + "/thesaurus.json", json.dumps(thesaurus))
        return public.ReturnMsg(True, '添加成功')

    # 导入关键词
    def import_thesaurus(self, get):
        '''
            @name 添加自定义关键词
            @author lkq@bt.cn
            @time 2022-10-12
            @param {
                 key=你好啊\r你好帅
            }
            #参数为一行一个
            @return {"status":True|False,"msg":"成功|失败"}
        '''
        if not get.get('key'):
            return public.ReturnMsg(False, '请输入关键词')
        padata = get.key.strip().split()
        if not padata:
            return public.ReturnMsg(False, '请输入关键词')
        thesaurus = self.get_thesaurus(get)
        if len(thesaurus) > 100:
            return public.ReturnMsg(False, '自定义词库最多100个')
        for i in padata:
            if i not in thesaurus:
                if len(i) < 3:
                    continue
                if len(thesaurus) > 100:
                    break
                thesaurus.append(i)

        public.WriteFile(self.__path + "/thesaurus.json", json.dumps(thesaurus))
        return public.ReturnMsg(True, '添加成功')

    # 删除关键词
    def del_thesaurus(self, get):
        '''
            @name 删除自定义关键词
            @author lkq@bt.cn
            @time 2022-10-12
            @param {
                 key=你好啊
            }
            @return {"status":True|False,"msg":"成功|失败"}
        '''
        padata = get.key.strip()
        if not padata:
            return public.ReturnMsg(False, '请输入关键词')
        thesaurus = self.get_thesaurus(get)
        if padata in thesaurus:
            thesaurus.remove(padata)
        public.WriteFile(self.__path + "/thesaurus.json", json.dumps(thesaurus))
        return public.ReturnMsg(True, '删除成功')

    # 清空关键词
    def clear_thesaurus(self, get):
        '''
            @name 清空自定义关键词
            @author lkq@bt.cn
            @time 2022-10-12
            @param {
            }
            @return {"status":True|False,"msg":"成功|失败"}
        '''
        public.WriteFile(self.__path + "/thesaurus.json", "[]")
        return public.ReturnMsg(True, '清空成功')

    def scanning(self, get):
        '''
            @name 手动扫描站点
            @author lkq@bt.cn
            @param get.id 扫描的id信息
            @time 2022-10-12
            @return {"status":True|False,"msg":"成功|失败"}
        '''
        path_info = public.Md5(str(get.id)) + ".txt"
        public.WriteFile("/dev/shm/" + path_info, "")
        pythons = public.get_python_bin()
        pid = self.M("testing").where("site_id=?", get.id).order("id desc").limit("1").getField("pid")
        if pid:
            if os.path.exists("/proc/{}/cmdline".format(pid)):
                ret = public.ReadFile("/proc/{}/cmdline".format(pid))
                if ret and "python" in ret and str(get.id) in ret:
                    return {"status": True, "msg": "正在进行扫描1", "path_info": "/dev/shm/" + path_info}
        public.ExecShell("nohup  {} /www/server/panel/class/projectModel/start_content.py {} &".format(pythons, get.id))
        return {"status": True, "msg": "正在进行扫描2", "path_info": "/dev/shm/" + path_info,"cmd":("nohup  {} /www/server/panel/class/projectModel/start_content.py {} &".format(pythons, get.id))}

    def kill_scanning(self, get):
        '''
            @name 结束扫描站点
            @author
            @param get.id 扫描的id信息
        '''
        test_info = self.M('testing').where("site_id=?", get.id).order("time desc").select()
        count = 0
        if len(test_info) > 0:
            i = test_info[0]
            if i['end_time'] == 0:
                # 如果这个pid还在运行则杀死
                if os.path.exists("/proc/%s" % i['pid']):
                    if os.path.exists("/proc/{}/cmdline".format(i['pid'])):
                        with open("/proc/{}/cmdline".format(i['pid']), 'rb') as f:
                            cmdline = f.read().decode('utf-8')
                            if cmdline.find("python") != -1:
                                count += 1
                                import signal
                                os.kill(int(i['pid']), signal.SIGKILL)
                                risks = self.M_info("risk").where("testing_id=?", i['testing_id']).count()
                                self.M('testing').where("id=?", i['id']).update(
                                    {"end_time": 1, "risks": risks})
                    else:
                        risks = self.M_info("risk").where("testing_id=?", i['testing_id']).count()
                        if risks > 0:
                            self.M('testing').where("id=?", i['id']).update({"end_time": 1, "risks": risks})
        if count >= 1:

            return public.ReturnMsg(True, '结束进程成功')
        else:
            return {"status": True, "msg": "结束进程成功"}

    def send_mail_data(self, title, body, login_type):
        '''
            @name 发送告警通知
            @author lkq@bt.cn
            @time 2022-10-12
            @param title 标题
            @param body 内容
            @param login_type 发送的类型
            @return bool True|False
        '''
        path = '/www/server/panel/class/msg/' + login_type + '_msg.py'
        if not os.path.exists(path):
            return False
        object = public.init_msg(login_type)
        if login_type == "mail":
            data = {}
            data['title'] = title
            data['msg'] = body
            object.push_data(data)
        elif login_type == "wx_account":
            object.send_msg(body)
        else:
            msg = public.get_push_info("网站内容告警", ['>发送内容：' + body])
            object.push_data(msg)
        return True

    def write_logs(self, logs, info):
        '''
            @name 写入日志信息
            @author lkq@bt.cn
            @time 2022-10-10
            @param logs  文件路径
            @param info 信息

        '''
        if logs:
            public.WriteFile(logs, info + "\n", "a+")

    def start(self, get):
        '''
            @name 开启扫描入口函数
            @auther: lkq@bt.cn
            @time 2022-10-12
            @param id: 扫描的站点ID
            @param logs: 日志文件
        '''
        id = get.id
        logs = get.path
        if self.M("monitor_site").where("id=?", id).count() == 0:
            print("任务不存在")
            self.write_logs(logs, "任务不存在")
            exit(0)
        monitr_site = self.M("monitor_site").where("id=?", id).find()
        start_time = int(time.time())
        # 生成随机字符串为本地扫描的ID
        rendomID = public.GetRandomString(10)
        try:
            monitr_site['scan_config'] = json.loads(monitr_site['scan_config'])
        except:
            monitr_site['scan_config'] = self.default_config(monitr_site['method'])
        # 检查残留进程
        test_info = self.M('testing').where("site_id=?", monitr_site['id']).select()
        for i in test_info:
            if i['end_time'] == 0:
                # 如果这个pid还在运行则杀死
                if os.path.exists("/proc/%s" % i['pid']):
                    if os.path.exists("/proc/{}/cmdline".format(i['pid'])):
                        with open("/proc/{}/cmdline".format(i['pid']), 'rb') as f:
                            cmdline = f.read().decode('utf-8')
                            if cmdline.find("python") != -1:
                                import signal
                                os.kill(int(i['pid']), signal.SIGKILL)
                                risks = self.M_info("risk").where("testing_id=?", i['testing_id']).count()
                                self.M('testing').where("id=?", i['id']).update({"end_time": 1, "risks": risks})
                    else:
                        risks = self.M_info("risk").where("testing_id=?", i['testing_id']).count()
                        if risks > 0:
                            self.M('testing').where("id=?", i['id']).update({"end_time": 1, "risks": risks})
        # 如果是手动扫描的话则最大深度为3
        if monitr_site['method']==1:
           monitr_site['scan_config']['scan_level'] = 20
        else:
            monitr_site['scan_config']['scan_level'] = 3
        url = {"is_local": monitr_site['is_local'], "url": monitr_site['url'],
               "crawl_deepth": monitr_site['scan_config']['scan_level'],
               "args": monitr_site['scan_config']['scan_args'], "site_name": monitr_site['site_name'],
               "ua": monitr_site['scan_config']['scan_ua'],
               "rendomID": rendomID, "site_id": monitr_site['id'], "method": monitr_site['method'],
               "configs": monitr_site['scan_config'], "logs": logs}
        spider = Spider(url)
        # 检测一下数据库是否被锁
        urlinfo = spider.M2("urlinfo").find()
        if type(urlinfo) == str:
            if urlinfo.endswith("database is locked"):
                # 删除数据库
                public.ExecShell(
                    "rm -rf /www/server/panel/class/projectModel/content/{}_info.db".format(monitr_site['site_name']))
                public.ExecShell(
                    "rm -rf /www/server/panel/class/projectModel/content/{}_info.db-journal".format(
                        monitr_site['site_name']))
                # 重新创建数据库
                self.init_site_db(monitr_site['site_name'])

        urlsinf = spider.M1("url").find()
        if type(urlsinf) == str:
            if urlsinf.endswith("database is locked"):
                # 删除数据库
                public.ExecShell(
                    "rm -rf /www/server/panel/class/projectModel/content/{}.db".format(monitr_site['site_name']))
                public.ExecShell(
                    "rm -rf /www/server/panel/class/projectModel/content/{}.db-journal".format(
                        monitr_site['site_name']))
                # 重新创建数据库
                # print("锁死了，重新建立数据库")
                self.init_site_db(monitr_site['site_name'])

        tesing = {"site_id": monitr_site['id'], "site_name": monitr_site['site_name'], "testing_id": rendomID,
                  "start_time": start_time, "end_time": 0, "risks": 0, "scans": 0, "time": start_time,
                  "pid": os.getpid()}
        self.M('testing').insert(tesing)
        public.WriteFile(logs,"")
        print("正在开始扫描")
        self.write_logs(logs, "正在开始扫描")
        scans = spider.crawler(url)
        # 结束的时候更新一下扫描表
        end_time = int(time.time())
        # 更新数量
        print("扫描即将结束....正在统计风险...")
        self.write_logs(logs, "扫描即将结束....正在统计风险")
        if monitr_site['method'] != 3:
            time.sleep(10)

        # scans = spider.M1("url").count()
        self.M("testing").where("testing_id=?", rendomID).update({"end_time": end_time, "scans": scans})
        # 告警通知 1 为开启 0 为关闭

        risks = self.M_info("risk").where("testing_id=?", rendomID).count()
        self.write_logs(logs, "扫描结束，耗时%s秒 共扫描%s个页面，发现%s个风险" % (end_time - start_time, scans, risks))
        if monitr_site['send_msg'] == 1 or monitr_site['send_msg']:
            # 存在风险的时候发送告警
            if risks > 0:
                body = "[{}]网站内容安全扫描成功，共扫描{}个页面，发现{}个风险,请及时处理".format(monitr_site['site_name'], scans, risks)
                print("发送告警")
                # self.send_mail_data("%s网站内容扫描" % monitr_site['site_name'], body, monitr_site['send_type'])
                self.push_msg_by_id(id, body)
        print("扫描结束，耗时%s秒 共扫描%s个页面，发现%s个风险" % (end_time - start_time, scans, risks))

    def in_thesaurus(self, args):
        '''
            @name 导入命令
            @author law<2023-11-13>
            @param  args
            @return
        '''
        try:
            command_file_path = "/tmp/inthesaurus.txt"
            from files import files
            fileObj = files()
            ff = fileObj.upload(args)
            if ff["status"]:
                data = public.readFile(command_file_path)
                # 导入数据
                get = public.to_dict_obj({})
                get.key = data
                # 删除临时文件
                if os.path.exists(command_file_path):
                    public.ExecShell(command_file_path)
                return self.import_thesaurus(get)
            else:
                return public.returnMsg(False, '导入失败')
        except:
            return public.returnMsg(False, traceback.format_exc())

    def out_thesaurus(self, args):
        '''
            @name 导出命令
            @author law<2023-11-13>
            @return .csv
        '''
        export_file_path = "/tmp/outthesaurus.txt"
        # 删除临时文件
        if os.path.exists(export_file_path):
            os.remove(export_file_path)
        try:
            # 获取数据
            thesaurus = '\n'.join(self.get_thesaurus(None))
            public.WriteFile(export_file_path, thesaurus)
            return public.returnMsg(True, export_file_path)
        except Exception as e:
            return public.returnMsg(False, '导出失败')

    @staticmethod
    def set_mod_push_conf(mvw_id: int, site_name: str, status: bool, sender: str):
        if "/www/server/panel" not in sys.path:
            sys.path.insert(0, "/www/server/panel")
        from mod.base.push_mod.safe_mod_push import SiteMonitorViolationWordTask
        SiteMonitorViolationWordTask.set_push_task(mvw_id, site_name, status, sender.split(","))

    @staticmethod
    def remove_mod_push_conf(mvw_id: int):
        if "/www/server/panel" not in sys.path:
            sys.path.insert(0, "/www/server/panel")
        from mod.base.push_mod.safe_mod_push import SiteMonitorViolationWordTask
        SiteMonitorViolationWordTask.remove_push_task(mvw_id)

    @staticmethod
    def push_msg_by_id(mvw_id: int, msg: str):
        if "/www/server/panel" not in sys.path:
            sys.path.insert(0, "/www/server/panel")
        from mod.base.push_mod import push_by_task_keyword
        push_by_task_keyword(
            "site_monitor_violation_word",
            "site_mvw_{}".format(mvw_id),
            push_data={"msg_list": [msg]}
        )


class Spider(main):
    '''
        @name 真正的爬取程序
        @param 线程数默认30
        @time 2022-10-12

    '''
    _max_thread = 30
    _threads = {}
    __addurlinfo = []
    __add_url = []
    source = "/www/server/panel/class/projectModel/content/source"
    hash = "/www/server/panel/class/projectModel/content/hash"

    # 需要传递扫描的URL 扫描的域名 需要扫描的id

    def __init__(self, monitor_site=None):
        if not monitor_site or len(monitor_site) == 0:
            print("没有传递扫描的网站信息")
            exit(0)
        super().__init__()
        self.lok = threading.RLock()  # 递归锁
        self.unvisited = []  # 未访问过的url初始化列表
        self.monitor_site = monitor_site
        self.domains = monitor_site['site_name']
        if not os.path.exists('class/projectModel/content/{}.db'.format(self.domains)):
            self.init_site_db(self.domains)
        self.OneAdd(monitor_site['url'], 0, monitor_site['url'])  # 并将需要爬取的url添加进linkQuence对列中
        if not os.path.exists(self.source):
            os.makedirs(self.source, 0o755, True)
        if not os.path.exists(self.hash):
            os.makedirs(self.hash, 0o755, True)
        if not os.path.exists(self.hash + "/{}".format(self.domains)):
            os.makedirs(self.hash + "/{}".format(self.domains), 0o755, True)

    def add_info(self, visitedUrl):
        '''
            @name 添加需要扫描的URl的信息到url数据库中
            @param visitedUrl 格式 [url,等级,time,父级urlid]
            @time 2022-10-12
            @return True|False
        '''

        if visitedUrl['url'].endswith('/') or visitedUrl['url'].endswith('.'):
            visitedUrl['url'] = visitedUrl['url'][:-1]
        if self.M1("url").where("url=?", (visitedUrl['url'],)).count():
            return
        else:
            id = self.M1("url").where("url=?", visitedUrl['parent']).getField("id")
            if id:
                inf = [visitedUrl['url'], int(time.time()), int(time.time()), id, visitedUrl['level']]
            else:
                inf = [visitedUrl['url'], int(time.time()), int(time.time()), 1, visitedUrl['level']]
            self.__add_url.append(inf)
            if len(self.__add_url) >= 20:
                _obj = self.M1("url")
                for i in self.__add_url:
                    _obj.addAll("url,level,time,update_time,father_id", i)
                _obj.commit()
                self.__add_url = []

    def one_add_info(self, visitedUrl):
        '''
            @name 初始化添加需要扫描的URl的信息到url数据库中
            @param visitedUrl 格式 [url,等级,time,父级urlid]
            @time 2022-10-12
            @return True|False
        '''

        if visitedUrl['url'].endswith('/') or visitedUrl['url'].endswith('.'):
            visitedUrl['url'] = visitedUrl['url'][:-1]
        if self.M1("url").where("url=?", (visitedUrl['url'],)).count():
            pass
        else:
            id = self.M1("url").where("url=?", visitedUrl['parent']).getField("id")
            if id:
                inf = [visitedUrl['url'], int(time.time()), int(time.time()), id, visitedUrl['level']]
            else:
                inf = [visitedUrl['url'], int(time.time()), int(time.time()), 1, visitedUrl['level']]
            self.__add_url.append(inf)
            if len(self.__add_url) >= 20:
                _obj = self.M1("url")
                for i in self.__add_url:
                    _obj.addAll("url,level,time,update_time,father_id", i)
                _obj.commit()
                self.__add_url = []

    def add_risk_scan_config(self, infos, source, new, content, risk_content, risk_type):
        '''
        @name 扫描到更改的时候添加到风险risk数据库中
        @author lkq@bt.cn
        @time 2022-10-12
        @param infos {
            infos  risk
            id  主键
            site_id  网站id
            site_name  网站名称
            url  风险url
            testing_id  测试id
            content  风险内容
            risk_content  风险类型
            risk_type  风险位置
            source_file 风险文件存放位置            #当风险位置为title,descriptions,keywords,body时才使用
            source_content_file   更改原始内容文件路径  #当风险位置不为title,descriptions,keywords,body的时候使用
            new_content_file  更改后的内容文件路径     #当风险位置不为title,descriptions,keywords,body的时候使用
            time  添加时间
        }
        @param source 修改前的内容
        @param new 修改后的内容
        @param content 风险描述
        @param risk_content 风险类型
        @param risk_type 风险位置
        @return True|False
        '''

        if self.M_info("risk").where("url=? and testing_id=?", (infos['url'], infos['rendomID'])).count() == 0:
            source_path = public.Md5(public.GetRandomString(32))
            public.WriteFile(self.source + "/" + source_path + ".txt", source)
            new_path = public.Md5(public.GetRandomString(32))
            public.WriteFile(self.source + "/" + new_path + ".txt", new)
            if risk_type in ['title_hash_update', 'tail_hash_update']:
                infos = {"site_id": infos['site_id'], "site_name": infos['site_name'], "url": infos['url'],
                         "testing_id": infos['rendomID'],
                         "content": content, "risk_content": risk_content, "risk_type": risk_type,
                         "source_file": "", "source_content_file": source + ".txt",
                         "new_content_file": new + ".txt",
                         "time": int(time.time())}
            else:
                infos = {"site_id": infos['site_id'], "site_name": infos['site_name'], "url": infos['url'],
                         "testing_id": infos['rendomID'],
                         "content": content, "risk_content": risk_content, "risk_type": risk_type,
                         "source_file": "", "source_content_file": source_path + ".txt",
                         "new_content_file": new_path + ".txt",
                         "time": int(time.time())}

            self.M_info("risk").insert(infos)
            keys = content.split(",")
            for i2 in keys:
                if self.M_info("works").where("words=?", (i2,)).count() >= 1:
                    count = self.M_info("works").where("words=?", (i2,)).getField("count")
                    if type(count) == int:
                        self.M_info("works").where("words=?", (i2,)).update(
                            {"count": count + 1, "update_time": int(time.time())})
                else:
                    self.M_info("works").insert(
                        {"words": i2, "count": 1, "time": int(time.time()), "update_time": int(time.time())})
            risks = self.M_info("risk").where("testing_id=?", infos['testing_id']).count()
            if risks:
                add_risk = self.M_info('testing').where("testing_id=?", infos['testing_id']).update({"risks": risks})
                if type(add_risk) == str:
                    print(add_risk)

    def add_urlinfo(self, info, configs):
        '''
            @name 添加数据到urlinfo 数据库中 用于存储扫描到的url的信息
            @author lkq@bt.cn
            @time 2022-10-12
            @param info {
                传递的内容如下 代表现在爬取的内容信息:
                    url_info = {}
                    url_info['title'] = titles
                    url_info['description'] = descriptions
                    url_info['keywords'] = keywords
                    url_info['title_hash'] = self.head_hash(soup,domains)
                    url_info['tail_hash'] = self.tail_hash(soup,domains)
            }
            @param configs {
                传递的内容如下 代表的为扫描的配置信息:
                {"configs": {"title":0,"descriptions":0,"keywords":0,"bodys":0,"tail_hash":0,"title_hash":0}}
            }
        '''

        url_id = info['id']
        # 判断是否是启动的时候添加的
        urlinfo = self.M2("urlinfo").where("urlid=?", url_id).find()
        if type(urlinfo) == str:
            print("urlinfo", urlinfo)
        if len(urlinfo) >= 1:
            flag = False
            if configs['configs']['title']:
                if urlinfo['title'] and info['title'] and urlinfo['title'] != info['title']:
                    # 更新了title
                    self.add_risk_scan_config(configs, urlinfo['title'], info['title'], "title发生更改", "title_update",
                                              "title_update")
                    flag = True
            # 如果更新了description
            if configs['configs']['descriptions']:
                if urlinfo['description'] and info['description'] and urlinfo['description'] != info['description']:
                    # 更新了description
                    print("更新了description")

                    self.add_risk_scan_config(configs, urlinfo['description'], info['description'], "description发生更改",
                                              "description_update",
                                              "description_update")
                    flag = True
            # 如果更新了keywords
            if configs['configs']['keywords']:
                if urlinfo['keywords'] and info['keywords'] and urlinfo['keywords'] != info['keywords']:
                    # 更新了keywords
                    print("更新了keywords")
                    self.add_risk_scan_config(configs, urlinfo['keywords'], info['keywords'], "keywords发生更改",
                                              "keywords_update",
                                              "keywords_update")
                    flag = True
            # 如果更新了title_hash
            if configs['configs']['title_hash']:
                if urlinfo['title_hash'] and info['title_hash'] and urlinfo['title_hash'] != info['title_hash']:
                    # 更新了title_hash
                    self.add_risk_scan_config(configs, urlinfo['title_hash'], info['title_hash'], "头部head发生更改",
                                              "title_hash_update",
                                              "title_hash_update")
                    flag = True
            # 如果更新了tail_hash
            if configs['configs']['tail_hash']:
                if urlinfo['tail_hash'] and info['tail_hash'] and urlinfo['tail_hash'] != info['tail_hash']:
                    # 更新了tail_hash
                    self.add_risk_scan_config(configs, urlinfo['tail_hash'], info['tail_hash'], "尾部script发生更改",
                                              "tail_hash_update",
                                              "tail_hash_update")
                    flag = True
            if flag:
                # 更新了
                datas = {"update_time": int(time.time()), "title": info['title'], "keywords": info['keywords'],
                         "description": info['description'], "title_hash": info['title_hash'],
                         "tail_hash": info['tail_hash'], "is_status": 1}
                UDD = self.M2("urlinfo").where("urlid=?", url_id).update(datas)
                self.M2("urlinfo").close()
                print("update add_urlinfo", UDD)
        else:
            inf = [url_id, info['title'], int(time.time()), info['keywords'], info['description'], info['title_hash'],
                   info['tail_hash'], 0, int(time.time())]
            self.__addurlinfo.append(inf)
            if len(self.__addurlinfo) >= 20:

                _obj = self.M2("urlinfo")
                for i in self.__addurlinfo:
                    _obj.addAll("urlid,title,time,keywords,description,title_hash,tail_hash,is_status,update_time", i)
                _obj.commit()
                self.__addurlinfo = []

    def addVisitedUrl(self, url, info, configs):  # 添加已访问过的url
        '''
            @name 添加已访问过的url
            @param url 访问过的url
            @param info 这个url的具体扫描出来的信息
            @param configs 配置信息
        '''

        id = self.M1("url").where("url=?", (url,)).getField("id")
        if id:
            info['id'] = id
            self.lok.acquire()
            self.add_urlinfo(info, configs)
            self.lok.release()
        cache.set(public.md5(url), 1, timeout=1080000)

    def OneAdd(self, url, level, parent_url):  # 添加未访问过的url
        '''
            @name初始化的时候添加未访问过的url
            @quthor lkq@bt.cn
            @param url 未访问过的url
            @param level 未访问过的url的等级
            @param parent_url 未访问过的url的父级url
        '''
        if url != '' and url:
            if cache.get(public.md5(url)):
                return
            cache.set(public.md5(url), 1, timeout=1080000)
            if url.endswith('/') or url.endswith('.'):
                url = url[:-1]
            urlinfo = {"url": url, "level": level, "parent": parent_url}
            self.one_add_info(urlinfo)
            self.unvisited.insert(0, urlinfo)
            return

    def addUnvisitedUrl(self, url, level, parent_url):  # 添加未访问过的url
        '''
            @name 添加未访问过的url
            @quthor lkq@bt.cn
            @param url 未访问过的url
            @param level 未访问过的url的等级
            @param parent_url 未访问过的url的父级url
        '''
        if url != '' and url:
            if cache.get(public.md5(url)):
                return
            self.lok.acquire()
            cache.set(public.md5(url), 1, timeout=1080000)
            if url.endswith('/') or url.endswith('.'):
                url = url[:-1]
            urlinfo = {"url": url, "level": level, "parent": parent_url}
            self.add_info(urlinfo)
            self.unvisited.insert(0, urlinfo)
            self.lok.release()
            return

    def popUnvisitedUrl(self):  # 从未访问过的url中取出一个url
        '''
            @name 从未访问过的url中取出一个url
            @quthor lkq@bt.cn
            @time 2022-10-10
            @return 返回一个url
        '''
        try:  # pop动作会报错终止操作，所以需要使用try进行异常处理
            self.lok.acquire()
            data = self.unvisited.pop()
            self.lok.release()
            return data
        except:
            self.lok.release()
            return None

    def unvisitedUrlEmpty(self):  # 判断未访问过列表是不是为空
        '''
            @name 判断未访问过列表是不是为空
            @quthor lkq@bt.cn
            @time 2022-10-10
            @return 返回一个bool值
        '''
        return len(self.unvisited) == 0

    def M1(self, table):
        '''
            @name 域名数据库中的url表对象
            @quthor lkq@bt.cn
            @time 2022-10-10
            @return 返回一个对象
        '''
        return self.site_M(self.domains, table)

    def M2(self, table):
        '''
            @name 域名_info 数据库中的urlinfo表对象
            @quthor lkq@bt.cn
            @time 2022-10-10
            @return 返回一个对象
        '''
        return self.site_M(self.domains + "_info", table)

    # 获取网站是否是https/http
    def get_url_type(self, head_url):
        '''
            @name 获取网站是否是https/http
            @quthor lkq@bt.cn
            @time 2022-10-10
            @return 返回一个字符串
        '''
        if head_url.startswith('https://'):
            return 'https://'
        else:
            return 'http://'

    def head_hash(self, soup, domains):
        '''
            @name 获取网站的hash值
            @quthor lkq@bt.cn
            @time 2022-10-10
            @return 返回一个MD5
        '''

        head_info = soup.head
        if head_info:
            heads = str(head_info)
        else:
            heads = ""
            return ""
        title = soup.title
        if title:
            title = str(title)
            heads = heads.replace(title, "")

        # 去掉css
        style = soup.select('style')
        for i in style:
            heads = heads.replace(str(i), "")
        # 去掉link
        link = soup.select('link')
        for i in link:
            i = str(i)
            if len(i) < 200:
                heads = heads.replace(str(i), "")
        # 去掉description
        description = soup.find(attrs={"name": "description"})
        if description:
            if description['content']:
                descriptions = str(description['content'])
                heads = heads.replace(descriptions, "")
        # 去掉keywords
        keyword = soup.find(attrs={"name": "keywords"})
        if keyword:
            if keyword['content']:
                keywords = str(keyword['content'])
                # print(keyword)
                heads = heads.replace(keywords, "")
        # 去掉所有的空格之类的
        # heads=heads.replace(" ", "").replace("\t", "").replace("\r", "").replace("\n", "")
        heads = heads.replace(" ", "").replace("\n", "")
        if not heads:
            return ""
        md5s = public.Md5(heads)
        paths = self.hash + "/{}/".format(domains) + md5s + ".txt"
        if not os.path.exists(paths) and heads:
            public.WriteFile(paths, heads)
        return md5s

    def tail_hash(self, soup, domains):
        '''
            @name 获取网站尾部的hash值
            @quthor lkq@bt.cn
            @time 2022-10-10
            @return 返回一个MD5
        '''

        count = 0
        tmp_tail = ""
        # 获取最后一个script标签
        for i in soup.select("script"):
            count += 1
            if count == len(soup.select("script")):
                tmp_tail = i.string
        if tmp_tail:
            # heads = tmp_tail.replace(" ", "").replace("\t", "").replace("\r", "").replace("\n", "")
            heads = tmp_tail.replace(" ", "").replace("\r", "")

            md5s = public.Md5(heads)
            paths = self.hash + "/{}/".format(domains) + md5s + ".txt"
            if not os.path.exists(paths):
                public.WriteFile(paths, heads)
            return md5s
        else:
            return ""

    def add_risk(self, site_id, site_name, url, testing_id, content, risk_content, risk_type, text):
        '''
        风险表  risk
        id  主键
        site_id  网站id
        site_name  网站名称
        url  风险url
        testing_id  测试id
        content  风险内容
        risk_content  风险类型
        risk_type  风险位置
        source_file 风险文件存放位置            #当风险位置为title,descriptions,keywords,body时才使用
        source_content_file   更改原始内容文件路径  #当风险位置不为title,descriptions,keywords,body的时候使用
        new_content_file  更改后的内容文件路径     #当风险位置不为title,descriptions,keywords,body的时候使用
        time  添加时间
        '''
        if self.M_info("risk").where("url=? and testing_id=?", (url, testing_id)).count() == 0:
            file_path = public.Md5(public.GetRandomString(32))
            public.WriteFile(self.source + "/" + file_path + ".txt", text)
            infos = {"site_id": site_id, "site_name": site_name, "url": url, "testing_id": testing_id,
                     "content": content, "risk_content": risk_content, "risk_type": risk_type,
                     "source_file": file_path + ".txt", "source_content_file": "", "new_content_file": "",
                     "time": int(time.time())}
            self.M_info("risk").insert(infos)
            keys = content.split(",")

            for i2 in keys:
                if self.M_info("works").where("words=?", (i2,)).count() >= 1:
                    count = self.M_info("works").where("words=?", (i2,)).getField("count")
                    if type(count) == int:
                        self.M_info("works").where("words=?", (i2,)).update(
                            {"count": count + 1, "update_time": int(time.time())})
                else:
                    self.M_info("works").insert(
                        {"words": i2, "count": 1, "time": int(time.time()), "update_time": int(time.time())})
            # 添加风险

            risks = self.M_info("risk").where("testing_id=?", testing_id).count()
            if risks:
                add_risk = self.M_info('testing').where("testing_id=?", testing_id).update({"risks": risks})
                if type(add_risk) == str:
                    print(add_risk)

    def getPageLink(self, visitedUrl, info):
        # 获取网站的域名
        '''
            @name 扫描网站的url入口函数
            @quthor lkq@bt.cn
            @time 2022-10-10
            @param visitedUrl 例子:{'url': 'https://www.o2oxy.cn', 'level': 1, 'parent': 'https://www.o2oxy.cn'}
            @param info 例子:{'is_local': 0, 'url': 'url', 'crawl_deepth': 20, 'args': 0, 'site_name': '域名', 'ua': 'ua', 'rendomID': '扫描id', 'site_id': 1, 'method': 1, 'configs': {'scan_thread': 20, 'scan_level': 20, 'scan_ua': 'ua', 'scan_args': 0, 'title': 0, 'descriptions': 0, 'keywords': 0, 'title_hash': 1, 'tail_hash': 0, 'access': 0, 'search_monitor': 0, 'thesaurus': 1}, 'logs': ''}
            @return 返回这个url中子url中的数量
        '''
        domains = info['site_name']  # 域名
        scan_ua = info['ua']  # ua
        crawl_deepth = info['crawl_deepth']  # 扫描深度
        args = info['args']  # 是否扫描参数
        is_local = info['is_local']  # 是否本地扫描
        site_id = info['site_id']  # 站点ID
        head_url = visitedUrl['url']
        rendomID = info['rendomID']
        list_href = 0
        if len(head_url.split('/')) < 3:
            print("网站格式不正确")
            return
        domain = head_url.split('/')[2]
        # 获取需要爬取的url
        if is_local:
            headers = {
                'host': domains,
                "User-Agent": scan_ua
            }
        else:
            headers = {
                "User-Agent": scan_ua
            }
        if domain != domains:
            # 如果他填写的域名为baidu.com 但是爬取的是www.baidu.com
            if domains.startswith("www"):
                if domains.replace('www', domains, 1) != domain:
                    return 0
            elif domains.startswith("www"):
                if domain.startswith("www", domain, 1) != domains:
                    return 0
        if is_local:
            head_url = head_url.replace(domains, '127.0.0.1', 1)
        try:
            reaponse = requests.get(head_url, headers=headers, verify=False, timeout=10)
        except:
            return 0
        # print(reaponse.text)
        if is_local:
            head_url = head_url.replace('127.0.0.1', domains, 1)
        if head_url in self._threads:
            del (self._threads[head_url])
        if reaponse.status_code != 200:

            id = self.M1("url").where("url=?", head_url).getField("id")
            if id:
                self.M1("url").where("id=?", id).delete()
            return
        if 'Content-Type' in reaponse.headers:
            if not 'html' in reaponse.headers['Content-Type']:
                return []
        reaponse.encoding = "utf-8"
        soup = Bs4(reaponse.text, 'html.parser')
        titles = ""
        if soup.title:
            titles = soup.title.string  # 获取head标签的所有内容
            # print("title",title)
        description = soup.find(attrs={"name": "description"})
        descriptions = ""
        if description:
            descriptions = description['content']
            # print("descriptions",descriptions)
        keyword = soup.find(attrs={"name": "keywords"})
        keywords = ""
        if keyword:
            keywords = keyword['content']
        url_info = {}
        url_info['title'] = titles
        url_info['description'] = descriptions
        url_info['keywords'] = keywords
        url_info['title_hash'] = self.head_hash(soup, domains)
        url_info['tail_hash'] = self.tail_hash(soup, domains)

        # 赌博关键词
        '''
        1 代表默认词库+自定义词库 2 代表默认词库 3 代表自定义词库
        '''
        if not 'thesaurus' in info['configs']:

            thesaurus = 1
        else:
            thesaurus = info['configs']['thesaurus']
        if thesaurus == 1:
            pass
        keywos = {}
        if thesaurus == 1 or thesaurus == 3:
            keywos["赌博"] = ['棋牌玩法', '投注网站', 'AG体育平台', '信誉开户', '百家乐导航', '久赢彩', '网上赌场', '线上赌城', '急速百家乐', '急速六合彩', '线上赌场',
                            '性感荷官', '线上下注', '真人赌博', '老虎机', '实时彩', '网上赌城', '实时竞猜平台', '炸金花', '万丰国际', '亚博体育', 'ttc福利彩票',
                            '太阳城集团', '互博国际', '永利娱乐', '皇马娱乐', '太阳城', '万豪国际', '亚博国际', 'bob体育', '188金宝博', '凯发娱乐', '永利游戏',
                            '新葡京', '亚洲城', '银河娱乐', '澳门新葡京', '皇冠体育', '云鼎娱乐', '欧亚国际', 'beplay', '乐动体育', 'betway', 'ope体育',
                            '意甲全球赞助商', '沙巴体育', '凯时娱乐', '欧宝体育', '宝马会', '威尼斯人', '金沙娱乐', '伟德体育', '新皇冠体育', '大發快3', '江苏快三',
                            '本站彩票', '香港六合彩', '幸运彩票', '北京赛车', '北京28', 'QG刮刮乐', '加拿大28', '欢乐生肖', '福利3D', '北京PK拾', 'KG彩票',
                            'VR彩票', 'VR真人彩票', '开元棋牌', '大唐棋牌', '幸运棋牌', 'BG棋牌', '百胜棋牌', 'KY棋牌', 'FG棋牌', '天美棋牌', 'VG棋牌',
                            '王者棋牌', 'TP棋牌', '传奇棋牌', '棋乐游', '金博棋牌', '欢乐棋牌', '幸运飞艇', '抢庄牛牛', '澳门六合彩', '极速赛车', '冰球突破',
                            '水牛闪电战', '极速六合彩', '极速时时彩', '北京PK10', 'BG大仙捕鱼', 'FG捕鸟达人', 'TP劈鱼来了', 'FG欢乐捕鱼', 'AG捕鱼王',
                            'FG美人捕鱼', 'TP钱龙捕鱼', 'BB捕鱼达人', 'FG雷霆战警', 'TP炸鱼来了', 'TP二爷捕鱼', 'JDB龙王捕鱼', 'BG西游捕鱼', 'BG捕鱼大师',
                            'GD锦绣厅', 'AG视讯', 'AE视讯', 'LEBO视讯', 'BG视讯', 'AG女优厅', 'DG视讯', 'WM真人', 'DS贵宾厅', '皇家视讯',
                            'eBET如意厅', 'BG畅游厅', 'BB视讯', 'PP王者厅', 'AB聚龙厅', 'WG视讯', 'OG视讯', 'OG东方厅', 'EA尊爵厅', '欧博视讯',
                            'BB富贵厅', '电竞牛', 'BC体育', 'YSB体育', '易胜博体育', '沙巴电竞', 'UG体育', 'IM体育', 'TF电竞', '泛亚体育', '泛亚电竞',
                            '三昇体育', '国际娱乐中心', '移动娱乐平台', '娱乐城', '深海捕鱼', 'MG电子', '真人娱乐', 'BBIN旗舰厅', '庄闲场', '棋牌游戏', '快乐彩',
                            'LEBO真人厅', '欧博视讯厅', '千炮捕鱼', '彩票投注', '四人牛牛', '时时反水', 'PT电子', 'JDB电子', 'FG电子', 'AMEBA电子',
                            'BB电子', 'CQ9电子', 'PG电子', 'pp电子', 'TP电子', 'NT电子', 'BG电子', 'HABA电子', 'SG电子', 'PNG电子', 'AG电子',
                            '皇朝电子', 'DT电子', 'ICG电子', 'MW电子', 'JOKER电子', 'jbo官网', 'long8', 'manbetx', '18luck', 'bet365',
                            'yabo', '华体会体育', 'ob真人']
            keywos["色情"] = ['成人色站', '亚洲va', '亚洲av', '成在人线', '国产av', '色影院', '日本va', '看v片', '日本有码', '一本道', '本地偷拍', '日本av',
                            '成年人视频', '久草小说', '成人小说', '无码成人', '成人影视', '色吧图片', '成人电影', '夜夜撸', '在线人成', '成人旡码', '免费A片',
                            '黄色视频', '成人在线', '国产va', '直播裸聊', '东京热', '成人社区', '第一会所', '狼人社区', '香蕉国产', '抖音成年短视频', '榴草社区',
                            '毛片基地', '麻豆视频', '狼友社区', '猫咪成人', '草榴社区', '伊人影院', 'UU直播', '柚柚AV', 'avporn', '国产精品', '成人高清',
                            '日韩视频', '欧美日韩', '欧美在线', '亚洲欧美', '日韩欧美', '亚洲高清', '亚洲有声', '高跟丝袜', '人妖人兽', '变态另类', '强暴虐待',
                            '美女诱惑', '欧美色图', '潮吹合集', '重口色情', '不伦恋情', '成人动漫', '暴力虐待', '推女郎图', '美腿丝袜', '经典三级', '少妇偷情',
                            '国产自拍', '激情口交', '无码专区', '巨乳诱惑', '日韩精品', '人妖直播', '露出偷窥', '高潮喷吹', '人妻熟女', 'SM重口味', '高清无码',
                            '人妻系列', '强奸乱伦', '巨乳美乳', '丝袜长腿', '校园春色', '欧美精品', '人兽性交', '欧美性爱', '熟女人妻', '亚洲无码', '打飞机区',
                            '欧美巨乳', '亚洲色图', '亚洲情色', '亚洲性爱', '乱伦熟女', '家庭乱伦', '精品三级', '制服诱惑', '露出激情', '自慰系列', '欧美激情',
                            '91porn', 'ThePorn', '抖音成人版', '柚子直播', '桃色直播', '青青视频', '小草青青在线视频', '久青草', '九九堂', '国产小青蛙',
                            '人妻交换', '色情小说']
            keywos['黑灰产'] = ['呼死你', 'webshell出售', '短信轰炸', '短信炸弹', '短信测压', '短信攻击', '电话轰炸', '数据售卖', '数据出售', '开房记录',
                             '酒店记录', '极速代挂', '代挂系统']
            keywos['水军'] = ['抖音水军', '棋牌代刷', '抖音刷粉', '刷播放量', '抖音买粉', '自动加粉丝', '新浪微博粉丝机']
            keywos['国家领导人'] = ['习包子', '习猪头', '刁近平', '习皇帝', '习帝皇', '习武大帝', '习维尼', '袭主席', '习近瓶', '刁太太', '习阿斗', '刁远突',
                               '庆丰帝', '毛二世', '小习子', '习无能', '包子习', '洗净瓶', '歪脖子刁', '刁犬犬', '刁太大', '刁宽衣', '刁哒哒', '习宝子',
                               '包子帝', '习远凸', '习彭傻逼', '习金瓶', '习草包', '习二傻子', '刁近坪', '习胖子', '肥仔习', '喜禁评', '袭尽瓶', '爱学袭']
            keywos['涉政'] = ['兲朝', '一档砖政', '刮民党', '中X南Y海', '推翻CCP', '黃屍', '红胃滨', '肿蝈人']
        if thesaurus == 1 or thesaurus == 2:
            keywos['自定义关键词'] = self.get_thesaurus(None)

        # 获取网页内容
        bodys = soup.body
        for i in keywos:
            if len(keywos[i]) == 0: continue
            # 判断网页的内容是否存在风险
            if titles:
                kes = '|'.join(keywos[i])
                kes = '(' + kes + ')'
                infosssss = re.findall(kes, titles)
                if infosssss:
                    temp = []
                    [temp.append(i) for i in infosssss if not i in temp]
                    self.lok.acquire()
                    self.add_risk(site_id, domains, head_url, rendomID, ','.join(temp), i, "title", reaponse.text)
                    self.lok.release()
                    print("title 风险关键词", infosssss)
            if descriptions:
                kes = '|'.join(keywos[i])
                kes = '(' + kes + ')'
                infosssss = re.findall(kes, descriptions)
                if infosssss:
                    temp = []
                    [temp.append(i) for i in infosssss if not i in temp]
                    self.lok.acquire()
                    self.add_risk(site_id, domains, head_url, rendomID, ','.join(temp), i, "descriptions",
                                  reaponse.text)
                    self.lok.release()
                    print("descriptions 风险关键词", infosssss)
            if keywords:
                kes = '|'.join(keywos[i])
                kes = '(' + kes + ')'
                infosssss = re.findall(kes, keywords)
                if infosssss:
                    temp = []
                    [temp.append(i) for i in infosssss if not i in temp]
                    self.lok.acquire()
                    self.add_risk(site_id, domains, head_url, rendomID, ','.join(temp), i, "keywords", reaponse.text)
                    self.lok.release()
                    print("keywords 风险关键词", infosssss)
            if bodys:
                kes = '|'.join(keywos[i])
                kes = '(' + kes + ')'
                infosssss = re.findall(kes, str(bodys))
                if infosssss:
                    temp = []
                    [temp.append(i) for i in infosssss if not i in temp]
                    self.lok.acquire()

                    self.add_risk(site_id, domains, head_url, rendomID, ','.join(temp), i, "body", reaponse.text)
                    self.lok.release()
                    # print("bodys 风险关键词",infosssss)
        # self.lok.acquire()
        # 添加已经访问的url到url数据库中
        self.addVisitedUrl(head_url, url_info, info)
        # self.lok.release()
        if visitedUrl['level'] + 1 > crawl_deepth: return 0
        title = soup.select('a')
        for i in title:
            # args 代表是否接受参数默认不接受
            url = str(i.get('href'))
            if args == 0 or args == '0':
                if '?' in url:
                    url = url.split('?')[0]
                elif '#' in url:
                    url = url.split('#')[0]
            if not url: continue
            if url == "/": continue
            if url.startswith('tel:'): continue
            if url.startswith('mailto:'): continue
            if url == "None":
                continue
            static_list = ["png", "jpg", "pdf", "gif", "mp3", "mp4", "js", "css", "bmp", "svg", "ttf", "woff",
                           "txt", "zip", "7z", "gz", "rar", "jar", ".swap", "exe"]
            # 判断是否是静态文件
            static = url.split(".")[-1]
            if static in static_list:
                continue
            if url.startswith('http://') or url.startswith('https://'):
                # 判断是否是我们需要爬取的网站
                if url.startswith(self.get_url_type(head_url) + domain):
                    if url == head_url: continue
                    self.addUnvisitedUrl(url, visitedUrl['level'] + 1, visitedUrl['url'])
                    list_href += 1
                # 如果他是域名填写的是baidu.com 内容中有www.baidu.com
                elif url.startswith(self.get_url_type(head_url) + "www." + domain):
                    self.addUnvisitedUrl(url, visitedUrl['level'] + 1, visitedUrl['url'])
                # 如果他是域名填写的是www.baidu.com 内容中有baidu.com
                elif url.startswith(self.get_url_type(head_url) + domain.replace("www.", "")):
                    self.addUnvisitedUrl(url, visitedUrl['level'] + 1, visitedUrl['url'])
            else:
                if url.startswith("#"): continue
                if url.lower().startswith('javascript'):
                    continue
                if url.startswith("#"): continue
                # 如果url为./ 或者/ 开头
                if url.startswith('/') or url.startswith('./'):
                    http_domain = self.get_url_type(head_url) + domain
                    head_s = head_url.replace(http_domain, "")
                    if url == head_s: continue
                    if url == head_url: continue
                    if url.startswith(head_s + "#"): continue
                    if url.startswith('./'):
                        url = url.replace('./', '/', 1)
                    # 如果他是/开头的 那么就是在当前域名下的  最终的url为 域名+/1.html
                    if url.startswith("//"+domain):
                        url=url.replace("//"+domain,"")
                    url = self.get_url_type(head_url) + domain + url
                    self.addUnvisitedUrl(url, visitedUrl['level'] + 1, visitedUrl['url'])
                    list_href += 1
                else:
                    # 如果为/ 结尾
                    if head_url.endswith('/'):
                        if url.startswith('/'):
                            url = url[:-1]
                        url = head_url + url

                        self.addUnvisitedUrl(url, visitedUrl['level'] + 1, visitedUrl['url'])
                        list_href += 1
                    else:
                        urls = head_url.split('/')[-1]
                        if urls == domain:
                            url = self.get_url_type(head_url) + domain + '/' + url
                            self.addUnvisitedUrl(url, visitedUrl['level'] + 1, visitedUrl['url'])
                            list_href += 1
                        else:
                            # 如果有点的情况下。需要判断是否是最后一个点·
                            if '.' in urls:
                                url = head_url.replace(urls, "") + url
                                self.addUnvisitedUrl(url, visitedUrl['level'] + 1, visitedUrl['url'])
                                list_href += 1
                            else:
                                if head_url.endswith('/'):
                                    url = head_url + url
                                else:
                                    url = head_url + "/" + url
                                self.addUnvisitedUrl(url, visitedUrl['level'] + 1, visitedUrl['url'])
                                list_href += 1

        self.lok.acquire()
        if len(self.__add_url) > 0:
            _obj = self.M1("url")
            for i in self.__add_url:
                _obj.addAll("url,level,time,update_time,father_id", i)
            _obj.commit()
            self.__add_url = []
        self.lok.release()
        return list_href

    def crawler(self, info):
        '''
        @name 正式的爬取，并依据深度进行爬取层级控制
        @auther: lkq@bt.cn
        @time 2022-10-12
        @param info: 当前扫描站点的信息
        '''
        domain = info['site_name']  # 域名
        crawl_deepth = info['crawl_deepth']  # 扫描深度
        count = 0
        # 如果method 为3 的时候则为单个URL的爬取
        if info['method'] == 3:
            count += 1
            visitedUrl = self.popUnvisitedUrl()
            self.write_logs(info['logs'], "正在检测#%d层:%s   已经检测数量%s" % (visitedUrl['level']+1, visitedUrl['url'], count))
            self.getPageLink(visitedUrl, info)
            if len(self.__addurlinfo) > 0:
                _obj = self.M2("urlinfo")
                for i in self.__addurlinfo:
                    _obj.addAll("urlid,title,time,keywords,description,title_hash,tail_hash,is_status,update_time", i)
                _obj.commit()
                self.__addurlinfo = []
        else:
            # 快速扫描和全站扫描

            tmp_count = 0
            while not self.unvisitedUrlEmpty():
                visitedUrl = self.popUnvisitedUrl()
                if type(crawl_deepth) == int:
                    if visitedUrl['level'] > crawl_deepth: continue
                else:
                    crawl_deepth = 50
                # 先把一级的目标全部导入完后执行多线程
                print("正在检测#%d层:%s   已经检测数量%s" % (visitedUrl['level']+1, visitedUrl['url'], count))
                self.write_logs(info['logs'],
                                "正在检测#%d层:%s   已经检测数量%s" % (visitedUrl['level']+1, visitedUrl['url'], count))
                if not domain in visitedUrl['url']: continue
                if count == 0:
                    tmp_count = self.getPageLink(visitedUrl, info)
                    count += 1
                elif count < tmp_count:
                    count += 1
                    p = threading.Thread(target=self.getPageLink, args=(visitedUrl, info))
                    p.start()
                    p.join(0.5)
                    while len(self._threads) >= self._max_thread:
                        time.sleep(1)
                    # @self.getPageLink(visitedUrl,info)
                else:
                    count += 1
                    self._threads[visitedUrl['url']] = 1
                    p = threading.Thread(target=self.getPageLink, args=(visitedUrl, info))
                    p.setDaemon(True)
                    p.start()
                    while len(self._threads) >= self._max_thread:
                        time.sleep(1)
            # 强制刷新缓存
            if len(self.__addurlinfo) > 0:
                _obj = self.M2("urlinfo")
                for i in self.__addurlinfo:
                    _obj.addAll("urlid,title,time,keywords,description,title_hash,tail_hash,is_status,update_time", i)
                _obj.commit()
                self.__addurlinfo = []
        if count - 1 > 0:
            return count - 1
        else:
            return count


if __name__ == '__main__':
    import sys
    main = main()
    if len(sys.argv) == 1:
        print("请输入参数")
        print("python3 main.py 1")
        exit(0)
    if len(sys.argv) == 2:
        id = sys.argv[1]
        paths = "/dev/shm/" + public.Md5(id) + ".txt"
        args = public.dict_obj()
        args.id = id
        args.path = paths
        main.start(args)