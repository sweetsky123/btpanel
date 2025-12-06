# coding: utf-8
# -------------------------------------------------------------------
# 宝塔Linux面板
# -------------------------------------------------------------------
# Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
# -------------------------------------------------------------------
# Author: sww <bt_ahong@qq.com>
# -------------------------------------------------------------------

# ------------------------------
# 查询监控报表插件
# ------------------------------

import os, re, json, time
import traceback
from datetime import datetime, timedelta
from logsModel.base import logsBase
import public, db


class main(logsBase):
    spider_table_reverse = {
        1: "百度",
        2: "必应",
        3: "360搜索",
        4: "谷歌",
        5: "百度云",
        6: "搜狗",
        7: "有道",
        8: "搜搜",
        9: "DNSPod",
        10: "Yandex",
        11: "易搜",
        12: "其他",
        13: "百度移动",
        14: "雅虎",
        15: "duckduckgo",
        77: "假"
    }

    def get_totle(self, get):
        try:
            search_time = 0
            if hasattr(get, 'day') and get.day:
                now = datetime.now() - timedelta(days=int(get.day))
                date_str = now.strftime('%Y%m%d')
                search_time = datetime.strptime(date_str, '%Y%m%d').timestamp()
            if not hasattr(get, 'siteName') and get.siteName:
                return public.returnMsg(False, '参数错误!')
            siteName = get.siteName
            db_path = '/www/server/total/logs/' + siteName + '/total.db'
            if not os.path.exists(db_path):
                return public.returnMsg(False, '数据不存在,安装监控报表以后的数据将会在此显示!')
            sql = db.Sql()
            sql.dbfile(db_path)
            data = sql.table('ip_areas_stat').field('id,time,ip,country,province,city,is_spider,request').select()
            data.reverse()
            result = {}
            for i in data:
                result[i['ip']] = result.get(i['ip'], {})
                result[i['ip']]['country'] = i['country'] + ' ' + i['province'] + ' ' + i['city']
                result[i['ip']]['is_spider'] = self.spider_table_reverse.get(i['is_spider'], '未知') + '蜘蛛' if i['is_spider'] else '-'
                result[i['ip']]['request'] = result[i['ip']].get('request', 0) + i['request']
                result[i['ip']]['time'] = result[i['ip']]['time'] if result[i['ip']].get('time', 0) else int(datetime.strptime(str(i['time']), '%Y%m%d').timestamp())
                if search_time:
                    if datetime.strptime(str(i['time']), '%Y%m%d').timestamp() < search_time:
                        break
            result = sorted(result.items(), key=lambda x: x[1]['request'], reverse=True)
            return result
        except:
            return {}
