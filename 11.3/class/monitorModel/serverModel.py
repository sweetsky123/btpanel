#coding: utf-8
#-------------------------------------------------------------------
# 宝塔Linux面板
#-------------------------------------------------------------------
# Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
#-------------------------------------------------------------------
# Author: cjxin <bt_ahong@qq.com>
#-------------------------------------------------------------------

#------------------------------
# 服务器监控模型，cpu，内存，磁盘，网络
#------------------------------
import os,re,json,time
from monitorModel.base import monitorBase
import public,db


class main(monitorBase):


    def __init__(self):
        self.__sql = db.Sql().dbfile('system')


    def get_top_bykey(self,get):
        """
        @name 获取cpu排行
        @param key str 排行类型  cpu,disk,net,memory,all
        """
        tab_key = '{}_top'.format(get.key)
        res = self.__sql.table('process_top_list').field('addtime,{}'.format(tab_key)).where('addtime>=? and addtime<=?',(get.start,get.end)).select()

        result = self.__get_top_sort(tab_key,res)
        return result

    def get_process_history(self,get):
        """
        @name 获取进程历史
        @param start int 开始时间
        @param end int 结束时间
        @param p_name str 进程名称
        @param t_pid str 时间类型，按小时，按分钟，按天
        """
        t_type = get.t_type
        if not t_type in ['hour','day','month','minute','week']:
            return public.returnMsg(False,'不支持的类型.')

        start = 0
        end = time.time()
        #按小时查看最多24小时
        if t_type == 'hour':
            start = end - 86400
        elif t_type == 'day':
            start = end - 86400 * 30
        elif t_type == 'month':
            start = end - 365 * 86400
        elif t_type == 'minute':
            start = end - 3600
        elif t_type == 'week':
            start = end - 8 * 7 * 86400
        else:
            #自定义查询时间
            t_type = 'day'
            start = get.start
            end = get.end

        data = {}
        skeys = ['cpu_top','memory_top','disk_top','net_top','all_top']

        res = self.__sql.table('process_top_list').where("addtime>=? and addtime<=? ",(start,end)).select()
        for val in res:
            #匹配进程名称
            find_keys = []
            for k in skeys:
                if val[k].find(get.p_name) == -1:
                    continue
                find_keys.append(k)

            if len(find_keys) == 0:
                continue

            skey = public.format_date('%Y-%m-%d %H:%M',val['addtime'])
            # if t_type == 'hour':
            #     skey = public.format_date('%Y-%m-%d %H',val['addtime'])
            # elif t_type == 'day':
            #     skey = public.format_date('%Y-%m-%d',val['addtime'])
            # elif t_type == 'month':
            #     skey = public.format_date('%Y-%m',val['addtime'])
            # elif t_type == 'minute':
            #     skey = public.format_date('%Y-%m-%d %H:%M',val['addtime'])
            # elif t_type == 'week':
            #     skey = public.format_date('%Y-%W',val['addtime'])

            if not skey in data:
                data[skey] = {'time':skey}

            for key in find_keys:
                p_list = json.loads(val[key])
                keys = self.__get_key_byindex(key)
                for s_val in p_list:
                    p_info = {}
                    column_idx = 0
                    for v in s_val:
                        if column_idx <= len(keys):
                            p_info[keys[column_idx]] = v
                        column_idx += 1

                    if p_info['name'] != get.p_name:
                        continue
                    for k in p_info:
                        if k in ['pid','addtime','runtime']:
                            continue
                        if type(p_info[k]) in [int,float]:
                            if p_info[k] <= 0:
                                continue
                            n_key = '{}_{}'.format(key,k)
                            if not n_key in data[skey]: data[skey][n_key] = 0

                            data[skey][n_key] += p_info[k]
        result = []
        for key in data.keys():
            result.append(data[key])
        return result

    def __get_key_byindex(self,table):
        """"
        @name 获取表指定索引的key
        @param table str 表名
        @param index int 索引
        """
        if table == 'cpu_top':
            return ['cpu_percent','pid','name','cmdline','user','runtime']
        elif table == 'memory_top':
            return ['used_size','pid','name','cmdline','user','runtime']
        elif table == 'disk_top':
            return ['total','read','write','pid','name','cmdline','user','runtime']
        elif table == 'net_top':
            return ['total','up','down','conn_num','package_num','pid','name','cmdline','user','runtime']
        elif table == 'all_top':
            return ['cpu_pre','disk_read','disk_write','mem_used_size','up','down','pid','name','cmdline','user','runtime']
        return []


    def __get_top_sort(self,tab_key,res):
        """
        @name 获取排行
        @param key str 排行类型  cpu,disk,net,memory,all
        """

        result = []
        keys = self.__get_key_byindex(tab_key)

        for info in res:
            arrs = json.loads(info[tab_key])
            if len(arrs) == 0:
                continue

            item = {}
            item['total'] = 0
            item['addtime'] = info['addtime']
            item['list'] = []
            for val in arrs:
                d_info = {}
                column_idx = 0
                for v in val:
                    if column_idx <= len(keys):
                        d_info[keys[column_idx]] = v
                    column_idx += 1
                item['list'].append(d_info)
                item['total'] += val[0]
            result.append(item)

        result = sorted(result,key=lambda x:x['addtime'],reverse=True)
        return result







