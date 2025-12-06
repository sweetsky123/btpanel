#coding: utf-8
#-------------------------------------------------------------------
# 宝塔Linux面板
#-------------------------------------------------------------------
# Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
#-------------------------------------------------------------------
# Author: cjxin <bt_ahong@qq.com>
#-------------------------------------------------------------------

#------------------------------
# 大文件分析
#------------------------------

import os,re,json,time
from monitorModel.base import monitorBase
import public,db


class main(monitorBase):
    #扫描历史
    log_path = '{}/data/scan/'.format(public.get_panel_path())

    def __init__(self):
        if not os.path.exists(self.log_path):
            os.makedirs(self.log_path)

    def start_scan(self,get):
        """
        @name 扫描磁盘
        @param path 扫描目录
        """
        id = get.id
        path = get.path
        if not os.path.exists(path):
            return public.returnMsg(False,'目录不存在.')

        res = public.ExecShell('ncdu')
        if res[0].find('not found') != -1:
            res = public.returnMsg(False,'请先安装ncdu工具.')
            res['code'] = 100
            return res

        result_file = '{}{}'.format(self.log_path,id)
        import panelTask
        task_obj = panelTask.bt_task()

        exec_shell = "ncdu {} -o {} ".format(path,result_file)
        task_obj.create_task('扫描目录文件大小', 0, exec_shell)

        return public.returnMsg(True,'扫描任务已创建.')


    def start_install_ncdu(self,get):
        """
        @安装ncdu工具
        """
        import panelTask
        task_obj = panelTask.bt_task()
        task_obj.create_task('安装ncdu工具', 0, 'yum install -y ncdu')

        return public.returnMsg(True,'安装任务已创建.')

    def get_scan_files(self,get):
        """
        @name 获取扫描结果
        @param id str 扫描id
        """
        result = []
        if not os.path.exists(self.log_path):
            return result

        for s_file in os.listdir(self.log_path):
            try:
                filename = '{}/{}'.format(self.log_path,s_file)
                f_stat = os.stat(filename)
                f_info = {'id':s_file,'size':f_stat.st_size,'mtime':f_stat.st_mtime}
                result.append(f_info)
            except:pass

        return result

    def get_scan_log(self,get):
        """
        @name 获取扫描日志
        @param id 扫描id
        """
        path = None
        id = get.id
        if 'path' in get:
            path = get.path

        result_file = '{}/{}'.format(self.log_path,id)
        if not os.path.exists(result_file):
            return public.returnMsg(False,'扫描结果不存在.')

        if path and not os.path.isdir(path):
            return public.returnMsg(False,'{}不是一个有效目录.'.format(path))

        result = {}
        slist = self.__get_log_data(result_file)
        if len(slist) > 0:
            res = []
            first_data = slist[0]
            if not path:
                res.append(first_data)
            else:
                self.__get_sub_data(first_data['list'],first_data['name'],path,res)

            if len(res) > 0:
                sdata = self.__get_dirs_size(res[0])
                #删除下级节点
                for val in sdata['list']:
                    if 'list' in val:
                        val = self.__get_dirs_size(val)
                        val['list'] = []
                result = sdata
        return result

    def __get_dirs_size(self,info):
        """
        @name 获取目录信息
        @param info 目录信息
        @param result 结果
        """
        res_str = json.dumps(info)
        info['dir_num'] = res_str.count('type')
        info['file_num'] = res_str.count('asize')
        info['total_asize'] = 0
        info['total_dsize'] = 0
        tmps = re.findall('asize\":\s+(\d+),',res_str)
        if tmps:
            for val in tmps: info['total_asize'] += int(val)

        tmps = re.findall('dsize\":\s+(\d+),',res_str)
        if tmps:
            for val in tmps: info['total_dsize'] += int(val)

        public.set_module_logs('tamper_core','get_effective_path')
        return info



    def __get_log_data(self,log_file):
        """
        @name 获取扫描日志
        @param log_file 日志文件
        """
        result = []
        try:
            data = public.readFile(log_file)
            data = json.loads(data)

            for info in data:
                if type(info) != list: continue
                self.__get_dirs_info(info,result)
        except:pass

        return result

    def __get_sub_data(self,data,root_path,sub_path,res):
        """
        @name 获取子目录数据
        @param id int 记录id
        @param path string 目录
        """
        for val in data:
            if len(res) > 0: break
            if not 'type' in val: continue

            sfile = '{}/{}'.format(root_path,val['name']).replace('//','/')
            if sfile == sub_path:
                res.append(val)
            else:
                self.__get_sub_data(val['list'],sfile,sub_path,res)

    def __get_dirs_info(self,data,result):
        """
        @name 获取目录详细信息
        """

        dir_info = {}
        for info in data:
            if not dir_info:
                dir_info = {'type':1,'name':info['name'],'asize':0,'dsize':0,'dirs':0,'files':0,'list':[]}
            else:

                if type(info) == list:
                    dir_info['dirs'] += 1
                    self.__get_dirs_info(info,dir_info['list'])
                else:

                    if not 'asize' in info: info['asize'] = 0
                    if not 'dsize' in info: info['dsize'] = 0

                    dir_info['asize'] += info['asize']
                    dir_info['dsize'] += info['dsize']
                    dir_info['files'] += 1

                    dir_info['list'].append(info)
        dir_info['list'] = sorted(dir_info['list'],key=lambda x:x['asize'],reverse=True)
        result.append(dir_info)
