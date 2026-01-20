# coding: utf-8
# -------------------------------------------------------------------
# 宝塔Linux面板
# -------------------------------------------------------------------
# Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
# -------------------------------------------------------------------
# Author: 王佳函 <mr_jia_han@qq.com>
# -------------------------------------------------------------------

import os

panelPath = '/www/server/panel'
os.chdir(panelPath)

import json
import time
from typing import Union

import public
from filesModel.base import filesBase


class main(filesBase):
    ncdu_exe = 'ncdu'
    # 扫描结果存放路径
    scan_temp_path = os.path.join(public.get_setup_path(), "disk_analysis/scan/")
    
    def __init__(self):
        if os.getenv('BT_PANEL'):
            self.ncdu_exe = os.path.join(panelPath, '/plugin/disk_analysis/ncdu')
        if not os.path.exists(self.scan_temp_path):
            os.makedirs(self.scan_temp_path)
        
        exec_shell = f"{self.ncdu_exe} -V"
        result = public.ExecShell(exec_shell)[1]
        if result.find("Permission denied") != -1:  # 无权限授权
            public.ExecShell("chmod +x /usr/bin/ncdu")
            result = public.ExecShell(exec_shell)[1]
        if result.find("ncdu: command not found") != -1:  # 连接不存在
            public.ExecShell("ln -s /www/server/panel/plugin/disk_analysis/ncdu /usr/bin/ncdu && chmod +x /usr/bin/ncdu")
            result = public.ExecShell(exec_shell)[1]
        
        # 删除
        log_path = '{}/data/scan/'.format(public.get_panel_path())
        if os.path.exists(log_path):
            public.ExecShell("rm -rf {}".format(log_path))
        
        cache_file = '{}/config/scan_disk_cache.json'.format(public.get_panel_path())
        if os.path.exists(cache_file):
            os.remove(cache_file)
    
    @classmethod
    def __check_disk(cls):
        # 校验磁盘大小
        df_data = public.ExecShell("df -T | grep '/'")[0]
        for data in str(df_data).split("\n"):
            data_list = data.split()
            if not data_list: continue
            use_size = data_list[4]
            size = data_list[5]
            disk_path = data_list[6]
            if int(use_size) < 1024 * 50 and str(size).rstrip("%") == "100" and disk_path in ["/", "/www"]:
                return "您的磁盘空间不足！请先清理出一些空间!(建议50MB及以上)"
        return True
    
    @classmethod
    def __get_stat(cls, path, info):
        if not os.path.exists(path):
            info["status"] = 0  # 文件状态 0 已删除 1 存在
            info["accept"] = None
            info["user"] = None
            info["atime"] = None
            info["ctime"] = None
            info["mtime"] = None
            info["ps"] = None
            return
        
        # 文件状态
        info["status"] = 1
        
        # 获取文件信息
        stat_file = os.stat(path)
        
        info["accept"] = oct(stat_file.st_mode)[-3:]
        import pwd
        try:
            info["user"] = pwd.getpwuid(stat_file.st_uid).pw_name
        except:
            info["user"] = str(stat_file.st_uid)
        info["atime"] = int(stat_file.st_atime)
        info["ctime"] = int(stat_file.st_ctime)
        info["mtime"] = int(stat_file.st_mtime)
        # info["ps"] = cls.get_file_ps(path)
    
    @classmethod
    def __analysis_sub_path_size(cls, analysis_data: list) -> dict:
        """
        @name 获取子目录信息
        @param analysis_data 目录信息
        @param result 结果
        """
        scan_result = analysis_data[0]
        scan_result["type"] = 1
        scan_result["asize"] = scan_result.get("asize", 0)
        scan_result["dsize"] = scan_result.get("dsize", 0)
        scan_result["dirs"] = 0
        scan_result["files"] = 0
        scan_result["dir_num"] = 0
        scan_result["file_num"] = 0
        scan_result["total_asize"] = scan_result.get("asize", 0)
        scan_result["total_dsize"] = scan_result.get("dsize", 0)
        
        for info in analysis_data[1:]:
            if isinstance(info, list):  # 目录
                scan_result["dirs"] += 1
                scan_result["dir_num"] += 1
                info = cls.__analysis_sub_path_size(info)
                scan_result["dir_num"] += info["dir_num"]
                scan_result["file_num"] += info["file_num"]
                scan_result["total_asize"] += info["total_asize"]
                scan_result["total_dsize"] += info["total_dsize"]
            else:
                if info.get("excluded") == "pattern":
                    continue
                scan_result["files"] += 1
                scan_result["file_num"] += 1
                if info.get("asize") is None: info["asize"] = 0
                if info.get("dsize") is None: info["dsize"] = 0
                scan_result["total_asize"] += info["asize"]
                scan_result["total_dsize"] += info["dsize"]
        
        return scan_result
    
    @classmethod
    def __analysis_batch_path_size(cls, analysis_data: list, scan_path_list: list, scan_time: int) -> dict:
        """
        @name 获取批量获取指定目录信息
        @param data 目录信息
        @param result 结果
        """
        result = {}
        scan_result = analysis_data[0]
        scan_result["type"] = 1
        scan_result["asize"] = scan_result.get("asize", 0)
        scan_result["dsize"] = scan_result.get("dsize", 0)
        scan_result["dirs"] = 0
        scan_result["files"] = 0
        scan_result["dir_num"] = 0
        scan_result["file_num"] = 0
        scan_result["total_asize"] = scan_result.get("asize", 0)
        scan_result["total_dsize"] = scan_result.get("dsize", 0)
        
        for info in analysis_data[1:]:
            if isinstance(info, list):  # 目录
                scan_result["dirs"] += 1
                scan_result["dir_num"] += 1
                info[0]["full_path"] = os.path.join(scan_result["full_path"], info[0]["name"])
                data = cls.__analysis_batch_path_size(info, scan_path_list, scan_time)
                result.update(data)
                info = info[0]
                scan_result["dir_num"] += info["dir_num"]
                scan_result["file_num"] += info["file_num"]
                scan_result["total_asize"] += info["total_asize"]
                scan_result["total_dsize"] += info["total_dsize"]
            else:
                info["full_path"] = os.path.join(scan_result["full_path"], info["name"])
                if info.get("excluded") == "pattern":
                    info["excluded"] = True
                    info["type"] = int(os.path.isdir(info["full_path"]))
                    if info["type"] == 1:  # 排除目录
                        info["files"] = 0
                        info["file_num"] = 0
                        info["dirs"] = 0
                        info["dir_num"] = 0
                else:
                    info["excluded"] = False
                    info["type"] = 0
                    info["files"] = -1
                    info["file_num"] = -1
                    info["dirs"] = -1
                    info["dir_num"] = -1
                scan_result["files"] += 1
                scan_result["file_num"] += 1
                if info.get("asize") is None: info["asize"] = 0
                if info.get("dsize") is None: info["dsize"] = 0
                info["total_asize"] = info["asize"]
                info["total_dsize"] = info["dsize"]
                scan_result["total_asize"] += info["asize"]
                scan_result["total_dsize"] += info["dsize"]
                
                if info["full_path"] in scan_path_list:
                    cls.__get_stat(info["full_path"], info)
                    info["stime"] = scan_time
                    result[info["full_path"]] = info
        
        if scan_result["full_path"] in scan_path_list:
            cls.__get_stat(scan_result["full_path"], scan_result)
            scan_result["stime"] = scan_time
            result[scan_result["full_path"]] = scan_result
        return result
    
    def get_batch_path_size(self, get):
        """
        @name 根据排除目录获取路径的总大小
        @param path 目标路径
        """
        # 校验磁盘大小
        resp = self.__check_disk()
        if isinstance(resp, str):
            return public.returnMsg(False, resp)
        
        if not hasattr(get, "path_list"):
            return public.returnMsg(False, "缺少参数! path_list")
        
        scan_path_list = json.loads(get.path_list)
        
        real_path_dict = {}  # 软连接处理
        for idx in range(len(scan_path_list)):
            path = scan_path_list[idx]
            r_path = os.path.realpath(path)
            if r_path != path:
                scan_path_list[idx] = r_path
                real_path_dict[r_path] = path
        
        scan_path = scan_path_list[0]
        if os.path.isfile(scan_path):
            scan_path = os.path.dirname(scan_path)
        for path in scan_path_list[1:]:
            while not path.startswith(scan_path):
                scan_path = os.path.dirname(scan_path)

        if not os.path.exists(scan_path):
            return public.returnMsg(False, "目录不存在！")

        # 生成 id
        scan_id = "temp_info_" + str(time.time()).replace(".", "")
        scan_result_file = os.path.join(self.scan_temp_path, scan_id)
        while os.path.exists(scan_result_file):
            scan_id = "temp_info_" + str(time.time()).replace(".", "")
            scan_result_file = os.path.join(self.scan_temp_path, scan_id)

        check = public.ExecShell("{} -V".format(self.ncdu_exe))
        if not check[0] or check[1]:
            return public.returnMsg(False, "检测到您已安装【堡塔硬盘分析工具】，但在扫描时运行【堡塔硬盘分析工具】出现错误！请修复或卸载【堡塔硬盘分析工具】后重试")
        scan_time = int(time.time())
        exec_shell = "{} '{}' -o '{}' ".format(self.ncdu_exe, scan_path, scan_result_file).replace('\\', '/').replace('//', '/')
        public.ExecShell(exec_shell)
        # 解析扫描结果
        scan_data_dict = {}  # 结果列表
        try:
            if not os.path.isfile(scan_result_file):
                return public.returnMsg(False, f"扫描错误！请检查：<br/>1. 服务器磁盘是否已满，请确保 / 或 /www 磁盘有可用空间！")
            
            data = public.readFile(scan_result_file)
            data = json.loads(data)
            for info in data:
                if not isinstance(info, list): continue
                info[0]["full_path"] = info[0]["name"]
                scan_data_dict = self.__analysis_batch_path_size(info, scan_path_list, scan_time)
                break
            # 解析完陈删除
            os.remove(scan_result_file)
        except Exception as err:
            return public.returnMsg(False, f"解析扫描结果错误！{err}")
        for r_path, path in real_path_dict.items():
            scan_data_dict[path] = scan_data_dict[r_path]
            del scan_data_dict[r_path]
        public.set_module_logs("disk_analysis", "get_batch_path_size", 1)
        return {"status": True, "msg": "扫描完成!", "data": scan_data_dict}
    
    @classmethod
    def __analysis_dir_path_size(cls, analysis_data: list, scan_time: int) -> dict:
        """
        @name 获取文件目录信息
        @param data 目录信息
        @param result 结果
        """
        scan_result = analysis_data[0]
        scan_result["type"] = 1
        scan_result["asize"] = scan_result.get("asize", 0)
        scan_result["dsize"] = scan_result.get("dsize", 0)
        scan_result["dirs"] = 0
        scan_result["files"] = 0
        scan_result["dir_num"] = 0
        scan_result["file_num"] = 0
        scan_result["total_asize"] = scan_result.get("asize", 0)
        scan_result["total_dsize"] = scan_result.get("dsize", 0)
        scan_result["scan_time"] = scan_time
        scan_result["list"] = {}
        cls.__get_stat(scan_result["full_path"], scan_result)
        
        for info in analysis_data[1:]:
            if isinstance(info, list):  # 目录
                scan_result["dirs"] += 1
                scan_result["dir_num"] += 1
                info[0]["full_path"] = os.path.join(scan_result["full_path"], info[0]["name"])
                info = cls.__analysis_sub_path_size(info)
                scan_result["dir_num"] += info["dir_num"]
                scan_result["file_num"] += info["file_num"]
                scan_result["total_asize"] += info["total_asize"]
                scan_result["total_dsize"] += info["total_dsize"]
            else:
                info["full_path"] = os.path.join(scan_result["full_path"], info["name"])
                if info.get("excluded") == "pattern":
                    info["excluded"] = True
                    info["type"] = int(os.path.isdir(info["full_path"]))
                    if info["type"] == 1:  # 排除目录
                        info["files"] = 0
                        info["file_num"] = 0
                        info["dirs"] = 0
                        info["dir_num"] = 0
                else:
                    info["excluded"] = False
                    info["type"] = 0
                    info["files"] = -1
                    info["file_num"] = -1
                    info["dirs"] = -1
                    info["dir_num"] = -1
                if info.get("notreg") is True and os.path.isdir(info["full_path"]) is True:
                    info["dir_num"] = 0
                    info["file_num"] = 0
                scan_result["files"] += 1
                scan_result["file_num"] += 1
                if info.get("asize") is None: info["asize"] = 0
                if info.get("dsize") is None: info["dsize"] = 0
                info["total_asize"] = info["asize"]
                info["total_dsize"] = info["dsize"]
                info["scan_time"] = scan_time
                scan_result["total_asize"] += info["asize"]
                scan_result["total_dsize"] += info["dsize"]
            cls.__get_stat(info["full_path"], info)
            
            scan_result["list"][info["name"]] = info
        return scan_result
    
    # 获取目录大小
    def get_dir_path_size(self, get):
        """
        @name 根据排除目录获取路径的总大小
        @param path 目标路径
        """
        # 校验磁盘大小
        resp = self.__check_disk()
        if isinstance(resp, str):
            return public.returnMsg(False, resp)
        
        if not hasattr(get, "path"):
            return public.returnMsg(False, "缺少参数! path")
        scan_path = get.path
        
        # 生成 id
        scan_id = "temp_info_" + str(time.time()).replace(".", "")
        scan_result_file = os.path.join(self.scan_temp_path, scan_id)
        while os.path.exists(scan_result_file):
            scan_id = "temp_info_" + str(time.time()).replace(".", "")
            scan_result_file = os.path.join(self.scan_temp_path, scan_id)

        check = public.ExecShell("{} -V".format(self.ncdu_exe))
        if not check[0] or check[1]:
            return public.returnMsg(False, "检测到您已安装【堡塔硬盘分析工具】，但在扫描时运行【堡塔硬盘分析工具】出现错误！请修复或卸载【堡塔硬盘分析工具】后重试")
        exec_shell = "{} '{}' -o '{}' ".format(self.ncdu_exe, scan_path, scan_result_file).replace('\\', '/').replace('//', '/')
        scan_time = int(time.time())
        public.ExecShell(exec_shell)

        # 解析扫描结果
        scan_data_dict = {}  # 结果列表
        try:
            if not os.path.isfile(scan_result_file):
                return public.returnMsg(False, f"扫描错误！请检查：<br/>1. 服务器磁盘是否已满，请确保 / 或 /www 磁盘有可用空间！")
            data = public.readFile(scan_result_file)
            data = json.loads(data)
            for info in data:
                if not isinstance(info, list): continue
                info[0]["full_path"] = info[0]["name"]
                scan_data_dict = self.__analysis_dir_path_size(info, scan_time)
                break
            # 解析完陈删除
            os.remove(scan_result_file)
        except Exception as err:
            return public.returnMsg(False, f"解析扫描结果错误！{err}")

        public.set_module_logs("disk_analysis", "get_dir_path_size", 1)
        return {"status": True, "msg": "扫描完成!", "data": scan_data_dict}
