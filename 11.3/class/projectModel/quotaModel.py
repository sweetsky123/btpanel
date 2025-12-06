# coding: utf-8
# -------------------------------------------------------------------
# 宝塔Linux面板
# -------------------------------------------------------------------
# Copyright (c) 2015-2017 宝塔软件(http:#bt.cn) All rights reserved.
# -------------------------------------------------------------------
# Author: hwliang <hwl@bt.cn>
# -------------------------------------------------------------------

# ------------------------------
# 磁盘配额管理
# ------------------------------
import os
import json
import time
import re
from typing import Union

import public
import psutil
from projectModel.base import projectBase
from panelMysql import panelMysql


class main(projectBase):
    __SETTINGS_FILE = os.path.join(public.get_panel_path(), "config/quota_list.json")

    __AUTH_MSG = public.to_string([27492, 21151, 33021, 20026, 20225, 19994, 29256, 19987, 20139, 21151, 33021, 65292, 35831, 20808, 36141, 20080, 20225, 19994, 29256])

    # 告警推送
    __PUSH_FILE = os.path.join(public.get_panel_path(), "class/push/push.json")

    def __init__(self):
        if not os.path.exists(self.__SETTINGS_FILE):
            public.writeFile(self.__SETTINGS_FILE, "{}")

        xfs_quota_bin = "/usr/sbin/xfs_quota"
        if not os.path.exists(xfs_quota_bin):
            if os.path.exists("/usr/bin/apt-get"):
                public.ExecShell("nohup apt-get install xfsprogs -y > /dev/null &")
            else:
                public.ExecShell("nohup yum install xfsprogs -y > /dev/null &")

        self.update()

    @classmethod
    def update(cls):
        config_file = os.path.join(public.get_panel_path(), "config/quota.json")
        mysql_file = os.path.join(public.get_panel_path(), "config/mysql_quota.json")
        if not os.path.exists(config_file) or not os.path.exists(mysql_file):
            return

        quota_dict = {}

        try:
            config_list = json.loads(public.readFile(config_file))
        except:
            config_list = []
        for config in config_list:
            path = config["path"]
            quota_dict[path] = {
                "id": config.get("id", cls.__get_quota_id(quota_dict)),
                "quota_type": "path",
                "quota_push": {
                    "size": config.get("size", 0),
                    "interval": 600,
                    "module": "",
                    "push_count": 3,
                    "status": False,
                },
                "quota_storage": {
                    "size": config.get("size", 0)
                },
            }

        try:
            mysql_list = json.loads(public.readFile(mysql_file))
        except:
            mysql_list = []

        data_dir = cls.get_datadir()
        for config in mysql_list:
            path = os.path.join(data_dir, config["db_name"])
            quota_dict[path] = {
                "id": config.get("id", cls.__get_quota_id(quota_dict)),
                "db_name": config["db_name"],
                "quota_type": "database",
                "quota_push": {
                    "size": config.get("size", 0),
                    "interval": 600,
                    "module": "",
                    "push_count": 3,
                    "status": False,
                },
                "quota_storage": {
                    "size": config.get("size", 0),
                    "insert_accept": config.get("insert_accept", False),
                },
            }

        public.writeFile(cls.__SETTINGS_FILE, json.dumps(quota_dict))
        os.remove(config_file)
        os.remove(mysql_file)

    # 检查
    @classmethod
    def __check_auth(cls):
        from pluginAuth import Plugin
        plugin_obj = Plugin(False)
        plugin_list = plugin_obj.get_plugin_list()
        return int(plugin_list["ltd"]) > time.time()

    @classmethod
    def __get_xfs_disk(cls) -> list:
        disks = []
        for disk in psutil.disk_partitions():
            if disk.fstype == "xfs":
                disk_info = {
                    "mountpoint": disk.mountpoint,  # 磁盘挂载点
                    "device": disk.device,  # 磁盘分区设备名称
                    "free": psutil.disk_usage(disk.mountpoint).free,  # 磁盘分区设备名称
                    "opts": disk.opts.split(","),  # 磁盘分区的选项
                }
                disks.append(disk_info)
        return disks

    # 获取目录是否在挂载点
    @classmethod
    def __get_path_dev_mountpoint(cls, path: str) -> Union[None, dict]:
        disk_list = cls.__get_xfs_disk()
        disk_list.sort(key=lambda item: (item["mountpoint"].count("/"), len(item["mountpoint"][item["mountpoint"].find("/"):])), reverse=True)
        for disk in disk_list:
            if path.startswith(disk["mountpoint"]):
                return disk
        return None

    # 获取xfs文件系统中最大的配额ID
    @classmethod
    def __get_xfs_quota_id(cls, mountpoint) -> int:
        result = public.ExecShell("xfs_quota -x -c report {mountpoint}|awk '{{print $1}}'|grep '#'".format(mountpoint=mountpoint))[0]
        if not result: return 0
        id_list = re.findall("#(\d+)\n", result)
        return int(max(id_list))

    # 获取配额最大 id
    @classmethod
    def __get_quota_id(cls, quota_dict):
        quota_id = 1001
        if not quota_dict: return quota_id

        quota_id_set = set([item["id"] for item in quota_dict.values()])
        while quota_id in quota_id_set:
            quota_id += 1
        return quota_id

    # 获取所有配额列表
    @classmethod
    def __get_quota_list(cls) -> dict:
        quota_dict = {}
        try:
            quota_dict = json.loads(public.readFile(cls.__SETTINGS_FILE))
        except:
            pass
        if isinstance(quota_dict, list) and not quota_dict:
            return {}
        return quota_dict

    # 获取磁盘配额目录
    @classmethod
    def get_quota_path(cls, path) -> dict:
        path = str(path).rstrip("/")
        quota_dict = cls.__get_quota_list()
        defaulte_path_quota = {
            "used": 0,
            "quota_push": {
                "size": 0,
                "used": 0,
            },
            "quota_storage": {
                "size": 0,
                "used": 0,
            }
        }

        quota = quota_dict.get(path, defaulte_path_quota)
        quota["used"] = -1
        if os.path.exists(path):
            # usage_info = psutil.disk_usage(path)
            # quota["used"] = usage_info.usbed
            # quota["free"] = usage_info.free
            quota["used"] = public.get_path_size(path)
        quota["quota_storage"]["used"] = quota["used"]
        quota["quota_push"]["used"] = quota["used"]
        return quota
    
    def get_path_quota(self,get):
        if not hasattr(get, "path"):
            return public.returnMsg(False, "缺少参数！path")
        return self.get_quota_path(get.path)
    
    
    # 设置目录配额
    def modify_path_quota(self, args):
        if not self.__check_auth():
            return public.returnMsg(False, self.__AUTH_MSG)
        if not hasattr(args, "path"):
            return public.returnMsg(False, "缺少参数！path")
        if not hasattr(args, "quota_type"):
            return public.returnMsg(False, "缺少参数！quota_type")
        if not hasattr(args, "quota_push"):
            return public.returnMsg(False, "缺少参数！quota_push")
        if not hasattr(args, "quota_storage"):
            return public.returnMsg(False, "缺少参数！quota_storage")

        path = args.path
        quota_type = args.quota_type
        if not isinstance(args.quota_push, dict):
            return public.returnMsg(False, "参数错误！ quota_push")
        if not isinstance(args.quota_storage, dict):
            return public.returnMsg(False, "参数错误！ quota_storage")
        if quota_type not in ["site", "ftp", "path"]:
            return public.returnMsg(False, "参数错误！quota_type")

        public.set_module_logs("quota", "modify_path_quota")

        if args.quota_push.get("status", False) is True:
            args.quota_push["module"] = args.quota_push.get("module", "").strip(",")
            if not args.quota_push["module"]:
                return public.returnMsg(False, "请选择推送消息通道！")

        path = str(path).rstrip("/")

        if not os.path.exists(path):
            return public.returnMsg(False, "指定目录不存在")
        if os.path.isfile(path):
            return public.returnMsg(False, "指定目录不是目录!")
        if os.path.islink(path):
            return public.returnMsg(False, "指定目录是软链接!")
        if not os.path.isdir(path):
            return public.returnMsg(False, "这不是一个有效的目录!")

        quota_dict = self.__get_quota_list()

        if quota_dict.get(path) is not None:
            if quota_dict[path]["quota_type"] == "database":
                return public.returnMsg(False, "该路径已被设置数据库配额！")
            quota = quota_dict[path]
            quota["quota_push"]["size"] = int(args.quota_push.get("size", 0))
            quota["quota_push"]["interval"] = int(args.quota_push.get("interval", 600))
            quota["quota_push"]["module"] = args.quota_push["module"]
            quota["quota_push"]["push_count"] = int(args.quota_push.get("push_count", 3))
            quota["quota_push"]["status"] = args.quota_push.get("status", False)
            quota["quota_storage"]["size"] = int(args.quota_storage.get("size", 0))
        else:
            quota = {
                "id": self.__get_quota_id(quota_dict),
                "quota_type": quota_type,
                "quota_push": {
                    "size": int(args.quota_push.get("size", 0)),
                    "interval": int(args.quota_push.get("interval", 600)),
                    "module": args.quota_push.get("module", ""),
                    "push_count": int(args.quota_push.get("push_count", 3)),
                    "status": args.quota_push.get("status", False),
                },
                "quota_storage": {
                    "size": int(args.quota_storage.get("size", 0)),
                },
            }

        if quota["quota_storage"]["size"] > 0:
            disk = self.__get_path_dev_mountpoint(path)
            if disk is None:
                return public.returnMsg(False, "指定目录所在分区不是XFS分区,不支持目录配额!")

            if "prjquota" not in disk["opts"]:
                msg = '<div class="ftp-verify-disk">指定xfs分区未开启目录配额功能,请在挂载该分区时增加prjquota参数<p>/etc/fstab文件配置示例：</p><pre>{device}       {mountpoint}           xfs             defaults,prjquota       0 0</pre><p>注意：配置好后需重新挂载分区或重启服务器才能生效</p></div>'.format(device=disk["device"], mountpoint=disk["mountpoint"])
                return public.returnMsg(False, msg)

            if args.quota_storage.get("size", 0) * 1024 * 1024 > disk["free"]:
                return public.returnMsg(False, "指定磁盘可用的配额容量不足!")

            res = public.ExecShell("xfs_quota -x -c 'project -s -p {path} {quota_id}'".format(path=path, quota_id=quota["id"]))
            if res[1]: return public.returnMsg(False, "设置配额错误！{}".format(res[1]))
            res = public.ExecShell("xfs_quota -x -c 'limit -p bhard={size}m {quota_id}' {mountpoint}".format(size=quota["quota_storage"]["size"], quota_id=quota["id"], mountpoint=disk["mountpoint"]))
            if res[1]: return public.returnMsg(False, "设置配额错误！{}".format(res[1]))

        self.__set_push(quota)

        quota_dict[path] = quota
        public.WriteLog("磁盘配额", "设置目录[{path}]的配额限制为: {size}MB".format(path=path, size=quota["quota_storage"]["size"]))
        public.writeFile(self.__SETTINGS_FILE, json.dumps(quota_dict))
        return public.returnMsg(True, "设置配额成功!")

    # 获取 mysql 数据库目录
    @classmethod
    def get_datadir(cls) -> str:
        data_dir = None
        data = panelMysql().query("show variables like 'datadir';")
        if data and isinstance(data, list):
            data_dir = data[0][1]

        if data_dir is None:
            myfile = "/etc/my.cnf"
            mycnf = public.readFile(myfile)
            try:
                data_dir = re.search("datadir\s*=\s*(.+)\n", mycnf).groups()[0]
            except:
                data_dir = "/www/server/data"
        return data_dir

    # 获取数据库配额
    @classmethod
    def get_quota_mysql(cls, name) -> dict:
        quota_dict = cls.__get_quota_list()
        data_dir = cls.get_datadir()
        defaulte_db_quota = {
            "used": 0,
            "size": 0,
            "quota_push": {
                "used": 0,
                "size": 0,
            },
            "quota_storage": {
                "used": 0,
                "size": 0,
            }
        }

        path = os.path.join(data_dir, name)
        quota = quota_dict.get(path, defaulte_db_quota)
        quota["used"] = -1
        if os.path.isdir(path):
            quota["used"] = public.get_path_size(path)

        quota["quota_storage"]["used"] = quota["used"]
        quota["quota_push"]["used"] = quota["used"]
        return quota

    # 移除数据库用户的插入权限
    @classmethod
    def __rm_mysql_insert_accept(cls, mysql_obj, username, db_name, db_host):
        res = mysql_obj.execute("REVOKE ALL PRIVILEGES ON `{}`.* FROM '{}'@'{}';".format(db_name, username, db_host))
        if res: raise public.PanelError("移除数据库用户的插入权限失败: {}".format(res))
        res = mysql_obj.execute("GRANT SELECT, DELETE, CREATE, DROP, REFERENCES, INDEX, CREATE TEMPORARY TABLES, LOCK TABLES, CREATE VIEW, EVENT, TRIGGER, SHOW VIEW, CREATE ROUTINE, ALTER ROUTINE, EXECUTE ON `{}`.* TO '{}'@'{}';".format(db_name, username, db_host))
        if res: raise public.PanelError("移除数据库用户的插入权限失败: {}".format(res))
        mysql_obj.execute("FLUSH PRIVILEGES;")
        return True

    # 恢复数据库用户的插入权限
    @classmethod
    def __rep_mysql_insert_accept(cls, mysql_obj, username, db_name, db_host):
        res = mysql_obj.execute("REVOKE ALL PRIVILEGES ON `{}`.* FROM '{}'@'{}';".format(db_name, username, db_host))
        if res: raise public.PanelError("恢复数据库用户的插入权限失败: {}".format(res))
        res = mysql_obj.execute("GRANT ALL PRIVILEGES ON `{}`.* TO '{}'@'{}';".format(db_name, username, db_host))
        if res: raise public.PanelError("恢复数据库用户的插入权限失败: {}".format(res))
        mysql_obj.execute("FLUSH PRIVILEGES;")
        return True

    # 设置数据库配额
    def modify_database_quota(self, args):
        if not self.__check_auth():
            return public.returnMsg(False, self.__AUTH_MSG)
        if not hasattr(args, "db_name"):
            return public.returnMsg(False, "缺少参数！db_name")


        nSize = 0
        try:
            if 'size' in args:
                nSize = int(args.size)
            if 'quota_storage' in args:
                nSize = int(args.quota_storage.get("size", 0))
        except: pass


        #是否支持推送
        is_push_conf = False
        if 'quota_push' in args:
            if not isinstance(args.quota_push, dict):
                return public.returnMsg(False, "参数错误！ quota_push")

            if args.quota_push.get("status", False) is True:
                args.quota_push["module"] = args.quota_push.get("module", "").strip(",")
                if not args.quota_push["module"]:
                    return public.returnMsg(False, "请选择推送消息通道！")
            is_push_conf = True

        db_name = args.db_name.strip()

        if not public.M("databases").where("name=? AND LOWER(type)=LOWER('mysql') AND sid=0", (db_name,)).count():
            return public.returnMsg(False, "暂不支持远程数据库配额！")

        data_dir = self.get_datadir()
        path = os.path.join(data_dir, db_name)

        if not os.path.isdir(path):
            return public.returnMsg(False, "数据库目录【{}】不存在!".format(path))

        quota_dict = self.__get_quota_list()

        if quota_dict.get(path) is not None:
            # if quota_dict[path]["quota_type"] != "database":
            #     return public.returnMsg(False, "该数据库目录已被设置目录配额！")
            quota = quota_dict[path]

            if "quota_push" not in quota:
                quota["quota_push"] = {}

            if is_push_conf:
                quota["quota_push"]["size"] = int(args.quota_push.get("size", 0))
                quota["quota_push"]["interval"] = int(args.quota_push.get("interval", 600))
                quota["quota_push"]["module"] = args.quota_push["module"]
                quota["quota_push"]["push_count"] = int(args.quota_push.get("push_count", 3))
                quota["quota_push"]["status"] = args.quota_push.get("status", False)
            quota["quota_storage"]["size"] = nSize
        else:
            quota = {
                "id": self.__get_quota_id(quota_dict),
                "db_name": db_name,
                "quota_type": "database",
                "quota_storage": {
                    "size": nSize,
                    "insert_accept": True,
                }
            }

            if is_push_conf:
                quota["quota_push"] =  {
                    "size": int(args.quota_push.get("size", 0)),
                    "interval": int(args.quota_push.get("interval", 600)),
                    "module": args.quota_push.get("module", ""),
                    "push_count": int(args.quota_push.get("push_count", 3)),
                    "status": args.quota_push.get("status", False),
                }

                self.__set_push(quota)

        quota_dict[path] = quota

        public.WriteLog("磁盘配额", "设置数据库[{db_name}]的配额限制为: {size}MB".format(db_name=db_name, size=nSize))
        public.writeFile(self.__SETTINGS_FILE, json.dumps(quota_dict))
        return public.returnMsg(True, "设置配额成功!")

    # 恢复数据库权限
    def recover_database_insert_accept(self, args):
        if not hasattr(args, "db_name"):
            return public.returnMsg(False, "缺少参数！db_name")

        db_name = args.db_name.strip()
        db_info = public.M("databases").where("name=? AND LOWER(type)=LOWER('mysql') AND sid=0", (db_name,)).find()
        if not db_info:
            return public.returnMsg(False, "暂不支持远程数据库配额！")

        data_dir = self.get_datadir()
        path = os.path.join(data_dir, db_name)

        quota_dict = self.__get_quota_list()
        if quota_dict.get(path) is None:
            return public.returnMsg(False, "该数据库配额信息不存在！")

        quota = quota_dict[path]

        mysql_obj = panelMysql()
        if not mysql_obj: return public.returnMsg(False, "连接本地数据库失败！")

        accept = mysql_obj.query("select Host from mysql.user where User='{username}'".format(username=db_info["username"]))
        if not isinstance(accept, list):
            return
        for host in accept:
            self.__rep_mysql_insert_accept(mysql_obj, db_info["username"], db_name, host[0])
        quota["quota_storage"]["insert_accept"] = True
        public.WriteLog("磁盘配额", "已关闭数据库[{}]配额,恢复插入权限".format(quota["db_name"]))
        public.writeFile(self.__SETTINGS_FILE, json.dumps(quota_dict))
        return public.returnMsg(True, "恢复成功！")

    # 设置告警
    @classmethod
    def __set_push(cls, quota: dict):
        type_msg_dict = {
            "database": "数据库",
            "site": "网站目录",
            "ftp": "FTP 目录",
        }
        try:
            push_dict = json.loads(public.readFile(cls.__PUSH_FILE))
        except:
            push_dict = {}

        quota_push_dict = push_dict.get("quota_push", {})

        quota_push = quota_push_dict.get(str(quota["id"]))

        if quota["quota_push"]["status"] is True:  # 推送状态
            if quota_push is None:
                quota_push = quota["quota_push"]
            else:
                quota_push.update(quota["quota_push"])
            quota_push["id"] = quota["id"]
            quota_push["title"] = "{} 磁盘容量告警".format(type_msg_dict.get(quota["quota_type"]))
            quota_push["type"] = quota["quota_type"]

            quota_push_dict[str(quota["id"])] = quota_push
        else:
            if quota_push is not None:
                del quota_push_dict[str(quota["id"])]

        push_dict["quota_push"] = quota_push_dict
        public.writeFile(cls.__PUSH_FILE, json.dumps(push_dict))

    # 检查
    @classmethod
    def quota_check(cls, quota_id: int):
        quota_dict = cls.__get_quota_list()

        quota = None
        for path, quota_info in quota_dict.items():
            if quota_info["id"] == quota_id:
                quota = quota_info
                quota["path"] = path
                break

        if quota is None:
            return None

        quota["used"] = public.get_path_size(quota["path"])

        if quota["quota_push"]["size"] * 1024 * 1024 < quota["used"]:
            return quota
        return None

    # 检查MySQL配额
    def database_quota_check(self, get) -> int:
        """
        task.py 60 定时执行
        """
        num = 0
        if not self.__check_auth():
            return num

        data_dir = self.get_datadir()

        quota_dict = self.__get_quota_list()
        mysql_obj = panelMysql()
        if not mysql_obj: return num
        try:
            for path, quota in quota_dict.items():
                if quota["quota_type"] != "database": continue
                num += 1

                temp_path = os.path.join(data_dir, quota["db_name"])
                if temp_path != path:
                    quota_dict[temp_path] = quota
                    del quota_dict[path]
                    quota = quota_dict[temp_path]
                    path = temp_path

                quota["used"] = public.get_path_size(path)

                username = public.M("databases").where("name=? AND LOWER(type)=LOWER('mysql') AND sid=0", (quota["db_name"],)).getField("username")
                accept = mysql_obj.query("select Host from mysql.user where User='{username}'".format(username=username))
                if not isinstance(accept, list):
                    continue

                if quota["quota_storage"]["size"] < 1 and quota["quota_storage"].get("insert_accept", False) is False:
                    for host in accept:
                        self.__rep_mysql_insert_accept(mysql_obj, username, quota["db_name"], host[0])
                    quota["quota_storage"]["insert_accept"] = True
                    public.WriteLog("磁盘配额", "已关闭数据库[{}]配额,恢复插入权限".format(quota["db_name"]))
                    continue

                if quota["quota_storage"]["size"] * 1024 * 1024 < quota["used"]:
                    if quota["quota_storage"].get("insert_accept", False) is True:
                        for host in accept:
                            self.__rm_mysql_insert_accept(mysql_obj, username, quota["db_name"], host[0])
                        quota["quota_storage"]["insert_accept"] = False
                        public.WriteLog("磁盘配额", "数据库[{}]因超出配额[{}MB],移除插入权限".format(quota["db_name"], quota["quota_storage"]["size"]))

                elif quota["quota_storage"].get("insert_accept", False) is False:
                    for host in accept:
                        self.__rep_mysql_insert_accept(mysql_obj, username, quota["db_name"], host[0])
                    quota["quota_storage"]["insert_accept"] = True
                    public.WriteLog("磁盘配额", "数据库[{}]因低于配额[{}MB],恢复插入权限".format(quota["db_name"], quota["quota_storage"]["size"]))
        except Exception as err:
            pass
        public.writeFile(self.__SETTINGS_FILE, json.dumps(quota_dict))
        return num

    # 网站配额
    def modify_path_quota_old(self, args):
        args.path = args.path
        args.quota_type = "site"
        args.quota_push = {"module": "", "status": False, "push_count": 5, "size": 0}
        args.quota_storage = {"size": 10}
        return self.modify_path_quota(args)