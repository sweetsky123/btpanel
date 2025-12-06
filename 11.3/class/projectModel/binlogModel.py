# coding: utf-8
# -------------------------------------------------------------------
# 宝塔Linux面板
# -------------------------------------------------------------------
# Copyright (c) 2015-2099 宝塔软件(http:#bt.cn) All rights reserved.
# -------------------------------------------------------------------
# Author: hezhihong <bt_ahong@qq.com>
# -------------------------------------------------------------------

# ------------------------------
# MySQL二进制日志备份
# ------------------------------
import os
import sys
import time
import json
import re
import datetime

from typing import Tuple, Union

os.chdir("/www/server/panel")
sys.path.append("class/")
import public
from projectModel.base import projectBase
from panelMysql import panelMysql
from panelBackup import backup
import db_mysql


class main(projectBase):
    _DB_BACKUP_DIR = os.path.join(public.M("config").where("id=?", (1,)).getField("backup_path"), "database")
    _MYSQL_INCREMENT_BACKUP_DIR = os.path.join(_DB_BACKUP_DIR, "mysql", "increment_backup")

    _BACKUP_DIR = public.M("config").where("id=?", (1,)).getField("backup_path")
    _BINLOG_BACKUP_DIR = os.path.join(_BACKUP_DIR, "mysql_bin_log/")

    _INSTALL_PATH = os.path.join(public.get_panel_path(), "pyenv/bin/python")
    _PYTHON_PATH = os.path.join(public.get_panel_path(), "pyenv/bin/python")
    _BINLOG_MODEL_PATH = os.path.join(public.get_panel_path(), "script/loader_binlog.py")

    _MYSQL_CNF = "/etc/my.cnf"
    _MYSQL_BIN = public.get_mysql_bin()
    _MYSQLDUMP_BIN = public.get_mysqldump_bin()
    _MYSQLBINLOG_BIN = os.path.join(public.get_setup_path(), "mysql/bin/mysqlbinlog")

    _SIZE_MIN = 1024 * 1024 * 1024  # 最小大小
    _INODE_MIN = 100  # 最小inode
    _IS_UPDATE = False
    _BACKUP_TIME=""

    _DATA_SQL_TYPE = {
        "insert": r"INSERT\s+INTO\s+`?{tb_name}`?\s+\([^)]+\)\s+VALUES\s+\(\s*'[^']+'\s*\)(?:,\s*\(\s*'[^']+'\s*\))*;",
        "update": r"UPDATE\s+(['\"`.,\w]*{tb_name}['\"`]*)\s+SET.+;",  # 更新语句
        "delete": r"DELETE\s+FROM\s+(['\"`.,\w]*{tb_name}['\"`]*)\s*.+;",  # 删除语句
        "truncate_table": r"TRUNCATE\s+TABLE\s+(['\"`.,\w\s]*{tb_name}['\"`.,\w\s]*);",  # 清除表数据语句
        # "create_database": r"CREATE\s+DATABASE\s+(['\"`\w\W]*)\s*.+;",  # 创建数据库语句
        "create_table": r"CREATE\s+TABLE\s+(['\"`.,\w]*{tb_name}['\"`]*)\s*.+;",  # 创建表语句
        "create_index": r"CREATE\s+INDEX\s+(['`\"\w\W]+)\s+ON\s+(['\"`.,\w]*{tb_name}['\"`]*)\s+.+;",  # 创建索引
        "alter_table": r"ALTER\s+TABLE\s+(['\"`.,\w]*{tb_name}['\"`]*)\s+.+;",  # 修改表语句
        # "drop_database": r"DROP\s+DATABASE\s+(['\"`\w\W]*);",  # 删除数据库
        "drop_table": r"DROP\s+TABLE\s+(['\"`.,\w\s]*{tb_name}['\"`\s]*)+;",  # 删除表
        "drop_index": r"DROP\s+INDEX\s+(['`\"\w\W]+)\s+ON\s+(['\"`.,\w]*{tb_name}['\"`]*);",  # 删除索引
        "rename_table": r"RENAME\s+TABLE\s+(['\"`.,\w]*{tb_name}['\"`]*\s+TO\s+['\"`.,\w]*|['\"`.,\w]*\s+TO\s+['\"`.,\w]*{tb_name}['\"`]*);",  # 重命名表
    }

    _NEW__DATA_SQL_TYPE = {
        "insert": r"""INSERT\s+INTO\s+`?{tb_name}`?\s*\([^)]+\)\s*VALUES\s*\(((?:[^)(']|'(?:[^']|'')*')*)\)(?:\s*,\s*\(((?:[^)(']|'(?:[^']|'')*')*)\))*\s*;""",
        "update": r"""UPDATE\s+(?:['"`]?{tb_name}['"`]?|['"`]?\w+['"`]?\.['"`]?{tb_name}['"`]?)\s+SET\s+(?:[^;]+)\s*(?:WHERE\s+.+?)?\s*;""",
        "delete": r"""DELETE\s+FROM\s+(?:['"`]?{tb_name}['"`]?|['"`]?\w+['"`]?\.['"`]?{tb_name}['"`]?)\s*(?:WHERE\s+.+?)?\s*;""",
        "truncate_table": r"""TRUNCATE\s+TABLE\s+(?:['"`]?{tb_name}['"`]?|['"`]?\w+['"`]?\.['"`]?{tb_name}['"`]?)\s*;""",
        "create_table": r"""CREATE\s+(?:TEMPORARY\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:['"`]?{tb_name}['"`]?|['"`]?\w+['"`]?\.['"`]?{tb_name}['"`]?)\s*\([^)]+\)(?:\s*[^;]+)?\s*;""",
        "create_index": r"""CREATE\s+(?:UNIQUE\s+)?INDEX\s+['"`]?\w+['"`]?\s+ON\s+(?:['"`]?{tb_name}['"`]?|['"`]?\w+['"`]?\.['"`]?{tb_name}['"`]?)\s*\([^)]+\)\s*;""",
        "alter_table": r"""ALTER\s+TABLE\s+(?:['"`]?{tb_name}['"`]?|['"`]?\w+['"`]?\.['"`]?{tb_name}['"`]?)\s+(?:ADD|DROP|MODIFY|CHANGE|ALTER|RENAME\s+TO|CONVERT\s+TO)[^;]+;""",
        "drop_table": r"""DROP\s+(?:TEMPORARY\s+)?TABLE\s+(?:IF\s+EXISTS\s+)?(?:['"`]?{tb_name}['"`]?|['"`]?\w+['"`]?\.['"`]?{tb_name}['"`]?)\s*;""",
        "drop_index": r"""DROP\s+INDEX\s+['"`]?\w+['"`]?\s+ON\s+(?:['"`]?{tb_name}['"`]?|['"`]?\w+['"`]?\.['"`]?{tb_name}['"`]?)\s*;""",
        "rename_table": r"""RENAME\s+TABLE\s+(?:(?:['"`]?{tb_name}['"`]?|['"`]?\w+['"`]?\.['"`]?{tb_name}['"`]?)\s+TO\s+['"`]?\w+['"`]?|['"`]?\w+['"`]?\s+TO\s+(?:['"`]?{tb_name}['"`]?|['"`]?\w+['"`]?\.['"`]?{tb_name}['"`]?))\s*;"""
    }
    _cloud_name={
        "tianyiyun":"天翼云cos",
        "webdav":"webdav存储",
        "minio":"minio存储",
        "dogecloud":"多吉云COS",
    }

    def __init__(self):
        if not os.path.exists(self._BACKUP_DIR):
            os.makedirs(self._BACKUP_DIR)
        if not os.path.exists(self._BINLOG_BACKUP_DIR):
            os.makedirs(self._BINLOG_BACKUP_DIR)

        self.update_version()
        self.repair_shell()

        self._error_msg = ""
        self.check_and_add_tianyiyun_column()

    def check_and_add_tianyiyun_column(self):
        try:
            public.M('mysql_increment_backup').field('tianyiyun').select()
        except Exception as e:
            if "no such column: tianyiyun" in str(e):
                try:
                    public.M('tianyiyun').execute("ALTER TABLE 'mysql_increment_backup' ADD 'tianyiyun' TEXT DEFAULT ''", ())
                except Exception as e:
                    pass
    # 版本更新
    @classmethod
    def update_version(cls):
        mysqlbinlog_is_exists = public.M("").query("SELECT name FROM sqlite_master WHERE type='table' AND name='mysqlbinlog_backup_setting';")
        if not mysqlbinlog_is_exists or cls._IS_UPDATE is True:
            return
        cls._IS_UPDATE = True

        setting_crontab = {}
        db_zip_password = {}
        crontab_list = public.M("crontab").where("sType=?", ("enterpriseBackup")).select()
        for crontab_info in crontab_list:
            urladdress = str(crontab_info["urladdress"]).split("|")
            db_name = urladdress[0]
            tb_name = urladdress[1]
            binlog_backup_id = urladdress[2]

            binlog_backup_info = public.M("mysqlbinlog_backup_setting").where("id=?", (binlog_backup_id)).find()

            # 重新生成 shell 脚本
            new_crontab = {
                "backupTo": "|".join([data for data in crontab_info["backupTo"].split("|") if data]),
                "sName": db_name,
                "sBody": tb_name,
                "urladdress": "",
                "sType": "mysql_increment_backup",
            }
            crontab_info.update(new_crontab)
            import crontab
            crontab.crontab().GetShell(crontab_info)
            public.M("crontab").where("id=?", (crontab_info["id"],)).update(new_crontab)

            increment_setting = {
                "cron_id": crontab_info["id"],
                "db_name": db_name,
                "tb_name": tb_name,
                "zip_password": binlog_backup_info["zip_password"],
                "last_backup_time": binlog_backup_info["last_excute_backup_time"],
            }
            setting_crontab[binlog_backup_id] = crontab_info["id"]
            db_zip_password[db_name] = binlog_backup_info["zip_password"]
            public.M("mysql_increment_settings").insert(increment_setting)

        inc_backup = {}

        def clear_unzip(backup_dir: str, zip_password):
            if not os.path.isdir(backup_dir): return  # 目录不存在
            full_record_path = os.path.join(backup_dir, "full_record.json")
            if os.path.exists(full_record_path):
                try:
                    full_record_data = json.loads(public.readFile(full_record_path))
                    for data in full_record_data:
                        inc_backup[data["full_name"]] = data["time"]
                except:
                    pass
                os.remove(full_record_path)
            inc_record_path = os.path.join(backup_dir, "inc_record.json")
            if os.path.exists(inc_record_path):
                try:
                    inc_record_data = json.loads(public.readFile(inc_record_path))
                    for data in inc_record_data:
                        inc_backup[data["full_name"]] = data["time"]
                except:
                    pass
                os.remove(inc_record_path)
            for date_name in os.listdir(backup_dir):
                date_dir = os.path.join(backup_dir, date_name)
                if date_dir.endswith(".sql"): os.remove(date_dir)
                if not os.path.isdir(date_dir): continue
                for name in os.listdir(date_dir):
                    zip_file = os.path.join(date_dir, name)
                    if not os.path.isfile(zip_file) or not zip_file.endswith(".zip"): continue
                    if os.path.getsize(zip_file) < 1024:  # 清楚空文件
                        if zip_password:
                            public.ExecShell("unzip -P {zip_password} -o '{file}' -d {input_dir}".format(zip_password=zip_password, file=zip_file, input_dir=date_dir))
                        else:
                            public.ExecShell("unzip -o '{file}' -d {input_dir}".format(file=zip_file, input_dir=date_dir))
                        file_path = ".".join(zip_file.split(".")[:-1]) + ".sql"
                        if not os.path.exists(file_path): continue
                        if os.path.getsize(file_path) == 0:
                            os.remove(file_path)
                            os.remove(zip_file)
                if len(os.listdir(date_dir)) == 0:
                    public.ExecShell("rm -rf {date_dir}".format(date_dir=date_dir))

        # 整理文件
        for db_name in os.listdir(cls._BINLOG_BACKUP_DIR):
            zip_password = db_zip_password.get(db_name)

            db_path = os.path.join(cls._BINLOG_BACKUP_DIR, db_name)
            if not os.path.isdir(db_path): continue
            for type_name in os.listdir(db_path):
                if type_name == "databases":
                    backup_dir = os.path.join(db_path, type_name)
                    clear_unzip(backup_dir, zip_password)
                elif type_name == "tables":
                    table_dir = os.path.join(db_path, type_name)
                    if not os.path.isdir(table_dir): continue
                    for tb_name in os.listdir(table_dir):
                        backup_dir = os.path.join(table_dir, tb_name)
                        clear_unzip(backup_dir, zip_password)

        old_data = public.M("mysqlbinlog_backups").field("sid,size,type,full_json,inc_json,local_name,ftp_name,alioss_name,txcos_name,qiniu_name,aws_name,upyun_name,obs_name,bos_name,gcloud_storage_name,gdrive_name,msonedrive_name").order("sid").select()
        sqlite_obj = public.M("mysql_increment_backup")
        for data in old_data:
            if setting_crontab.get(str(data["sid"])) is None:
                continue
            if data.get("local_name") is not None:
                if not os.path.isfile(data.get("local_name")):
                    continue

            backup_data = {
                "cron_id": setting_crontab[str(data["sid"])],
                "size": data["size"],
                "type": 1 if data["type"] == "full" else 0,
                "addtime": inc_backup.get(data["local_name"]),
                "name": os.path.basename(data["local_name"]),
                "localhost": data.get("local_name"),
                "ftp": data.get("ftp_name"),
                "alioss": data.get("alioss_name"),
                "txcos": data.get("txcos_name"),
                "qiniu": data.get("qiniu_name"),
                "aws_s3": data.get("aws_name"),
                "upyun": data.get("upyun_name"),
                "obs": data.get("obs_name"),
                "bos": data.get("bos_name"),
                "gcloud_storage": data.get("gcloud_storage_name"),
                "gdrive": data.get("gdrive_name"),
                "msonedrive": data.get("msonedrive_name"),
                "jdcloud": "",
                "tianyiyun":data.get("tianyiyun"),
                "webdav":data.get("webdav"),
                "minio":data.get("minio"), 
                "dogecloud":data.get("dogecloud")
            }
            sqlite_obj.insert(backup_data)

        public.M("").execute("DROP TABLE {table_name};".format(table_name="mysqlbinlog_backup_setting"))
        public.M("").execute("DROP TABLE {table_name};".format(table_name="mysqlbinlog_backups"))
        cls._IS_UPDATE = False

    # 修复shell脚本
    @classmethod
    def repair_shell(cls):
        crontab_list = public.M("crontab").where("sType=?", ("mysql_increment_backup")).select()
        for crontab_info in crontab_list:
            echo_shell = os.path.join(public.GetConfigValue("setup_path"), "cron", crontab_info.get("echo"))
            if os.path.exists(echo_shell):
                content = str(public.readFile(echo_shell))
                if str(content).find("script/loader_binlog") == -1:
                    import crontab
                    crontab.crontab().GetShell(crontab_info)

    @classmethod
    def __check_auth(cls) -> bool:
        try:
            from pluginAuth import Plugin
            plugin_obj = Plugin(False)
            plugin_list = plugin_obj.get_plugin_list()
            if int(plugin_list['ltd']) > time.time():
                return True
            return False
        except:
            return False

    # 分页
    @classmethod
    def get_page(cls, data: list, get) -> Tuple[list, str]:
        """
        @name 取分页
        @return 指定分页数据
        """
        p = int(getattr(get, "p", 1))
        limit = int(getattr(get, "limit", 10))

        # 包含分页类
        import page
        # 实例化分页类
        page = page.Page()
        info = {
            "p": p,
            "count": len(data),
            "row": limit,
            "return_js": "",
            "uri": {},
        }

        # 获取分页数据
        page_info = page.GetPage(info)
        start_idx = (int(p) - 1) * limit
        end_idx = p * limit if p * limit < len(data) else len(data)
        data = data[start_idx:end_idx]
        return data, page_info

    # 获取所有数据库
    def get_databases(self, get):
        try:
            database_list = public.M("databases").field("name").where("sid=0 and LOWER(type)=LOWER(?)", ("mysql")).select()
            for database in database_list:
                database["value"] = database["name"]
                cron_id = public.M("mysql_increment_settings").where("db_name=?", (database["name"])).getField("cron_id")
                database["cron_id"] = cron_id if cron_id else None

                table_list = panelMysql().query("show tables from `{db_name}`;".format(db_name=database["name"]))
                if not isinstance(table_list, list):
                    continue
                cron_id = public.M("mysql_increment_settings").where("tb_name == ''", ()).getField("cron_id")
                database["table_list"] = [{"tb_name": "所有", "value": "", "cron_id": cron_id if cron_id else None}]
                for tb_name in table_list:
                    cron_id = public.M("mysql_increment_settings").where("tb_name in (?)", (tb_name[0])).getField("cron_id")
                    database["table_list"].append({"tb_name": tb_name[0], "value": tb_name[0], "cron_id": cron_id if cron_id else None})
            return {"status": True, "msg": "ok", "data": database_list}
        except Exception as err:
            pass
    # 获取 binlog 状态
    def get_binlog_status(self, get=None) -> dict:
        """
            获取数据库二进制日志是否已经开启
            @return:
        """
        binlog_status = panelMysql().query("show variables like 'log_bin'")
        if not isinstance(binlog_status, list):
            return public.returnMsg(False, "连接 Mysql 异常！")
        if "ON" in binlog_status[0]:
            return {"status": True}
        return {"status": False}

    # 获取所有数据库备份信息
    def get_increment_crontab(self, get):
        try:
            db_name = getattr(get, "db_name", None)
            if db_name:
                increment_list = public.M("mysql_increment_settings").field("cron_id,db_name,tb_name,zip_password,last_backup_time").where("db_name=?", (db_name)).order("id desc").select()
            else:
                increment_list = public.M("mysql_increment_settings").field("cron_id,db_name,tb_name,zip_password,last_backup_time").order("id desc").select()
            result = []
            for increment_info in increment_list:
                crontab_info = public.M("crontab").where("id=? and sType=?", (increment_info["cron_id"], "mysql_increment_backup")).find()
                if not crontab_info:
                    public.M("mysql_increment_settings").where("cron_id=?", (increment_info["cron_id"])).delete()
                    public.M("mysql_increment_backup").where("cron_id=?", (increment_info["cron_id"])).delete()
                    continue

                # increment_info.update(crontab_info)

                total_size = public.M("mysql_increment_backup").query("SELECT sum(size) from mysql_increment_backup where cron_id={};".format(increment_info["cron_id"]))
                if not total_size:
                    total_size = 0
                else:
                    total_size = total_size[0][0]
                    if not total_size:
                        total_size = 0

                increment_info["tb_name"] = "所有" if not increment_info["tb_name"] else increment_info["tb_name"]
                increment_info["full_size"] = public.to_size(total_size)
                increment_info["backupTo"] = str(crontab_info["backupTo"]).split("|")
                increment_info["name"] = crontab_info["name"]
                increment_info["sType"] = crontab_info["sType"]
                increment_info["type"] = crontab_info["type"]
                if increment_info["type"] == "week":
                    increment_info["week"] = crontab_info["where1"]
                increment_info["where1"] = crontab_info["where1"]
                increment_info["hour"] = crontab_info["where_hour"]
                increment_info["minute"] = crontab_info["where_minute"]
                increment_info["notice"] = crontab_info["notice"]
                increment_info["notice_channel"] = crontab_info["notice_channel"]
                result.append(increment_info)
            result, page_info = self.get_page(result, get)
            return {"status": True, "msg": "OK", "data": result, "page": page_info}
        except Exception as err:
            pass
    # 添加增量备份任务
    def add_mysql_increment_crontab(self, get):
        pay = self.__check_auth()
        if pay is False:
            return public.returnMsg(False, "当前功能为企业版专享")

        if not hasattr(get, "db_name"):
            return public.returnMsg(False, "缺少参数 db_name!")
        if not hasattr(get, "tb_name"):
            return public.returnMsg(False, "缺少参数 tb_name!")
        db_name = get.db_name
        tb_name = getattr(get, "tb_name", "")
        zip_password = getattr(get, "zip_password", None)

        if public.M("mysql_increment_settings").where("db_name=? and tb_name=?", (db_name, tb_name)).count() != 0:
            return public.returnMsg(False, "指定的数据库或者表已经存在备份，不能重复添加！")

        get["sType"] = "mysql_increment_backup"
        get["sName"] = db_name
        get["sBody"] = tb_name
        import crontab
        resp = crontab.crontab().AddCrontab(get)
        if resp.get("status") is False and resp.get("id") is None:
            return public.returnMsg(False, resp.get("msg"))

        increment_settings = {
            "cron_id": resp.get("id"),
            "db_name": db_name,
            "tb_name": tb_name,
            "zip_password": zip_password,
            "last_backup_time": "",
        }
        public.M("mysql_increment_settings").insert(increment_settings)
        public.set_module_logs("binlog", "add_mysqlbinlog_backup_setting")
        return public.returnMsg(True, "添加成功！")

    # 修改增量备份任务
    def modify_mysql_increment_crontab(self, get):
        pay = self.__check_auth()
        if pay is False:
            return public.returnMsg(False, "当前功能为企业版专享")

        get["sType"] = "mysql_increment_backup"
        import crontab
        resp = crontab.crontab().modify_crond(get)
        if resp.get("status") is False:
            return resp

        return public.returnMsg(True, "修改成功！")

    # 获取可恢复数据库时间点
    def get_backup(self, get):
        pay = self.__check_auth()
        if pay is False:
            return public.returnMsg(False, "当前功能为企业版专享")

        if not hasattr(get, "cron_id"):
            return public.returnMsg(False, "缺少参数 cron_id!")
        if not str(get.cron_id).isdigit():
            return public.returnMsg(False, "参数错误 cron_id!")
        cron_id = int(get.cron_id)
        increment_backup = public.M("mysql_increment_backup").field("cron_id,size,type,addtime,name,localhost").where("cron_id=?", (cron_id)).order("id desc").select()

        return {"status": True, "msg": "OK", "data": increment_backup}

    # 恢复数据库
    def restore_time_database(self, get):
        try:
            pay = self.__check_auth()
            if pay is False:
                return public.returnMsg(False, "当前功能为企业版专享")

            if not hasattr(get, "cron_id"):
                return public.returnMsg(False, "缺少参数 cron_id!")
            if not hasattr(get, "node_time"):
                return public.returnMsg(False, "缺少参数 node_time!")

            cron_id = get.cron_id
            node_time = get.node_time

            node_time = datetime.datetime.strptime(node_time, "%Y-%m-%d %H:%M:%S")

            cron_info = public.M("crontab").where("id=? and sType='mysql_increment_backup'", (cron_id)).find()

            if not cron_info:
                return public.returnMsg(False, "增量备份定时任务不存在！")

            # 取备份配置信息
            increment_setting = public.M("mysql_increment_settings").where("cron_id=?", (cron_id)).find()
            if not increment_setting:
                return public.returnMsg(False, "增量备份配置不存在！")

            increment_backup = public.M("mysql_increment_backup").where("cron_id=?", (cron_id)).select()

            # 连接 Mysql
            db_host = "localhost"
            db_user = "root"
            db_password = public.M("config").where("id=?", (1,)).getField("mysql_root")
            if not db_password:
                return public.returnMsg(False, "数据库密码为空！请先设置数据库密码！")
            try:
                myconf = public.readFile("/etc/my.cnf")
                rep = r"port\s*=\s*([0-9]+)"
                db_port = int(re.search(rep, myconf).groups()[0])
            except:
                db_port = 3306

            mysql_obj = db_mysql.panelMysql().set_host(db_host, db_port, increment_setting["db_name"], db_user, db_password)
            if isinstance(mysql_obj, bool):
                return public.returnMsg(False, "连接数据库[{}:{}]失败".format(db_host, int(db_port)))

            # 临时解压目录
            temp_name = "mysql_restore_temp_{time_num}".format(time_num=int(time.time() * 1000_000))
            backup_type = "databases" if not increment_setting["tb_name"] else "tables"
            temp_dir = os.path.join(self._BINLOG_BACKUP_DIR, increment_setting["db_name"], backup_type, increment_setting["tb_name"], temp_name)

            input_path_list = []
            for info in increment_backup:
                add_time = datetime.datetime.strptime(info["addtime"], "%Y-%m-%d %H:%M:%S")
                if node_time >= add_time:
                    if info.get("localhost"):
                        if os.path.isfile(info.get("localhost")):  # 本地有存储
                            backup_path = info.get("localhost")
                        else:
                            return public.returnMsg(False, "检查到服务器备份文件丢失，请重新添加计划任务进行增量备份！")
                    else:  # 从云存储上拉取备份文件
                        public.ExecShell("rm -rf '{input_dir}'".format(input_dir=temp_dir))
                        return public.returnMsg(False, "暂不支持从云存储上恢复！")
                        # backup_path = ""
                        # from CloudStoraUpload import CloudStoraUpload
                        # for cloud_name in storage_list:
                        #     if backup.get(cloud_name):
                        #         cloud = CloudStoraUpload().run(cloud_name)
                        #         # if cloud
                        #         # backup.get("localhost")
                        #
                        #         backup_path = os.path.join(temp_dir, backup["name"])
                    if not os.path.isfile(backup_path):
                        public.ExecShell("rm -rf '{input_dir}'".format(input_dir=temp_dir))
                        return public.returnMsg(False, "备份文件丢失")

                    # 解压
                    if increment_setting["zip_password"]:
                        public.ExecShell("unzip -P {zip_password} -o '{file}' -d {input_dir}".format(zip_password=increment_setting["zip_password"], file=backup_path, input_dir=temp_dir))
                    else:
                        public.ExecShell("unzip -o '{file}' -d {input_dir}".format(file=backup_path, input_dir=temp_dir))

                    file_name = os.path.basename(backup_path)
                    file_name = ".".join(file_name.split(".")[:-1]) + ".sql"
                    sql_file = os.path.join(temp_dir, file_name)
                    if not os.path.isfile(sql_file):
                        public.ExecShell("rm -rf '{input_dir}'".format(input_dir=temp_dir))
                        return public.returnMsg(False, "解压备份文件失败")

                    input_path_list.append(sql_file)
            del increment_backup

            shell = "'{mysql_bin}' --force --host='{db_host}' --port={db_port} --user={db_user} --password='{password}' '{db_name}'".format(
                mysql_bin=self._MYSQL_BIN,
                db_host=db_host,
                db_port=int(db_port),
                db_user=db_user,
                password=db_password,
                db_name=increment_setting["db_name"],
            )
            # 恢复数据库
            for path in input_path_list:
                public.ExecShell("{shell} < '{path}'".format(shell=shell, path=path), env={"MYSQL_PWD": db_password})

            public.ExecShell("rm -rf '{input_dir}'".format(input_dir=temp_dir))
            return public.returnMsg(True, "恢复成功！")
        except Exception as err:
            pass

    # 导出数据
    def export_time_database(self, get):
        try:
            pay = self.__check_auth()
            if pay is False:
                return public.returnMsg(False, "当前功能为企业版专享")

            if not hasattr(get, "cron_id"):
                return public.returnMsg(False, "缺少参数 cron_id!")
            if not hasattr(get, "node_time"):
                return public.returnMsg(False, "缺少参数 node_time!")

            cron_id = get.cron_id
            node_time = get.node_time

            node_time = datetime.datetime.strptime(node_time, "%Y-%m-%d %H:%M:%S")

            cron_info = public.M("crontab").where("id=? and sType='mysql_increment_backup'", (cron_id)).find()

            if not cron_info:
                return public.returnMsg(False, "增量备份定时任务不存在！")

            # 取备份配置信息
            increment_setting = public.M("mysql_increment_settings").where("cron_id=?", (cron_id)).find()
            if not increment_setting:
                return public.returnMsg(False, "增量备份配置不存在！")

            # 临时解压目录
            if not increment_setting["tb_name"]:
                temp_name = "export_db_{db_name}_{node_time}_mysql_increment_backup".format(db_name=increment_setting["db_name"], node_time=node_time.strftime("%Y-%m-%d_%H-%M-%S"))
            else:
                temp_name = "export_tb_{db_name}_{node_time}_mysql_increment_backup".format(db_name=increment_setting["db_name"], node_time=node_time.strftime("%Y-%m-%d_%H-%M-%S"))
            temp_dir = os.path.join(self._MYSQL_INCREMENT_BACKUP_DIR, increment_setting["db_name"], temp_name)

            if not os.path.isdir(temp_dir):
                os.makedirs(temp_dir)

            increment_backup = public.M("mysql_increment_backup").where("cron_id=?", (cron_id)).select()
            for info in increment_backup:
                add_time = datetime.datetime.strptime(info["addtime"], "%Y-%m-%d %H:%M:%S")
                if node_time >= add_time:
                    if info.get("localhost"):
                        if os.path.isfile(info.get("localhost")):  # 本地有存储
                            backup_path = info.get("localhost")
                        else:
                            return public.returnMsg(False, "检查到服务器备份文件丢失，请重新添加计划任务进行增量备份！")
                    else:  # 从云存储上拉取备份文件
                        public.ExecShell("rm -rf '{input_dir}'".format(input_dir=temp_dir))
                        return public.returnMsg(False, "暂不支持从云存储上恢复！")
                        # backup_path = ""

                    if not os.path.isfile(backup_path):
                        public.ExecShell("rm -rf '{input_dir}'".format(input_dir=temp_dir))
                        return public.returnMsg(False, "备份文件丢失")

                    # 解压
                    if increment_setting["zip_password"]:
                        public.ExecShell("unzip -P {zip_password} -o '{file}' -d '{input_dir}'".format(zip_password=increment_setting["zip_password"], file=backup_path, input_dir=temp_dir))
                    else:
                        public.ExecShell("unzip -o '{file}' -d '{input_dir}'".format(file=backup_path, input_dir=temp_dir))

                    file_name = ".".join(info["name"].split(".")[:-1]) + ".sql"
                    sql_file = os.path.join(temp_dir, file_name)
                    if not os.path.isfile(sql_file):
                        public.ExecShell("rm -rf '{input_dir}'".format(input_dir=temp_dir))
                        return public.returnMsg(False, "解压备份文件失败")

            is_zip, zip_file = self.zip_file(temp_dir)
            if is_zip is False:
                public.ExecShell("rm -rf '{input_dir}'".format(input_dir=temp_dir))
                return public.returnMsg(False, "导出错误!压缩文件失败!")
            if os.path.exists(temp_dir):
                public.ExecShell("rm -rf '{input_dir}'".format(input_dir=temp_dir))
                return public.returnMsg(False, "导出错误！压缩文件失败！")

            zip_file_info = {
                "name": os.path.basename(zip_file),
                "path": zip_file,
                "size": os.path.getsize(zip_file),
            }
            return {"status": True, "msg": "导出成功！", "data": zip_file_info}
        except Exception as err:
            pass

    def echo_start(self):
        print()
        print("-" * 76)
        print("★开始备份[{}]".format(public.format_date()))
        print("-" * 76)

    def echo_info(self, msg):
        print("|-{}".format(msg))

    def echo_error(self, msg):
        print("-" * 90)
        print("|-错误：{}".format(msg))
        if self._error_msg:
            self._error_msg += "\n"
        self._error_msg += msg

    # 执行计划任务
    def execute_by_comandline(self, get):
        """
            执行计划任务调用
        """
        self.echo_start()

        cron_info = public.M("crontab").where("echo=? and sType='mysql_increment_backup'", (get.echo_id)).find()

        # 检测是否开启二进制日志
        binlog_status = self.get_binlog_status()
        if binlog_status["status"] is False:
            error_msg = "请检查数据库是否正常运行或者请先开启二进制日志,否则可能导致备份的数据不完整！"
            self.echo_error(error_msg)
            self.send_failture_notification(cron_info, error_msg)
            return False, error_msg

        if not cron_info:
            error_msg = "增量备份定时任务不存在！"
            self.echo_error(error_msg)
            self.send_failture_notification(cron_info, error_msg, target="|database")
            return False, error_msg

        # 取备份配置信息
        increment_setting = public.M("mysql_increment_settings").field("cron_id,db_name,tb_name,zip_password,last_backup_time").where("cron_id=?", (cron_info["id"])).find()
        if not increment_setting:
            error_msg = "增量备份任务不存在！"
            self.echo_error(error_msg)
            self.send_failture_notification(cron_info, error_msg, target="|database")
            return False, error_msg

        cron_info.update(increment_setting)

        # 处理表数据
        cron_info["tb_list"] = None
        if not cron_info["tb_name"]:  # 全部表
            try:
                db_name = cron_info["db_name"].replace("`", "``")  # 防止 SQL 注入
                query_sql = "SHOW TABLES FROM `{db_name}`;".format(db_name=db_name)
                table_list = panelMysql().query(query_sql)

                # 检查查询结果
                if table_list is None or not isinstance(table_list, list):
                    raise Exception("未能获取有效的表！")

                # 生成表列表
                cron_info["tb_list"] = [table[0] for table in table_list]
            except Exception as e:
                error_msg = "查询数据库表失败：{}".format(e)
                self.echo_error(error_msg)
                self.send_failture_notification(cron_info, error_msg)
                return False, error_msg
        else:
            cron_info["tb_list"] = str(cron_info["tb_name"]).split(",")

        # 获取 Mysql 配置
        cron_info["db_host"] = "localhost"
        cron_info["db_user"] = "root"
        cron_info["db_password"] = public.M("config").where("id=?", (1,)).getField("mysql_root")
        if not cron_info["db_password"]:
            error_msg = "数据库密码为空！请先设置数据库密码！"
            self.echo_error(error_msg)
            return False, error_msg
        try:
            cron_info["db_port"] = panelMysql().query("show global variables like 'port'")[0][1]
        except:
            cron_info["db_port"] = 3306

        database = public.M("databases").where("name=? and LOWER(type)=LOWER(?)", (cron_info["db_name"], "mysql")).find()
        if not database:
            error_msg = "MySQL 备份数据库 {} 不存在".format(cron_info["db_name"])
            self.echo_error(error_msg)
            self.send_failture_notification(cron_info, error_msg)
            return False, error_msg

        if not cron_info["tb_name"]:
            cron_info["backup_type"] = "databases"
            cron_info["backup_file_dir"] = os.path.join(self._BINLOG_BACKUP_DIR, cron_info["db_name"], cron_info["backup_type"])
        else:
            cron_info["backup_type"] = "tables"
            if cron_info["tb_name"].find(",") == -1:
                cron_info["backup_file_dir"] = os.path.join(self._BINLOG_BACKUP_DIR, cron_info["db_name"], cron_info["backup_type"], cron_info["tb_name"])
            else:
                cron_info["backup_file_dir"] = os.path.join(self._BINLOG_BACKUP_DIR, cron_info["db_name"], cron_info["backup_type"], public.md5(cron_info["tb_name"]))

        if not os.path.exists(cron_info["backup_file_dir"]):
            os.makedirs(cron_info["backup_file_dir"])

        # 备份信息
        backup_data = {
            "cron_id": cron_info["cron_id"],
            "size": 0,
            "type": 0,
            "addtime": "",
            "name": "",
            "localhost": "",
            "ftp": "",
            "alioss": "",
            "txcos": "",
            "qiniu": "",
            "aws_s3": "",
            "upyun": "",
            "obs": "",
            "bos": "",
            "gcloud_storage": "",
            "gdrive": "",
            "msonedrive": "",
            "jdcloud": "",
            "tianyiyun":"",
            "webdav":"",
            "minio":"",
            "dogecloud":""
        }
        start_time = time.time()
        if not cron_info["last_backup_time"]:  # 全量备份
            status, error_msg = self.full_backup(cron_info, backup_data)
            if status is False:  # 备份失败
                self.send_failture_notification(cron_info, error_msg)
                return status, error_msg

            backup_data["type"] = 1
        else:
            current_time = datetime.datetime.now()
            # 全量备份是否为一个星期前
            full_backup_time = public.M("mysql_increment_backup").where("type=1 and cron_id=?", (cron_info["id"])).getField("addtime")
            try:
                date_obj = datetime.datetime.strptime(full_backup_time, "%Y-%m-%d %H:%M:%S") + datetime.timedelta(days=7)
            except:
                date_obj = current_time
            if date_obj <= current_time:
                self.echo_info("全量备份时间为七天之前：{}".format(full_backup_time))
                self.echo_info("开始重新进行全量备份")
                status, error_msg = self.full_backup(cron_info, backup_data)
                if status is False:  # 备份失败
                    self.send_failture_notification(cron_info, error_msg)
                    return status, error_msg

                backup_data["type"] = 1
            else:
                self._BACKUP_TIME=full_backup_time
                # 增量备份
                status, error_msg = self.inc_backup(cron_info, backup_data)
                if status is False:  # 备份失败
                    self.send_failture_notification(cron_info, error_msg)
                    return status, error_msg

                backup_data["type"] = 0

        if not error_msg:  # 导出数据为空
            return

        backup_path = error_msg

        # 压缩
        if os.path.getsize(backup_path) == 0:
            self.echo_info("备份完成，数据库无变动!")
            os.remove(backup_path)
            return True, ""

        is_zip, zip_file = self.zip_file(backup_path, cron_info["zip_password"])
        if is_zip is False:
            public.ExecShell("rm {}".format(backup_path))
            error_msg = "数据库全量备份失败，压缩文件失败!"
            self.echo_error(error_msg)
            self.send_failture_notification(cron_info, error_msg)
            return False, error_msg

        zip_size = os.path.getsize(zip_file)
        backup_data["size"] = zip_size
        backup_data["name"] = os.path.basename(zip_file)

        self.echo_info("备份完成，耗时{:.2f}秒，压缩包大小：{}".format(time.time() - start_time, public.to_size(zip_size)))
        self.echo_info("数据库已备份到：{}".format(zip_file))
        # 上传云存储
        cloud_list = cron_info["backupTo"].split("|")
        for cloud_name in cloud_list:
            if str(cloud_name).lower() == "localhost":
                backup_data[cloud_name] = zip_file
                continue
            if cloud_name in ["tianyiyun","webdav","minio","dogecloud"]:
                
                from CloudStoraUpload import CloudStoraUpload
                self._cloud_new = CloudStoraUpload()
                self._cloud = self._cloud_new.run(cloud_name)
                if self._cloud is False:
                    error_msg = "链接云存储失败，请检查配置是否正确！"
                    self.echo_info(error_msg)
                    self.send_failture_notification(cron_info, error_msg)
                    return False, error_msg

                self.echo_info("正在上传到{}，请稍候...".format(self._cloud_name[cloud_name]))
                upload_path = os.path.join(self._cloud_new.backup_path, "mysql_bin_log", cron_info["db_name"], cron_info["backup_type"], cron_info["tb_name"], os.path.basename(zip_file))
                if self._cloud.upload_file(zip_file, upload_path):                   
                    self.echo_info("已成功上传到{}".format(self._cloud_name[cloud_name]))
                    backup_data[cloud_name] = upload_path +'|' + cloud_name + '|' + os.path.basename(zip_file)
                else:
                    error_msg = "{}备份任务执行失败。".format(self._cloud_name[cloud_name])
                    self.echo_error(error_msg)

                    remark = "备份到" + cloud_name
                    self.send_failture_notification(cron_info, error_msg, remark=remark)
                    return False, error_msg
            else:
                from CloudStoraUpload import CloudStoraUpload
                self._cloud = CloudStoraUpload()
                self._cloud.run(cloud_name)

                if not self._cloud.obj:
                    error_msg = "链接云存储失败，请检查配置是否正确！"
                    self.echo_info(error_msg)
                    self.send_failture_notification(cron_info, error_msg)
                    return False, error_msg

                self.echo_info("正在上传到{}，请稍候...".format(self._cloud.obj._title))

                upload_path = os.path.join(self._cloud.obj.backup_path, "mysql_bin_log", cron_info["db_name"], cron_info["backup_type"], cron_info["tb_name"], os.path.basename(zip_file))
                if self._cloud.cloud_upload_file(zip_file, upload_path):
                    self.echo_info("已成功上传到{}".format(self._cloud.obj._title))
                    backup_data[cloud_name] = upload_path +'|' + cloud_name + '|' + os.path.basename(zip_file)

                else:
                    error_msg = "备份任务执行失败。"
                    if hasattr(self._cloud, "error_msg"):
                        if self._cloud.obj.error_msg:
                            error_msg = self._cloud.obj.error_msg
                    self.echo_error(error_msg)

                    remark = "备份到" + self._cloud.obj._title
                    self.send_failture_notification(cron_info, error_msg, remark=remark)
                    return False, error_msg

        # 本地不保留
        if cron_info["save_local"]==0 and not backup_data["localhost"]:
            os.remove(zip_file)
            self.echo_info("用户设置不保留本地备份，已删除：{}".format(zip_file))
        self.echo_info("最后备份时间：{}".format(backup_data["addtime"]))
        next_backuptime=datetime.datetime.strptime(self._BACKUP_TIME, "%Y-%m-%d %H:%M:%S") + datetime.timedelta(days=7)
        self.echo_info("下次全量备份时间：{}".format(next_backuptime))
        self.echo_info("温馨提示：全量备份是为了确保数据的一致性和完整性，通常每隔一段时间进行一次全量备份，以重置备份链并确保所有数据都得到完整备份。".format(next_backuptime))
        public.M("mysql_increment_settings").where("cron_id=?", (cron_info["id"])).setField("last_backup_time", backup_data["addtime"])
        public.M("mysql_increment_backup").insert(backup_data)

        return public.returnMsg(True, "备份成功！")

    # 数据库全量备份
    def full_backup(self, cron_info: dict, backup_data: dict) -> Tuple[bool, str]:
        """
            数据库全量备份
        """
        # 清理备份
        public.ExecShell("rm -rf {}/*".format(os.path.join(cron_info["backup_file_dir"])))
        public.M("mysql_increment_backup").where("cron_id=?", (cron_info["id"])).delete()

        self.echo_info("全量备份开始")
        # 二进制日志备份
        if not os.path.exists(self._MYSQLDUMP_BIN):
            error_msg = "数据库增量备份失败，请先安装 Mysql 数据库!"
            self.echo_error(error_msg)
            return False, error_msg

        mysql_obj = db_mysql.panelMysql().set_host(cron_info["db_host"], cron_info["db_port"], cron_info["db_name"], cron_info["db_user"], cron_info["db_password"])
        if isinstance(mysql_obj, bool):
            error_msg = "连接数据库[{}:{}]失败".format(cron_info["db_host"], cron_info["db_port"])
            self.echo_error(error_msg)
            return False, error_msg

        database_list = mysql_obj.query("show databases;")
        if not isinstance(database_list, list):
            error_msg = "MySQL数据库异常！请确保MySQL数据库正常并且是开启状态"
            self.echo_error(error_msg)
            return False, error_msg

        database_list = [db[0] for db in database_list if db[0] not in ["sys", "mysql", "information_schema", "performance_schema"]]
        if cron_info["db_name"] not in database_list:
            error_msg = "备份的数据库 {} 不存在！".format(cron_info["db_name"])
            self.echo_error(error_msg)
            return False, error_msg

        # 获取数据库大小
        db_size = 0
        if not cron_info["tb_name"]:  # 全部表
            db_data = mysql_obj.query("select sum(DATA_LENGTH)+sum(INDEX_LENGTH) from information_schema.tables where table_schema='{}'".format(cron_info["db_name"]))
            if isinstance(db_data, list) and len(db_data) != 0:
                if db_data[0][0]:
                    db_size = db_data[0][0]
        else:
            table_sql = "'" + "','".join(cron_info["tb_list"]) + "'"
            db_data = mysql_obj.query("select sum(DATA_LENGTH)+sum(INDEX_LENGTH) from information_schema.tables where table_schema='{}' and table_name in ({})".format(cron_info["db_name"], table_sql))
            if isinstance(db_data, list) and len(db_data) != 0:
                if db_data[0][0]:
                    db_size += db_data[0][0]
        if not db_size:
            error_msg = "数据库 `{}` 没有数据!".format(cron_info["db_name"])
            self.echo_error(error_msg)
            return False, error_msg

        # 检测磁盘空间
        disk_path, disk_free, disk_inode = backup().get_disk_free(self._BINLOG_BACKUP_DIR)
        self.echo_info("分区{}可用磁盘空间为：{}，可用Inode为：{}".format(disk_path, public.to_size(disk_free), disk_inode))
        if disk_path:
            if disk_free < db_size:
                error_msg = "目标分区可用的磁盘空间小于{},无法完成备份，请增加磁盘容量，或在设置页面更改默认备份目录!".format(public.to_size(db_size))
                self.echo_error(error_msg)
                return False, error_msg
            if disk_inode < self._INODE_MIN:
                error_msg = "目标分区可用的Inode小于{},无法完成备份，请增加磁盘容量，或在设置页面更改默认备份目录!".format(self._INODE_MIN)
                self.echo_error(error_msg)
                return False, error_msg

        db_charset = public.get_database_character(cron_info["db_name"])

        if not cron_info["tb_name"]:
            msg = "所有表"
        else:
            msg = cron_info["tb_name"]
        self.echo_info("备份MySQL数据库：{}-{}".format(cron_info["db_name"], msg))
        self.echo_info("数据库大小：{}".format(public.to_size(db_size)))
        self.echo_info("数据库字符集：{}".format(db_charset))

        if not cron_info["tb_name"]:  # 全部表
            table_shell = ""
            file_name = "full_db_{db_name}_{backup_time}_mysql_info.sql".format(db_name=cron_info["db_name"], backup_time=time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime()))
        else:
            tb_list = str(cron_info["tb_name"]).split(",")
            table_shell = "'" + "' '".join(tb_list) + "'"
            file_name = "full_tb_{db_name}_{backup_time}_mysql_info.sql".format(db_name=cron_info["db_name"], backup_time=time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime()))

        # 数据库全量备份
        full_backup_sql_file = os.path.join(cron_info["backup_file_dir"], file_name)

        shell = "'{mysqldump_bin}' --routines --events --skip-triggers --set-gtid-purged=OFF --default-character-set='{db_charset}' --force --hex-blob " \
                "--single-transaction --skip-lock-tables --quick --host='{db_host}' --port={db_port} --user={db_user} '{db_name}' {table_shell} > '{backup_path}'  2>/dev/null".format(
            mysqldump_bin=self._MYSQLDUMP_BIN,
            db_charset=db_charset,
            db_host=cron_info["db_host"],
            db_port=cron_info["db_port"],
            db_user=cron_info["db_user"],
            db_name=cron_info["db_name"],
            table_shell=table_shell,
            backup_path=full_backup_sql_file
        )
        backup_data["addtime"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self._BACKUP_TIME=backup_data["addtime"] 
        self.echo_info("开始备份：{}".format(backup_data["addtime"]))
        public.ExecShell(shell, env={"MYSQL_PWD": cron_info["db_password"]})

        if not os.path.exists(full_backup_sql_file):
            error_msg = "数据库全量备份失败，导出 sql 文件不存在!"
            self.echo_error(error_msg)
            return False, error_msg

        return True, full_backup_sql_file

    # 数据库增量备份
    def inc_backup(self, cron_info: dict, backup_data: dict) -> Tuple[bool, str]:
        self.echo_info("增量备份开始")

        # 二进制日志备份
        if not os.path.exists(self._MYSQLBINLOG_BIN):
            error_msg = "数据库增量备份失败，请先安装 Mysql 数据库!"
            self.echo_error(error_msg)
            return False, error_msg

        mysql_obj = db_mysql.panelMysql().set_host(cron_info["db_host"], cron_info["db_port"], cron_info["db_name"], cron_info["db_user"], cron_info["db_password"])
        if isinstance(mysql_obj, bool):
            error_msg = "连接数据库[{}:{}]失败".format(cron_info["db_host"], cron_info["db_port"])
            self.echo_error(error_msg)
            return False, error_msg

        database_list = mysql_obj.query("show databases;")
        if not isinstance(database_list, list):
            error_msg = "MySQL数据库异常！请确保MySQL数据库正常并且是开启状态"
            self.echo_error(error_msg)
            return False, error_msg

        database_list = [db[0] for db in database_list if db[0] not in ["sys", "mysql", "information_schema", "performance_schema"]]
        if cron_info["db_name"] not in database_list:
            error_msg = "备份的数据库 {} 不存在！".format(cron_info["db_name"])
            self.echo_error(error_msg)
            return False, error_msg

        # 获取数据库大小
        db_size = 0
        if not cron_info["tb_name"]:  # 全部表
            db_data = mysql_obj.query("select sum(DATA_LENGTH)+sum(INDEX_LENGTH) from information_schema.tables where table_schema='{}'".format(cron_info["db_name"]))
            if isinstance(db_data, list) and len(db_data) != 0:
                if db_data[0][0]:
                    db_size = db_data[0][0]
        else:
            table_sql = "'" + "','".join(cron_info["tb_list"]) + "'"
            db_data = mysql_obj.query("select sum(DATA_LENGTH)+sum(INDEX_LENGTH) from information_schema.tables where table_schema='{}' and table_name in ({})".format(cron_info["db_name"], table_sql))
            if isinstance(db_data, list) and len(db_data) != 0:
                if db_data[0][0]:
                    db_size += db_data[0][0]
        if not db_size:
            error_msg = "数据库 `{}` 没有数据!".format(cron_info["db_name"])
            self.echo_error(error_msg)
            return False, error_msg

        # 检测磁盘空间
        disk_path, disk_free, disk_inode = backup().get_disk_free(self._BINLOG_BACKUP_DIR)
        self.echo_info("分区{}可用磁盘空间为：{}，可用Inode为：{}".format(disk_path, public.to_size(disk_free), disk_inode))
        if disk_path:
            if disk_free < db_size:
                error_msg = "目标分区可用的磁盘空间小于{},无法完成备份，请增加磁盘容量，或在设置页面更改默认备份目录!".format(public.to_size(db_size))
                self.echo_error(error_msg)
                return False, error_msg
            if disk_inode < self._INODE_MIN:
                error_msg = "目标分区可用的Inode小于{},无法完成备份，请增加磁盘容量，或在设置页面更改默认备份目录!".format(self._INODE_MIN)
                self.echo_error(error_msg)
                return False, error_msg

        # 每天一个文件夹
        backup_binlog_file_dir = os.path.join(cron_info["backup_file_dir"], str(time.strftime("%Y-%m-%d", time.localtime())))
        if not os.path.exists(backup_binlog_file_dir):
            os.makedirs(backup_binlog_file_dir)

        if not cron_info["tb_name"]:
            msg = "所有表"
        else:
            msg = cron_info["tb_name"]
        self.echo_info("备份MySQL数据库：{}-{}".format(cron_info["db_name"], msg))

        # 获取所有binlog 日志列表
        binlog_list = self.get_binlog_list()
        if len(binlog_list) == 0:
            error_msg = "数据库增量备份失败，binlog 日志缺失！"
            self.echo_error(error_msg)
            return False, error_msg
        bin_log_shell = "'" + "' '".join(binlog_list) + "'"

        temp_binlog_sql_file = os.path.join(cron_info["backup_file_dir"], "temp_binlog_sql_{current_time}.sql".format(current_time=int(time.time() * 1000_000)))
        inc_backup_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        shell = "'{mysqlbinlog_bin}' --base64-output=decode-rows --open-files-limit=1024 --start-datetime='{start_time}' --stop-datetime='{end_time}' --database='{db_name}' {bin_log} | perl -0777 -pe 's/\n?\/\*!\*\///gs' > {binlog_file_path}".format(
            mysqlbinlog_bin=self._MYSQLBINLOG_BIN,
            start_time=cron_info["last_backup_time"],
            end_time=inc_backup_time,
            db_name=cron_info["db_name"],
            bin_log=bin_log_shell,
            binlog_file_path=temp_binlog_sql_file,
        )
        backup_data["addtime"] = inc_backup_time

        self.echo_info("开始备份：{}".format(backup_data["addtime"]))
        self.echo_info("备份时间：{} ~ {}".format(cron_info["last_backup_time"], inc_backup_time))
        public.ExecShell(shell)

        if not cron_info["tb_name"]:  # 全部表
            file_name = "inc_{db_name}_db_{backup_time}_mysql_info.sql".format(db_name=cron_info["db_name"], backup_time=time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime()))
        else:
            file_name = "inc_{db_name}_tb_{backup_time}_mysql_info.sql".format(db_name=cron_info["db_name"], backup_time=time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime()))
        # 数据库增量备份
        inc_backup_sql_file = os.path.join(backup_binlog_file_dir, file_name)

        dump_file_obj = open(inc_backup_sql_file, "a+", encoding="utf-8")
        dump_file_obj.write("-- 宝塔面板")
        dump_file_obj.write("\n-- Host      : {}".format(public.GetLocalIp()))
        dump_file_obj.write("\n-- Database  : {}".format(cron_info["db_name"]))
        dump_file_obj.write("\n-- Table     : {}".format(cron_info["tb_name"] if cron_info["tb_name"] else "所有"))
        dump_file_obj.write("\n-- Date      : {}".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        dump_file_obj.write("\n-- StartTime : {}".format(cron_info["last_backup_time"]))
        dump_file_obj.write("\n-- EndTime   : {}".format(inc_backup_time))

        self.__new_binlog_inc_sql(temp_binlog_sql_file, dump_file_obj, cron_info)

        if not os.path.exists(inc_backup_sql_file):
            error_msg = "数据库增量备份失败，导出 sql 文件失败!"
            self.echo_error(error_msg)
            return False, error_msg

        return True, inc_backup_sql_file

    @classmethod
    def __new_binlog_inc_sql(cls, temp_binlog_sql_file: str, dump_file_obj, cron_info: dict):
        try:
            try:
                fp = open(temp_binlog_sql_file, "r")
            except Exception as ex:
                if sys.version_info[0] != 2:
                    try:
                        fp = open(temp_binlog_sql_file, "r", encoding="utf-8", errors='ignore')
                    except:
                        fp = open(temp_binlog_sql_file, "r", encoding="GBK", errors='ignore')
                else:
                    return
            read_size_max = 4096
            fp.seek(0, os.SEEK_END)
            end_pos = fp.tell()
            fp.seek(0, os.SEEK_SET)

            content = ""
            while end_pos > 0:
                read_size = min(end_pos, read_size_max)
                end_pos -= read_size
                try:
                    content += fp.read(read_size)
                except Exception as err:
                    break
                if content.find("\n# at") != -1:
                    content_list = content.split("\n# at")
                    if end_pos > 0:
                        content = "\n# at" + content_list.pop()
                    for item in content_list:
                        if not item: continue

                        sql_info = cls.__analysis_binlog_sql(item, cron_info)

                        if sql_info is None:
                            continue

                        dump_file_obj.write("\n")
                        dump_file_obj.write("\n-- {} server id {} start_log_pos {} end_log_pos {}".format(sql_info["timestamp"], sql_info["server_id"], sql_info["start_log_pos"], sql_info["end_log_pos"]))
                        if sql_info.get("comment") is not None:
                            dump_file_obj.write("\n-- {}\n".format(sql_info["comment"]))
                        dump_file_obj.write(sql_info["sql"])
            fp.close()
        except:
            pass

        if os.path.exists(temp_binlog_sql_file):
            os.remove(temp_binlog_sql_file)

    @classmethod
    def __analysis_binlog_sql(cls, item_content: str, cron_info: dict):
        sql_obj = None
        for re_sql in cls._NEW__DATA_SQL_TYPE.values():
            if not cron_info["tb_name"]:  # 全部表
                sql_obj = re.search(re_sql.format(tb_name=".*"), item_content, flags=re.IGNORECASE)
            else:
                for tb_name in cron_info["tb_list"]:
                    sql_obj = re.search(re_sql.format(tb_name=tb_name), item_content, flags=re.IGNORECASE)
                    if sql_obj:
                        break
            if sql_obj:
                break
        else:
            return None

        if sql_obj is None:
            return None

        sql_info = {
            "sql": sql_obj.group(0),
        }

        info_obj = re.search("^\s+(\d+)\n", item_content)
        if info_obj:
            sql_info["start_log_pos"] = info_obj.group(1)  # 起始位置

        info_obj = re.search(
            r"#\s*(\d{6}\s\d{2}:\d{2}:\d{2})\s+server\s+id\s+(\d+)\s+end_log_pos\s+(\d+)\s+(\w+)",
            item_content, flags=re.IGNORECASE | re.MULTILINE | re.DOTALL
        )
        if info_obj:
            sql_info["comment"] = info_obj.group(0).strip()  # 全部
            sql_info["date_time"] = info_obj.group(1)  # 时间
            sql_info["server_id"] = int(info_obj.group(2))  # server id
            sql_info["end_log_pos"] = info_obj.group(3)  # end_log_pos
            sql_info["event_type"] = info_obj.group(4)  # 事件类型 Query、Xid

            # 其他参数
            args_dict = {
                "thread_id": "thread_id=(\d+)",  # 线程 id thread_id
                "exec_time": "exec_time=(\d+)",  # 事件执行时间 exec_time
                "error_code": "error_code=(\d+)",  # 事件错误代码 error_code
                "xid": "Xid\s*=\s*(\d+)",  # 事件错误代码 error_code
            }
            for name, re_str in args_dict.items():
                temp_obj = re.search(re_str, info_obj.group(0))
                if temp_obj:
                    sql_info[name] = temp_obj.group(1)

        info_obj = re.search("\nSET\s+TIMESTAMP=(\d+);\n", item_content)
        if info_obj:
            sql_info["set_timestamp"] = info_obj.group(0)
            sql_info["timestamp"] = datetime.datetime.fromtimestamp(int(info_obj.group(1))).strftime("%Y-%m-%d %H:%M:%S")  # 事件错误代码 error_code

        return sql_info

    # 压缩文件
    @classmethod
    def zip_file(cls, await_zip: str, password: str = None) -> Tuple[bool, str]:
        try:
            if os.path.isfile(await_zip):
                zip_file = ".".join(await_zip.split(".")[:-1]) + ".zip"
            else:
                zip_file = await_zip + ".zip"
            zip_dir = os.path.dirname(await_zip)
            file_name = os.path.basename(await_zip)
            if password:  # 压缩密码
                public.ExecShell("cd '{zip_dir}' && zip -mP '{password}' '{zip_file}' -r '{file_name}'".format(zip_dir=zip_dir, password=password, zip_file=zip_file, file_name=file_name))
            else:
                public.ExecShell("cd '{zip_dir}' && zip -m '{zip_file}' -r '{file_name}'".format(zip_dir=zip_dir, zip_file=zip_file, file_name=file_name))

            if not os.path.exists(zip_file):
                return False, ""
            return True, zip_file
        except Exception as err:
            print(f"err:{err}")

    # 获取 binlog 文件列表
    @classmethod
    def get_binlog_list(cls) -> list:
        bin_log = []
        mysql_conf = public.readFile(cls._MYSQL_CNF)

        mysql_cnf_obj = re.search("\ndatadir\s*=\s*(.+)\n", mysql_conf)
        if not mysql_cnf_obj:
            return bin_log
        data_dir = mysql_cnf_obj.group(1)

        mysql_bin_index = os.path.join(data_dir, "mysql-bin.index")
        binlog_text = public.readFile(mysql_bin_index)

        for item in binlog_text.split('\n'):
            log_file = item.strip()
            log_name = log_file.lstrip("./")
            if not log_file: continue  # 空行
            bin_log_path = os.path.join(data_dir, log_name)
            if not os.path.isfile(bin_log_path): continue
            bin_log.append(bin_log_path)
        return bin_log

    # 备份失败发送消息通知
    def send_failture_notification(self, cron_info: dict, error_msg, target=None, remark=""):
        """
        @name 备份失败发送消息通知
        @param error_msg 错误信息
        :remark 备注
        """
        cron_title = cron_info["name"]
        notice = cron_info["notice"]
        notice_channel = cron_info["notice_channel"]
        if target is None:
            target = "{}|database".format("-".join([cron_info.get("db_name"), cron_info.get("tb_name")]))
        backup_obj = backup()

        backup_obj.save_backup_status(False, target, msg=error_msg)
        if notice == 0 or not notice_channel:
            return

        if notice == 1 or notice == 2:
            title = backup_obj.generate_failture_title(cron_title)
            task_name = cron_title
            msg = backup_obj.generate_failture_notice(task_name, error_msg, remark)
            res = backup_obj.send_notification(notice_channel, title, msg,cron_info=cron_info)
            if res:
                self.echo_info("消息通知已发送。")
