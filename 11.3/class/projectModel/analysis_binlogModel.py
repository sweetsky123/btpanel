# coding: utf-8
# -------------------------------------------------------------------
# 宝塔Linux面板
# -------------------------------------------------------------------
# Copyright (c) 2015-2099 宝塔软件(http:#bt.cn) All rights reserved.
# -------------------------------------------------------------------
# Author: 王佳函
# -------------------------------------------------------------------

# ------------------------------
# MySQL二进制日志分析
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

class main(projectBase):
    _MYSQLBINLOG_BIN = os.path.join(public.get_setup_path(), "mysql/bin/mysqlbinlog")

    _BINLOG_ANALYSIS_DIR = os.path.join(public.get_setup_path(), "binlog_analysis")

    _SQL_TYPE = {
        "insert": r"INSERT\s+INTO\s+(['\"`.,\w]*{tb_name}['\"`]*)\s+{search_content_re};", # 插入语句
        "update": r"UPDATE\s+(['\"`.,\w]*{tb_name}['\"`]*)\s+SET{search_content_re};", # 更新语句
        "delete": r"DELETE\s+FROM\s+(['\"`.,\w]*{tb_name}['\"`]*)\s*{search_content_re};", # 删除语句
        "truncate_table": r"TRUNCATE\s+TABLE\s+(['\"`.,\w\s]*{tb_name}['\"`.,\w\s]*);", # 清除表数据语句
        "create_database": r"CREATE\s+DATABASE\s+(['\"`\w\W]*)\s*{search_content_re};", # 创建数据库语句
        "create_table": r"CREATE\s+TABLE\s+(['\"`.,\w]*{tb_name}['\"`]*)\s*{search_content_re};", # 创建表语句
        "create_index": r"CREATE\s+INDEX\s+(['`\"\w\W]+)\s+ON\s+(['\"`.,\w]*{tb_name}['\"`]*)\s+{search_content_re};", # 创建索引
        "alter_table": r"ALTER\s+TABLE\s+(['\"`.,\w]*{tb_name}['\"`]*)\s+{search_content_re};", # 修改表语句
        "drop_database": r"DROP\s+DATABASE\s+(['\"`\w\W]*);", # 删除数据库
        "drop_table": r"DROP\s+TABLE\s+(['\"`.,\w\s]*{tb_name}['\"`\s]*)+;", # 删除表
        "drop_index": r"DROP\s+INDEX\s+(['`\"\w\W]+)\s+ON\s+(['\"`.,\w]*{tb_name}['\"`]*);", # 删除索引
        "rename_table": r"RENAME\s+TABLE\s+(['\"`.,\w]*{tb_name}['\"`]*\s+TO\s+['\"`.,\w]*|['\"`.,\w]*\s+TO\s+['\"`.,\w]*{tb_name}['\"`]*);", # 重命名表
    }
    _SQL_TYPE_MSG = {
        "insert": "插入语句",
        "update": "更新语句",
        "delete": "删除语句",
        "truncate_table": "清除表数据语句",
        "create_database": "创建数据库语句",
        "create_table": "创建表语句",
        "create_index": "创建索引",
        "alter_table": "修改表语句",
        "drop_database": "删除数据库",
        "drop_table": "删除表",
        "drop_index": "删除索引",
        "rename_table": "重命名表语句",
    }

    _SQL_TYPE_LIST = [
        {
            "name": "全部",
            "value": "all",
            "desc": "全部语句",
        },
        {
            "name": "INSERT INTO",
            "value": "insert",
            "desc": "插入语句",
        },
        {
            "name": "UPDATE",
            "value": "update",
            "desc": "更新语句",
        },
        {
            "name": "DELETE FROM",
            "value": "delete",
            "desc": "删除语句",
        },
        {
            "name": "TRUNCATE TABLE",
            "value": "truncate_table",
            "desc": "清除表数据语句",
        },
        {
            "name": "CREATE DATABASE",
            "value": "create_database",
            "desc": "创建数据库语句",
        },
        {
            "name": "CREATE TABLE",
            "value": "create_table",
            "desc": "创建表语句",
        },
        {
            "name": "CREATE INDEX",
            "value": "create_index",
            "desc": "创建索引",
        },
        {
            "name": "ALTER TABLE",
            "value": "alter_table",
            "desc": "修改表语句",
        },
        {
            "name": "DROP DATABASE",
            "value": "drop_database",
            "desc": "删除数据库",
        },
        {
            "name": "DROP TABLE",
            "value": "drop_table",
            "desc": "删除表",
        },
        {
            "name": "DROP INDEX",
            "value": "drop_index",
            "desc": "删除索引",
        },
        {
            "name": "RENAME TABLE",
            "value": "rename_table",
            "desc": "重命名表语句",
        },
    ]
    def __init__(self):
        if not os.path.exists(self._BINLOG_ANALYSIS_DIR):
            os.makedirs(self._BINLOG_ANALYSIS_DIR)

    # 获取binlog 日志
    @classmethod
    def __get_binlog(cls) -> Tuple[list, int]:
        bin_log_size = 0
        bin_log = []
        myfile = '/etc/my.cnf'
        mycnf = public.readFile(myfile)
        try:
            data_dir = re.search("datadir\s*=\s*(.+)\n", mycnf).groups()[0]
        except:
            data_dir = "/www/server/data"
        index_file = os.path.join(data_dir, "mysql-bin.index")
        if not os.path.exists(index_file):
            return bin_log, bin_log_size

        text = public.readFile(index_file)
        for item in text.split('\n'):
            log_file = item.strip()
            log_name = log_file.lstrip("./")
            if not log_file: continue  # 空行
            bin_log_path = os.path.join(data_dir, log_name)
            if not os.path.isfile(bin_log_path): continue
            st = os.stat(bin_log_path)
            bin_log.append({
                "name": log_name,
                "path": bin_log_path,
                "size": st.st_size,
            })
            bin_log_size += st.st_size
        return bin_log, bin_log_size

    # 获取可解析最早日期
    def get_search_condition(self, get):
        # 获取最早时间
        bin_log, size = self.__get_binlog()
        if not bin_log:
            return public.returnMsg(False, "暂无可解析的 binlog 日志！")

        current_time = datetime.datetime.now()
        first_time = None
        for bin_log_info in bin_log:
            shell = "'{mysqlbinlog_bin}' '{bin_log}' | grep -m 1 'SET TIMESTAMP'".format(
                mysqlbinlog_bin=self._MYSQLBINLOG_BIN,
                bin_log=bin_log_info["path"],
            )
            first_time_str = public.ExecShell(shell)[0]
            time_obj = re.search("SET\s*TIMESTAMP=(\d+)", first_time_str)
            if time_obj:
                first_time = datetime.datetime.fromtimestamp(int(time_obj.group(1)))
                break

        # 获取数据库
        database_list = public.M("databases").field("name").where("sid=0 and LOWER(type)=LOWER(?)", ("mysql")).select()
        for database in database_list:
            database["value"] = database["name"]

            table_list = panelMysql().query("show tables from `{db_name}`;".format(db_name=database["name"]))
            if not isinstance(table_list, list):
                continue
            database["table_list"] = [{"name": "所有", "value": "all"}]
            for tb_name in table_list:
                database["table_list"].append({"name": tb_name[0], "value": tb_name[0]})

        if first_time is None:
            first_time = current_time

        if first_time < current_time - datetime.timedelta(hours=1):
            start_time = current_time - datetime.timedelta(hours=1)
        else:
            start_time = first_time

        data = {
            "start_time": start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "first_time": first_time.strftime("%Y-%m-%d %H:%M:%S"),
            "database": database_list,
            "sql_type": self._SQL_TYPE_LIST,
        }
        return {"status": True, "msg": "ok", "data": data}


    # 解析 binlog 日志
    @classmethod
    def __analysis_binlog_sql(cls, item_content: str, tb_list: list, sql_type_list: list, search_content: str):
        try:
            if search_content is not None:
                search_content_re = "([\n\w\W]*{search_content}[\n\w\W]*)".format(search_content=search_content)
            else:
                search_content_re = "[\n\w\W]+"

            sql_obj = None
            sql_type_msg = None
            for sql_type in sql_type_list:
                re_sql = cls._SQL_TYPE.get(sql_type)
                if re_sql is None: continue
                sql_type_msg = cls._SQL_TYPE_MSG.get(sql_type)

                for tb_name in tb_list:
                    if tb_name == "all":
                        tb_name = "(.+)"
                    sql_obj = re.search(re_sql.format(tb_name=tb_name, search_content_re=search_content_re), item_content, flags=re.IGNORECASE)
                    if sql_obj:
                        break
                if sql_obj:
                    break
            else:
                return None

            if sql_obj is None:
                return None

            sql_data = {
                "sql": sql_obj.group(0),
                "sql_type": sql_type_msg,
            }

            info_obj = re.search("^\s+(\d+)\n", item_content)
            if info_obj:
                sql_data["start_log_pos"] = info_obj.group(1)  # 起始位置

            info_obj = re.search("\n#([\d\s:]+)\s+server\s+id\s+(\d+)\s+end_log_pos\s+(\d+)\s+(\w+)\s+(\w+)\s+(\w+).*\n", item_content)
            if info_obj:
                sql_data["comment"] = info_obj.group(0)  # 全部
                sql_data["date_time"] = info_obj.group(1)  # 时间
                sql_data["server_id"] = int(info_obj.group(2))  # server id
                sql_data["end_log_pos"] = info_obj.group(3)  # end_log_pos
                sql_data["CRC32"] = info_obj.group(4)  # 校验算法(循环冗余校验) CRC32
                sql_data["CRC32_value"] = info_obj.group(5)  # 校验值 0x2483112d
                sql_data["event_type"] = info_obj.group(6)  # 事件类型 Query、Xid

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
                        sql_data[name] = temp_obj.group(1)

            info_obj = re.search("\nSET\s+TIMESTAMP=(\d+);\n", item_content)
            if info_obj:
                sql_data["set_timestamp"] = info_obj.group(0)
                sql_data["timestamp"] = datetime.datetime.fromtimestamp(int(info_obj.group(1))).strftime("%Y-%m-%d %H:%M:%S")  # 事件错误代码 error_code
            return sql_data
        except Exception as err:
            return None

    # 解析 binlog 日志
    @classmethod
    def __analysis_binlog(cls,
                          temp_analysis_file: str,
                          tb_list: list,
                          sql_type_list: list,
                          search_content: str,
                          dump_file_obj=None,
                          get=None,
                          ):
        try:
            fp = open(temp_analysis_file, "r")
        except Exception as ex:
            if sys.version_info[0] != 2:
                try:
                    fp = open(temp_analysis_file, "r",encoding="utf-8",errors='ignore')
                except:
                    fp = open(temp_analysis_file, "r",encoding="GBK",errors='ignore')
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
                    sql_info = cls.__analysis_binlog_sql(
                        item_content=item,
                        tb_list=tb_list,
                        sql_type_list=sql_type_list,
                        search_content=search_content,
                    )
                    if sql_info is None:
                        continue
                    if dump_file_obj is not None:
                        dump_file_obj.write("\n")
                        dump_file_obj.write("\n-- {} server-id = {} start_log_pos = {}  end_log_pos = {}\n".format(sql_info["timestamp"], sql_info["server_id"], sql_info["start_log_pos"], sql_info["end_log_pos"]))
                        dump_file_obj.write(sql_info["sql"])
                    else:
                        if hasattr(get, "_ws"):
                            sql_info["sql"] = public.html_encode(sql_info["sql"])
                            get._ws.send(public.getJson(sql_info))
        fp.close()

    # 解析 binlog 日志
    def analysis_binlog(self, get):
        db_list = getattr(get, "db_list", "[]")
        tb_list = getattr(get, "tb_list", "['all']")
        start_time = getattr(get, "start_time", None)
        end_time = getattr(get, "end_time", None)
        sql_type_list = getattr(get, "sql_type_list", "[]")
        search_content = getattr(get, "search_content", None)

        if sql_type_list[0] == "all":
            sql_type_list = self._SQL_TYPE.keys()
        start_time_obj = datetime.datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        end_time_obj = datetime.datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")

        bin_log, size = self.__get_binlog()
        if not bin_log:
            return public.returnMsg(False, "暂无可解析的 binlog 日志！")


        for db_name in db_list:
            temp_name = "temp_{db_name}_{start_time}_{end_time}_{analysis_time}.sql".format(
                db_name=db_name,
                start_time=start_time_obj.strftime("%Y-%m-%d_%H:%M:%S"),
                end_time=end_time_obj.strftime("%Y-%m-%d_%H:%M:%S"),
                analysis_time=int(time.time() * 1000_000),
            )
            temp_analysis_file = os.path.join(self._BINLOG_ANALYSIS_DIR, temp_name)
            if not os.path.exists(temp_analysis_file):
                binlog_list = [info["path"] for info in bin_log]
                db_name_shell = "--database='{db_name}'".format(db_name=db_name)

                bin_log_shell = "'" + "' '".join(binlog_list) + "'"

                shell = "'{mysqlbinlog_bin}' --base64-output=decode-rows --open-files-limit=1024 --start-datetime='{start_time}' --stop-datetime='{end_time}' {db_name_shell} {bin_log} | perl -0777 -pe 's/\n?\/\*!\*\///gs' > {result_file}".format(
                    mysqlbinlog_bin=self._MYSQLBINLOG_BIN,
                    start_time=start_time,
                    end_time=end_time,
                    db_name_shell=db_name_shell,
                    bin_log=bin_log_shell,
                    result_file=temp_analysis_file,
                )
                public.ExecShell(shell)

            self.__analysis_binlog(
                temp_analysis_file=temp_analysis_file,
                tb_list=tb_list,
                sql_type_list=sql_type_list,
                search_content=search_content,
                get=get,
            )
            os.remove(temp_analysis_file)
        public.set_module_logs("analysis_binlog", "analysis_binlog", 1)
        return True

    # 导出解析 binlog 日志
    def analysis_binlog_dump(self, get):
        db_list = getattr(get, "db_list", "[]")
        tb_list = getattr(get, "tb_list", "['all']")
        start_time = getattr(get, "start_time", None)
        end_time = getattr(get, "end_time", None)
        sql_type_list = getattr(get, "sql_type_list", "[]")
        search_content = getattr(get, "search_content", None)
        # 导出
        dump_dir = getattr(get, "dump_dir", None)

        db_list = json.loads(db_list)
        tb_list = json.loads(tb_list)
        sql_type_list = json.loads(sql_type_list)

        if sql_type_list[0] == "all":
            sql_type_list = self._SQL_TYPE.keys()
        start_time_obj = datetime.datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        end_time_obj = datetime.datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")

        bin_log, size = self.__get_binlog()
        if not bin_log:
            return public.returnMsg(False, "暂无可解析的 binlog 日志！")

        dump_file_list = []
        if dump_dir is not None and not os.path.exists(dump_dir):
            os.makedirs(dump_dir)

        for db_name in db_list:
            temp_name = "temp_{db_name}_{start_time}_{end_time}_{analysis_time}.sql".format(
                db_name=db_name,
                start_time=start_time_obj.strftime("%Y-%m-%d_%H:%M:%S"),
                end_time=end_time_obj.strftime("%Y-%m-%d_%H:%M:%S"),
                analysis_time=int(time.time() * 1000_000),
            )
            temp_analysis_file = os.path.join(self._BINLOG_ANALYSIS_DIR, temp_name)
            if not os.path.exists(temp_analysis_file):
                binlog_list = [info["path"] for info in bin_log]
                db_name_shell = "--database='{db_name}'".format(db_name=db_name)

                bin_log_shell = "'" + "' '".join(binlog_list) + "'"

                shell = "'{mysqlbinlog_bin}' --base64-output=decode-rows --open-files-limit=1024 --start-datetime='{start_time}' --stop-datetime='{end_time}' {db_name_shell} {bin_log} | perl -0777 -pe 's/\n?\/\*!\*\///gs' > {result_file}".format(
                    mysqlbinlog_bin=self._MYSQLBINLOG_BIN,
                    start_time=start_time,
                    end_time=end_time,
                    db_name_shell=db_name_shell,
                    bin_log=bin_log_shell,
                    result_file=temp_analysis_file,
                )
                public.ExecShell(shell)

            dump_file_obj = None
            dump_file_name = None
            dump_file = None
            if dump_dir is not None:
                dump_file_name = "{db_name}_binlog_dump.sql".format(db_name=db_name)
                dump_file = os.path.join(dump_dir, dump_file_name)
                idx = 1
                while os.path.isfile(dump_file):
                    dump_file_name = "{db_name}_binlog_dump({idx}).sql".format(db_name=db_name,idx=idx)
                    dump_file = os.path.join(dump_dir, dump_file_name)
                    idx += 1

                dump_file_obj = open(dump_file, "a+", encoding="utf-8")
                dump_file_obj.write("-- 宝塔面板")
                dump_file_obj.write("\n-- Host     : {}".format(public.GetLocalIp()))
                dump_file_obj.write("\n-- Database : {}".format(db_name))
                dump_file_obj.write("\n-- Date     : {}".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            self.__analysis_binlog(
                temp_analysis_file=temp_analysis_file,
                tb_list=tb_list,
                sql_type_list=sql_type_list,
                search_content=search_content,
                dump_file_obj=dump_file_obj,
                get=get,
            )
            if dump_file_obj is not None:
                dump_file_obj.close()
                dump_info = {
                    "name": dump_file_name,
                    "path": dump_file,
                    "size": os.path.getsize(dump_file)
                }
                dump_file_list.append(dump_info)
            os.remove(temp_analysis_file)
        public.set_module_logs("analysis_binlog", "analysis_binlog_dump", 1)
        return {"status": True, "msg": "导出成功！", "data": dump_file_list}
