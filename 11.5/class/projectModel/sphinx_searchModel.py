# coding: utf-8
# -------------------------------------------------------------------
# 宝塔Linux面板
# -------------------------------------------------------------------
# Copyright (c) 2015-2099 宝塔软件(http:#bt.cn) All rights reserved.
# -------------------------------------------------------------------
# Author: 王佳函
# -------------------------------------------------------------------

# ------------------------------
# MySQL 全文检索
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
import db_mysql
from panelMysql import panelMysql

class main(projectBase):
    __SPHINX_INDEXER_BIN = os.path.join(public.get_setup_path(), "sphinx/bin/indexer")
    __SPHINX_SEARCHD_BIN = os.path.join(public.get_setup_path(), "sphinx/bin/searchd")

    __BASE_DIR = os.path.join(public.get_setup_path(), "sphinx_search")
    __CONFIG_DIR = os.path.join(__BASE_DIR, "conf")
    __DATA_DIR = os.path.join(__BASE_DIR, "data")
    __INDEX_LIST_PATH = os.path.join(__BASE_DIR, "index_list.json")

    _CONF_TEXT = """#
# Minimal Sphinx configuration sample (clean, simple, functional)
#

common
{
    datadir     = %s # just for clarity, this is the default
}

# 主源
source db_source
{
    type        = mysql

    sql_host    = %s
    sql_user    = %s
    sql_pass    = %s
    sql_db      = %s
    sql_port    = %s
    sql_query   = %s
}

# 增量源
source db_source_increment: db_source
{
    type        = mysql

    sql_host    = %s
    sql_user    = %s
    sql_pass    = %s
    sql_db      = %s
    sql_port    = %s
    sql_query   = %s
}

index %s
{
    type        = plain
    source      = db_source

    ngram_len               = 1
	ngram_chars             = U+3000..U+2FA1F
}

# 增量索引
index %s_increment : %s

{
    type        = plain
    source      = db_source_increment
    ngram_len               = 1
	ngram_chars             = U+3000..U+2FA1F

}

indexer
{
	mem_limit		= 128M
}


searchd
{
	listen			= %s
	read_timeout		= 5
	max_children		= 30
	seamless_rotate		= 1
	preopen_indexes		= 1
	unlink_old		= 1
	workers			= threads # for RT to work
}
"""

    def __init__(self):
        if not os.path.exists(self.__CONFIG_DIR):
            os.makedirs(self.__CONFIG_DIR)
        if not os.path.exists(self.__DATA_DIR):
            os.makedirs(self.__DATA_DIR)

        if not os.path.exists(self.__INDEX_LIST_PATH):
            public.writeFile(self.__INDEX_LIST_PATH, "{}")

    # 检查插件
    @classmethod
    def __check_plugin(cls) -> Union[bool, str]:
        if not os.path.exists(cls.__SPHINX_INDEXER_BIN) or not os.path.exists(cls.__SPHINX_SEARCHD_BIN):
            return False, "请先安装 sphinx !"

        resp = public.ExecShell("btpip list | grep sphinxapi-py3")[0]
        if resp.find("sphinxapi-py3") == -1:
            public.ExecShell("btpip install sphinxapi-py3==2.1.11")
            resp = public.ExecShell("btpip list | grep sphinxapi-py3")[0]
            if resp.find("sphinxapi-py3") == -1:
                return False, "安装 sphinxapi-py3 失败！请手动安装: btpip install sphinxapi-py3==2.1.11"
        return True, ""

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
    def __check_port(cls, port):
        '''
        @name 检查端口是否被占用
        @args port:端口号
        @return: 被占用返回True，否则返回False
        @author: lkq 2021-08-28
        '''
        a = public.ExecShell("netstat -nltp|awk '{print $4}'")
        if a[0]:
            if re.search(":{}\n".format(port), a[0]):
                return True
            else:
                return False
        else:
            return False

    @classmethod
    def __generate_random_port(cls) -> int:
        '''
        @name 生成随机端口
        @args
        @return: 端口号
        @author: lkq 2021-08-28
        '''
        import random
        port = random.randint(5000, 10000)
        while cls.__check_port(port):
            port = random.randint(5000, 10000)
        return port

    # 获取索引配置
    @classmethod
    def __get_index_list(cls, sid: str = None, db_name: str = None, tb_name: str = None, default = None) -> Union[dict, None]:
        try:
            index_list = json.loads(public.readFile(cls.__INDEX_LIST_PATH))
        except:
            index_list = {}

        if sid is not None:
            index_list = index_list.get(str(sid), {})

        if db_name is not None:
            index_list = index_list.get(db_name, {})

        if tb_name is not None:
            index_list = index_list.get(tb_name, default)
        return index_list

    # 设置索引信息
    @classmethod
    def __set_index_list(cls, info: dict) -> bool:
        if info.get("sid") is None:
            return False
        if info.get("db_name") is None:
            return False
        if info.get("tb_name") is None:
            return False

        index_list = cls.__get_index_list()

        if index_list.get(str(info["sid"])) is None:
            index_list[str(info["sid"])] = {}
        sid_list = index_list[str(info["sid"])]

        if sid_list.get(info["db_name"]) is None:
            sid_list[info["db_name"]] = {}
        db_list = sid_list[info["db_name"]]

        db_list[info["tb_name"]] = info
        public.writeFile(cls.__INDEX_LIST_PATH, json.dumps(index_list))
        return True

    # 获取数据库信息
    def get_database(self, get):
        if not hasattr(get, "sid"):
            return public.returnMsg(False, "缺少参数！sid")
        if not str(get.sid).isdigit():
            return public.returnMsg(False, "参数错误！sid")

        sid = int(get.sid)
        if sid != 0:
            conn_config = public.M("database_servers").where("id=? AND LOWER(db_type)=LOWER('mysql')", (sid,)).find()
            if not conn_config:
                return public.returnMsg(False, "远程数据库信息不存在！")
            conn_config["db_name"] = None
            db_user = conn_config["db_user"]
            db_password = conn_config["db_password"]
            db_host = conn_config["db_host"]
            db_port = int(conn_config["db_port"])
        else:
            db_user = "root"
            db_password = public.M("config").where("id=?", (1,)).getField("mysql_root")
            db_host = "localhost"
            try:
                db_port = int(panelMysql.panelMysql().query("show global variables like 'port'")[0][1])
            except:
                db_port = 3306
        mysql_obj = db_mysql.panelMysql().set_host(db_host, db_port, None, db_user, db_password)
        if isinstance(mysql_obj, bool):
            return public.returnMsg(False, "连接数据库[{}:{}]失败".format(db_host, db_port))

        database_list = public.M("databases").field("name").where("sid=? AND LOWER(type)=LOWER('mysql')", (sid,)).select()
        for database in database_list:
            database["value"] = database["name"]

            table_list = mysql_obj.query("SELECT TABLE_NAME, TABLE_COMMENT FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = '{db_name}';".format(db_name=database["name"]))
            if not isinstance(table_list, list):
                continue
            database["table_list"] = []
            for tb_name in table_list:
                name = tb_name[0]
                if tb_name[1]:
                    name += "（{}）".format(tb_name[1])
                database["table_list"].append({"name": name, "value": tb_name[0]})
        return {"status": True, "msg": "ok", "data": database_list}

    # 创建主索引
    @classmethod
    def __create_index(cls, index_info: dict):
        if not os.path.exists(index_info["index_dir"]):
            os.makedirs(index_info["index_dir"])
        create_index_shell = "{indexer_bin} --config {config_path} {tb_name}".format(
            indexer_bin=cls.__SPHINX_INDEXER_BIN,
            config_path=index_info["conf_path"],
            tb_name=index_info["tb_name"],
        )
        public.ExecShell(create_index_shell)

    # 更新索引
    @classmethod
    def __update_index(cls, index_info: dict):
        # 更新索引

        create_index_shell = "{indexer_bin} --config {config_path} {tb_name}_increment".format(
            indexer_bin=cls.__SPHINX_INDEXER_BIN,
            config_path=index_info["conf_path"],
            tb_name=index_info["tb_name"],
        )
        public.ExecShell(create_index_shell)

        merge_index_shell = "{indexer_bin} --config {config_path} --merge {tb_name} {tb_name}_increment".format(
            indexer_bin=cls.__SPHINX_INDEXER_BIN,
            config_path=index_info["conf_path"],
            tb_name=index_info["tb_name"],
        )
        public.ExecShell(merge_index_shell)

    # 更新索引
    @classmethod
    def __check_index(cls, get,  sid: int, db_name: str, tb_name: str, mysql_obj: db_mysql.panelMysql, conn_config: dict) -> bool:
        index_info = cls.__get_index_list(str(sid), db_name, tb_name)
        if index_info is None: # 添加索引信息
            conf_path = os.path.join(cls.__CONFIG_DIR, "{}_{}_{}.conf".format(sid, db_name, tb_name))
            index_dir = os.path.join(cls.__DATA_DIR, str(sid), db_name, tb_name)
            index_info = {
                "sid": int(sid),
                "db_name": db_name,
                "tb_name": tb_name,
                "conf_path": conf_path,
                "index_dir": index_dir,
                "index_path": os.path.join(index_dir, "indexes/{}".format(tb_name)),
                "index_increment_path": os.path.join(index_dir, "indexes/{}_increment".format(tb_name)),
                "search_port": cls.__generate_random_port(),
                "pri_field": "",
                "value": 0,
                "field_list": [],
                "create_index": None,
                "update_index": None,
            }

        data_list = mysql_obj.query("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = '{db_name}' AND TABLE_NAME = '{tb_name}' AND EXTRA like '%auto_increment%';".format(db_name=db_name, tb_name=tb_name))
        if not isinstance(data_list, list) or len(data_list) == 0:
            get._ws.send(public.getJson({
                "ws_callback": get.ws_callback,
                "status": False,
                "type": 0,
                "msg": "{}.{} 表中没有自增主键".format(db_name, tb_name),
                "data": None,
            }))
            return False

        index_info["pri_field"] = data_list[0][0] # 获取主键字段

        data_list = mysql_obj.query("SELECT COLUMN_NAME, COLUMN_COMMENT FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = '{db_name}' AND TABLE_NAME = '{tb_name}';".format(db_name=db_name, tb_name=tb_name))
        if not isinstance(data_list, list) or len(data_list) == 0:
            get._ws.send(public.getJson({
                "ws_callback": get.ws_callback,
                "status": False,
                "type": 0,
                "msg": "{}.{} 查询表字段失败".format(db_name, tb_name),
                "data": None,
            }))
            return False
        index_info["field_list"] = [item[0] if not item[1] else "{}（{}）".format(item[0], item[1]) for item in data_list] # 获取所有字段


        data_list = mysql_obj.query("SELECT MAX({pri_field}) FROM `{db_name}`.`{tb_name}`;".format(pri_field= index_info["pri_field"], db_name=db_name, tb_name=tb_name))
        if not isinstance(data_list, list) or len(data_list) == 0:
            get._ws.send(public.getJson({
                "ws_callback": get.ws_callback,
                "status": False,
                "type": 0,
                "msg": "{}.{} 查询表信息失败".format(db_name, tb_name),
                "data": None,
            }))
            return False

        next_value = data_list[0][0] # 获取最大id

        create_index_time = None
        if index_info.get("create_index") is not None:
            create_index_time = datetime.datetime.strptime(index_info["create_index"], "%Y-%m-%d %H:%M:%S")

        day_time = datetime.datetime.now() - datetime.timedelta(days=1)

        if index_info.get("value") is None or not os.path.exists(index_info["index_dir"]):
            index_info["value"] = next_value
        elif index_info["value"] == next_value and not (create_index_time is not None and create_index_time < day_time):
            cls.__set_index_list(index_info)
            return True # 没有新增数据，并且 索引创建时间没有大于 一天

        sql_query = "select * from {};".format(index_info["tb_name"])
        sql_query_increment = "select * from {} where {} > {} and {} < {};".format(index_info["tb_name"], index_info["pri_field"], index_info["value"], index_info["pri_field"], next_value)

        # 检查端口是否被占用
        if cls.__check_port(index_info["search_port"]):
            index_info["search_port"] = cls.__generate_random_port()

        conf = cls._CONF_TEXT % (
            index_info["index_dir"],
            conn_config["host"],
            conn_config["user"],
            conn_config["password"],
            index_info["db_name"],
            str(conn_config["port"]),
            sql_query,
            conn_config["host"],
            conn_config["user"],
            conn_config["password"],
            index_info["db_name"],
            str(conn_config["port"]),
            sql_query_increment,
            index_info["tb_name"],
            index_info["tb_name"],
            index_info["tb_name"],
            str(index_info["search_port"])
        )
        public.writeFile(index_info["conf_path"], conf)

        if not os.path.exists(index_info["index_path"]) or (create_index_time is not None and create_index_time < day_time):# 创建索引
            # get._ws.send(public.getJson({
            #     "ws_callback": get.ws_callback,
            #     "status": True,
            #     "type": 0,
            #     "msg": "正在创建索引...",
            #     "data": None,
            # }))
            index_info["create_index"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cls.__create_index(index_info)
        else:
            # get._ws.send(public.getJson({
            #     "ws_callback": get.ws_callback,
            #     "status": True,
            #     "type": 0,
            #     "msg": "正在更新索引...",
            #     "data": None,
            # }))
            index_info["update_index"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cls.__update_index(index_info)
        index_info["value"] = next_value
        cls.__set_index_list(index_info)
        return True

    # 搜索关键词
    def sphinx_search(self, get):
        if not hasattr(get, "_ws"):
            return public.returnMsg(False, "暂不支持其他请求")

        status,resp = self.__check_plugin()
        if status is False:
            get._ws.send(public.getJson({
                "ws_callback": get.ws_callback,
                "status": False,
                "type": 0,
                "msg": resp,
                "data": None,
            }))
            return True

        if not hasattr(get, "sid"):
            get._ws.send(public.getJson({
                "ws_callback": get.ws_callback,
                "status": False,
                "type": 0,
                "msg": "缺少参数 sid !",
                "data": None,
            }))
            return True
        if not hasattr(get, "db_name"):
            get._ws.send(public.getJson({
                "ws_callback": get.ws_callback,
                "status": False,
                "type": 0,
                "msg": "缺少参数 db_name !",
                "data": None,
            }))
            return True
        if not hasattr(get, "tb_name"):
            get._ws.send(public.getJson({
                "ws_callback": get.ws_callback,
                "status": False,
                "type": 0,
                "msg": "缺少参数 tb_name !",
                "data": None,
            }))
            return True
        if not hasattr(get, "search"):
            get._ws.send(public.getJson({
                "ws_callback": get.ws_callback,
                "status": False,
                "type": 0,
                "msg": "缺少参数 search !",
                "data": None,
            }))
            return True

        sid = get.sid
        db_name = get.db_name
        tb_name = get.tb_name
        search = get.search
        p = int(getattr(get, "p", 1))
        limit = int(getattr(get, "limit", 50))

        conn_config = {
            "host": "localhost",
            "port": 3306,
            "user": "root",
            "password": "",
        }

        if int(sid) != 0:
            data = public.M("database_servers").where("id=? AND LOWER(db_type)=LOWER('mysql')", (sid,)).find()
            if not conn_config:
                return public.returnMsg(False, "远程数据库信息不存在！")
            conn_config["host"] = data["db_host"]
            conn_config["port"] = int(data["db_port"])
            conn_config["user"] = data["db_user"]
            conn_config["password"] = data["db_password"]
        else:
            conn_config["password"] =  public.M("config").where("id=?", (1,)).getField("mysql_root")
            try:
                conn_config["port"] = int(panelMysql.panelMysql().query("show global variables like 'port'")[0][1])
            except:
                pass

        mysql_obj = db_mysql.panelMysql().set_host(conn_config["host"], conn_config["port"], None, conn_config["user"], conn_config["password"])
        if isinstance(mysql_obj, bool):
            get._ws.send(public.getJson({
                "ws_callback": get.ws_callback,
                "status": False,
                "msg": "连接数据库[{}:{}]失败".format(conn_config["host"], conn_config["port"]),
                "data": None,
            }))
            return True

        if self.__check_index(get, sid, db_name,tb_name, mysql_obj, conn_config) is False:
            return True

        index_info = self.__get_index_list(str(sid), db_name, tb_name)
        public.ExecShell("{search_bin} --config {config_path} --stop".format(search_bin=self.__SPHINX_SEARCHD_BIN, config_path=index_info["conf_path"]))
        public.ExecShell("ps -ef|grep -a '%s'|grep -v grep|awk '{print $2}'|xargs kill -9"%(index_info["conf_path"]))
        public.ExecShell("{search_bin} --config {config_path}".format(search_bin=self.__SPHINX_SEARCHD_BIN, config_path=index_info["conf_path"]))

        from sphinxapi import SphinxClient, SPH_GROUPBY_ATTR, SPH_SORT_EXTENDED

        host = "localhost"
        port = index_info["search_port"]
        index = index_info["tb_name"]
        filtercol = "group_id"
        filtervals = []
        sortby = ''
        groupby = ''
        groupsort = '@group desc'

        cl = SphinxClient()
        cl.SetServer(host, port)
        if filtervals:
            cl.SetFilter(filtercol, filtervals)
        if groupby:
            cl.SetGroupBy(groupby, SPH_GROUPBY_ATTR, groupsort)
        if sortby:
            cl.SetSortMode(SPH_SORT_EXTENDED, sortby)

        cl.SetLimits((p - 1) * limit, limit, limit)
        result = cl.Query(search, index)

        if not result:
            get._ws.send(public.getJson({
                "ws_callback": get.ws_callback,
                "status": False,
                "msg": cl.GetLastError(),
                "data": None,
            }))
            return True

        # 包含分页类
        import page
        # 实例化分页类
        page = page.Page()
        info = {
            "p": p,
            "count": result["total_found"],
            "row": limit,
            "return_js": getattr(get, "return_js", ""),
            "uri": {},
        }
        page_info = page.GetPage(info)

        query_data = {
            "total": result["total"],
            "total_found": result["total_found"],
            "time": result["time"],
            "words": result["words"],
            "pri_field": index_info["pri_field"],
            "field_list": index_info["field_list"],
            "page": page_info,
        }
        get._ws.send(public.getJson({
            "ws_callback": get.ws_callback,
            "status": True,
            "type": 1,
            "data": query_data,
        }))

        for search_info  in result.get("matches", []):
            data_list = mysql_obj.query("select * from `{db_name}`.`{tb_name}` where {field}={value};".format(
                db_name=db_name,
                tb_name=tb_name,
                field=index_info["pri_field"],
                value=search_info["id"]
            ))
            if not isinstance(data_list, list):
                continue
            data_list = data_list[0]
            if len(data_list) != len(index_info["field_list"]):
                continue

            for idx in range(len(data_list)):
                if isinstance(data_list[idx], datetime.datetime):
                    data_list[idx] = data_list[idx].strftime("%Y-%m-%d %H:%M:%S")
                data_list[idx] = public.html_encode(data_list[idx])
            get._ws.send(public.getJson({
                "ws_callback": get.ws_callback,
                "status": True,
                "type": 2,
                "data": data_list,
            }))
        public.ExecShell("{search_bin} --config {config_path} --stop".format(search_bin=self.__SPHINX_SEARCHD_BIN, config_path=index_info["conf_path"]))
        public.ExecShell("ps -ef|grep -a '%s'|grep -v grep|awk '{print $2}'|xargs kill -9"%(index_info["conf_path"]))
        public.set_module_logs("Mysql", "敏感词搜索", 1)
        return True

    # 获取索引列表
    def get_index_list(self, get):

        index_list = []

        index_dict = self.__get_index_list()

        sqltie_obj = public.M("database_servers")

        for sid, info in index_dict.items():
            if sid == "0":
                db_host = "localhost"
            else:
                db_host = sqltie_obj.where("id=? AND LOWER(db_type)=LOWER('mysql')", (sid)).getField("db_host")
                if isinstance(db_host, str):
                    continue
            for db_name, db_info in info.items():
                for tb_name, index_info in db_info.items():
                    data = {
                        "db_host": db_host,
                        "sid": index_info["sid"],
                        "db_name": db_name,
                        "tb_name": tb_name,
                        "search_port": index_info["search_port"],
                        "create_index": index_info["create_index"],
                        "update_index": index_info["update_index"],
                        "size": public.get_path_size(index_info["index_dir"])
                    }

                    index_list.append(data)
        return {"status": True, "msg": "ok", "data": index_list}

    # 删除索引
    def del_index_list(self, get):
        if not hasattr(get, "sid"):
            return public.returnMsg(False, "缺少参数 sid !")
        if not hasattr(get, "db_name"):
            return public.returnMsg(False, "缺少参数 db_name !")
        if not hasattr(get, "tb_name"):
            return public.returnMsg(False, "缺少参数 tb_name !")

        index_dict = self.__get_index_list()
        sid_info = index_dict.get(str(get.sid))
        if sid_info is None:
            return public.returnMsg(False, "索引信息不存在!")
        db_info = sid_info.get(get.db_name)
        if db_info is None:
            return public.returnMsg(False, "索引信息不存在!")
        tb_info = db_info.get(get.tb_name)
        if tb_info is None:
            return public.returnMsg(False, "索引信息不存在!")


        public.ExecShell("rm {}".format(tb_info.get("conf_path")))
        public.ExecShell("rm -rf {}".format(tb_info.get("index_dir")))

        del db_info[get.tb_name]

        public.writeFile(self.__INDEX_LIST_PATH, json.dumps(index_dict))
        return public.returnMsg(True, "删除成功！")
