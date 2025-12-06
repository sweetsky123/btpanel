# coding: utf-8
# +-------------------------------------------------------------------
# | 宝塔Linux面板 x3
# +-------------------------------------------------------------------
# | Copyright (c) 2015-2017 宝塔软件(http://bt.cn) All rights reserved.
# +-------------------------------------------------------------------
# | Author: 王佳函 <mr_jia_han@qq.com>
# +-------------------------------------------------------------------
import copy
import datetime
import shutil
import sys
import os
import re

import public
import requests

os.chdir(public.get_panel_path())
sys.path.append("class/")

import json

try:
    import yaml
except:
    public.ExecShell("btpip install pyyaml")

from typing import Union, Tuple

from databaseModel.redisModel import panelRedisDB


class main:
    """
    下载配置文件
    wget -O /www/server/redis_docker/redis_slave_1.conf http://download.redis.io/redis-stable/redis.conf
    wget -O /www/server/redis_docker/sentinel_slave_1.conf http://download.redis.io/redis-stable/sentinel.conf


    docker run -d -p 10001:6379 --name redis-1 -v /www/server/redis_docker/redis_1.conf:/etc/redis/redis.conf -v /www/server/redis_docker/redis_1:/data redis:7.0.5 redis-server /etc/redis/redis.conf
    docker run -d -p 10001:6379 --name redis-2 -v /www/server/redis_docker/redis_2.conf:/etc/redis/redis.conf -v /www/server/redis_docker/redis_2:/data redis:7.0.5 redis-server /etc/redis/redis.conf
    docker run -d -p 10001:6379 --name redis-3 -v /www/server/redis_docker/redis_3.conf:/etc/redis/redis.conf -v /www/server/redis_docker/redis_3:/data redis:7.0.5 redis-server /etc/redis/redis.conf
    docker run -d -p 10001:6379 --name redis-4 -v /www/server/redis_docker/redis_4.conf:/etc/redis/redis.conf -v /www/server/redis_docker/redis_4:/data redis:7.0.5 redis-server /etc/redis/redis.conf
    docker run -d -p 10001:6379 --name redis-5 -v /www/server/redis_docker/redis_5.conf:/etc/redis/redis.conf -v /www/server/redis_docker/redis_5:/data redis:7.0.5 redis-server /etc/redis/redis.conf
    docker run -d -p 10001:6379 --name redis-6 -v /www/server/redis_docker/redis_6.conf:/etc/redis/redis.conf -v /www/server/redis_docker/redis_6:/data redis:7.0.5 redis-server /etc/redis/redis.conf
    docker run -d -p 10001:6379 --name redis-7 -v /www/server/redis_docker/redis_7.conf:/etc/redis/redis.conf -v /www/server/redis_docker/redis_7:/data redis:7.0.5 redis-server /etc/redis/redis.conf

    redis 配置

    """
    _CLUSTER_DIR = os.path.join(public.get_setup_path(), "redis_cluster")

    _CLUSTER_CONFIG = os.path.join(_CLUSTER_DIR, "redis_cluster.json")  # 集群配置文件
    _DOCKER_COMPOSE = os.path.join(_CLUSTER_DIR, "docker-compose.yml")

    # 下载路径
    _REDIS_CONF_URL = "http://download.redis.io/redis-stable/redis.conf"
    _REDIS_SENTINEL_CONF_URL = "http://download.redis.io/redis-stable/sentinel.conf"

    # 配置文件路径
    _REDIS_CONF = os.path.join(_CLUSTER_DIR, "redis.conf")
    _REDIS_SENTINEL_CONF = os.path.join(_CLUSTER_DIR, "sentinel.conf")

    def __init__(self):
        if not os.path.exists(self._CLUSTER_DIR):
            os.makedirs(self._CLUSTER_DIR)
        if not os.path.exists(self._CLUSTER_CONFIG):
            # replicate 1
            # sentinel 2
            # cluster 3
            # {
            #     "name": "redis_1",
            #     "port": 10001,
            #     "cpu": 1,
            #     "memory": 200,
            #     "role": 200,
            # },
            config = {
                "config": {
                    "pattern": "replicate",
                    "redis_version": "",
                    "databases": 16,
                    "requirepass": "",
                    "replicate": 0,
                    "version": "",
                    "status": False,
                },
                "cluster": []
            }
            public.writeFile(self._CLUSTER_CONFIG, json.dumps(config))

        # 下载redis配置文件
        if not os.path.isfile(self._REDIS_CONF):
            resp = requests.get(self._REDIS_CONF_URL)
            with open(self._REDIS_CONF, "wb") as f:
                f.write(resp.content)

            node_redis_content = public.readFile(self._REDIS_CONF)
            node_redis_content = re.sub(r"\nlocale-collate", "\n#locale-collate", node_redis_content)
            node_redis_content = re.sub(r"\nset-max-listpack-entries", "\n#set-max-listpack-entries", node_redis_content)
            node_redis_content = re.sub(r"\nset-max-listpack-value", "\n#set-max-listpack-value", node_redis_content)
            node_redis_content = re.sub(r"\nzset-max-listpack-entries", "\n#zset-max-listpack-entries", node_redis_content)
            node_redis_content = re.sub(r"\nzset-max-listpack-value", "\n#zset-max-listpack-value", node_redis_content)

            public.writeFile(self._REDIS_CONF, node_redis_content)
        # 下载哨兵配置文件
        if not os.path.isfile(self._REDIS_SENTINEL_CONF):
            resp = requests.get(self._REDIS_SENTINEL_CONF_URL)
            with open(self._REDIS_SENTINEL_CONF, "wb") as f:
                f.write(resp.content)

    @classmethod
    def __get_config(cls, config_type: str = None, default=None) -> dict:
        """
        获取集群配置
        """
        try:
            cluster_config = json.loads(public.readFile(cls._CLUSTER_CONFIG))
        except:
            cluster_config = {
                "config": {
                    "pattern": "replicate",
                    "redis_version": "",
                    "databases": 16,
                    "requirepass": "",
                    "replicate": 0,
                    "version": "",
                    "status": False,
                },
                "cluster": [],
            }
        if config_type is not None:
            cluster_config = cluster_config.get(config_type, default)
        return cluster_config

    @classmethod
    def __set_config(cls, cluster_config: dict) -> bool:
        """
        设置集群配置
        @param config: 配置信息
        @return:
        """
        public.writeFile(cls._CLUSTER_CONFIG, json.dumps(cluster_config))
        return True

    @classmethod
    def _new_password(cls) -> str:
        """
        帮助方法生成随机密码
        """
        import random
        import string
        # 生成随机密码
        password = "".join(random.sample(string.ascii_letters + string.digits, 16))
        return password

    @classmethod
    def check_docker(cls) -> Tuple[bool, str]:
        docker_version = public.ExecShell("docker --version")[0]
        docker_exists = re.search(r"\d+\.\d+(\.\d+)?", docker_version)
        if not docker_exists:
            return False, "请先安装 Docker!"
        docker_compose_version = public.ExecShell("docker-compose --version")[0]
        docker_compose_exists = re.search(r"\d+\.\d+(\.\d+)?", docker_compose_version)
        if not docker_compose_exists:
            return False, "请先安装 Docker-compose!"
        return True, ""

    # 设置集群
    def set_cluster(self, get):
        is_true, err = self.check_docker()
        if is_true is False:
            return public.returnMsg(False, err)
        if not hasattr(get, "pattern"):
            return public.returnMsg(False, "缺少参数! pattern")
        if not hasattr(get, "redis_version"):
            return public.returnMsg(False, "缺少参数! redis_version")
        if not hasattr(get, "databases"):
            return public.returnMsg(False, "缺少参数! databases")
        if not hasattr(get, "requirepass"):
            return public.returnMsg(False, "缺少参数! requirepass")
        if not hasattr(get, "cluster"):
            return public.returnMsg(False, "缺少参数! cluster")
        if not str(get.databases).isdigit():
            return public.returnMsg(False, "参数错误! databases")

        if len(get.cluster) < 3:
            return public.returnMsg(False, "集群实例至少为 3 个！")

        if get.pattern not in ["replicate", "sentinel", "cluster"]:
            return public.returnMsg(False, "参数错误! pattern")

        pattern = get.pattern
        redis_version = get.redis_version
        databases = int(get.databases)
        requirepass = get.requirepass
        replicate = int(getattr(get, "replicate", 0))
        add_cluster = get.cluster

        cluster_config = self.__get_config()
        if cluster_config.get("config") is None:
            cluster_config["config"] = {}

        docker_version = public.ExecShell("docker-compose --version")[0]
        docker_version_obj = re.search(r"\d+\.\d+(\.\d+)?", docker_version)
        if not docker_version_obj:
            return public.returnMsg(False, "请先安装 Docker-compose!")
        docker_version = docker_version_obj.group()

        cluster_config["config"]["pattern"] = pattern
        cluster_config["config"]["redis_version"] = redis_version
        cluster_config["config"]["databases"] = databases
        cluster_config["config"]["requirepass"] = requirepass
        cluster_config["config"]["replicate"] = replicate
        cluster_config["config"]["version"] = docker_version

        is_master = False
        port_set = set()
        for add_cluster_info in add_cluster:
            if add_cluster_info["role"] == 1:
                is_master = True
            if add_cluster_info["port"] in port_set:
                return public.returnMsg(False, "重复端口：{}".format(add_cluster_info["port"]))
            port_set.add(add_cluster_info["port"])
        
        if is_master is False:
            return public.returnMsg(False, "必须要有一个主库")
        
        cluster_list = [add_cluster_info for add_cluster_info in add_cluster if add_cluster_info.get("node_id") is not None]
        add_cluster = [add_cluster_info for add_cluster_info in add_cluster if add_cluster_info.get("node_id") is None]
        # 获取 id
        max_id = 1

        for add_cluster_info in add_cluster:
            cluster_list.sort(key=lambda data: data["node_id"])
            for cluster_info in cluster_list:
                if cluster_info.get("node_id") is not None:
                    while max_id == int(cluster_info.get("node_id")):
                        max_id += 1

            add_cluster_info["node_id"] = max_id
            add_cluster_info["name"] = "redis_node_{}".format(max_id)
            add_cluster_info["cluster_dir"] = os.path.join(self._CLUSTER_DIR, add_cluster_info["name"])
            cluster_list.append(add_cluster_info)

        # if pattern == "cluster" and replicate != 0:  # 创建集群
        if pattern == "cluster":  # 创建集群
            master_num = 0
            slave_num = 0
            for cluster_info in cluster_list:
                cluster_info["port"] = int(cluster_info["port"])
                if cluster_info["role"] == 1:
                    master_num += 1
                else:
                    slave_num += 1
                if cluster_info["port"] > 55535:
                    return public.returnMsg(False, "集群端口不能大于 55535！")
            if master_num < 3:
                return public.returnMsg(False, "集群最少要有 3 个主节点！<br/>当前主节点 {} 个，请确保主节点的数量!".format(master_num))
            if slave_num > 0 and slave_num % master_num != 0:
                return public.returnMsg(False, "您设置了从节点，从节点的个数应为为主节点的倍数！<br/>主节点 {} 个，从节点应为 {}/{}/{}...{}*n".format(master_num, master_num * 1, master_num * 2, master_num * 3, master_num))
            # if master_num * replicate != slave_num:
            #     return public.returnMsg(False, "您设置了每个主节点下有 {} 个从节点<br/>当前主节点 {} 个，则需要 {}/{}*{} 个从节点，请确保从节点的数量!".format(replicate, master_num, slave_num, master_num, replicate))

        cluster_list.sort(key=lambda data: data["node_id"])
        cluster_config["cluster"] = cluster_list
        self.__set_config(cluster_config)

        try:
            self.restart_cluster(None)
        except:
            return public.returnMsg(False, "重启集群失败！")

        return public.returnMsg(True, "设置成功！")

    # 部署 Redis 集群
    def restart_cluster(self, get):
        is_true, err = self.check_docker()
        if is_true is False:
            return public.returnMsg(False, err)
        cluster_config = self.__get_config()

        config = cluster_config.get("config", {})
        if config.get("status",False) is True:
            public.ExecShell("cd {} && docker-compose down".format(self._CLUSTER_DIR))

        cluster_list = cluster_config.get("cluster", [])
        if len(cluster_list) == 0:
            return public.returnMsg(False, "请先创建集群！")

        if config["pattern"] not in ["replicate", "sentinel", "cluster"]:
            public.returnMsg(False, "该模式不存在!")

        docker_file = {
            "version": config["version"],
            "services": {},
        }

        config_data = copy.deepcopy(config)
        for cluster_info in cluster_list:
            if config["pattern"] != "cluster" and cluster_info.get("role") == 1:
                config_data["master_port"] = cluster_info.get("port", "6379")
                config_data["master_host"] = public.GetLocalIp()

        # 集群
        cluster_master_node = ""
        cluster_slave_node = ""
        for cluster_info in cluster_list:

            if not os.path.exists(cluster_info["cluster_dir"]):
                os.makedirs(cluster_info["cluster_dir"])
            config_data["name"] = cluster_info["name"]
            config_data["role"] = cluster_info["role"]
            config_data["host"] = cluster_info.get("host", "0.0.0.0")
            config_data["port"] = cluster_info.get("port", "6379")
            config_data["cluster_dir"] = cluster_info["cluster_dir"]
            config_data["use_cpu"] = str(cluster_info.get("use_cpu", "1"))
            config_data["use_memory"] = str(cluster_info.get("use_memory", "500"))

            # 配置文件
            if config["pattern"] == "replicate":  # 主从
                docker_file_content = self._replicate_conf(config_data)

            elif config["pattern"] == "sentinel":  # 哨兵
                config_data["node_id"] = cluster_info["node_id"]
                config_data["sentinel_port"] = cluster_info["port"] + 10000 if cluster_info["port"] + 10000 < 60000 else cluster_info["port"] - 10000
                config_data["quorum"] = len(cluster_list) if cluster_info.get("quorum") is None else int(cluster_info.get("quorum"))
                config_data["replica-priority"] = cluster_info["node_id"] if cluster_info.get("replica_priority") is None else int(cluster_info.get("replica_priority"))
                config_data["milliseconds"] = 10 if cluster_info.get("milliseconds") is None else int(cluster_info.get("milliseconds"))
                docker_file_content, sentinel_docker_file_content = self._sentinel_conf(config_data)

                docker_file["services"][cluster_info["name"] + "_sentinel"] = sentinel_docker_file_content

            elif config["pattern"] == "cluster":  # 集群

                if config_data["role"] == 1:
                    cluster_master_node += " {}:{}".format(public.get_local_ip(), config_data["port"])
                else:
                    cluster_slave_node += " {}:{}".format(public.get_local_ip(), config_data["port"])
                docker_file_content = self._cluester_conf(config_data)
            else:
                return public.returnMsg(False, "该模式不存在!")

            docker_file["services"][cluster_info["name"]] = docker_file_content

        with open(self._DOCKER_COMPOSE, "w") as f:
            f.write(yaml.dump(docker_file))

        public.ExecShell("cd {} && docker-compose up -d".format(self._CLUSTER_DIR))

        if config["pattern"] == "cluster":  # 创建集群
            cluster_create = "redis-cli -a {} --cluster-yes --cluster create{}{}".format(config["requirepass"], cluster_master_node, cluster_slave_node)
            if config["replicate"] is not None:
                cluster_create += " --cluster-replicas {}".format(config["replicate"])
            public.ExecShell(cluster_create, timeout=5)
        config["status"] = True
        self.__set_config(cluster_config)
        return {"status": True, "msg": "配置完成！", "data": ""}

    # 停止集群
    def stop_cluster(self, get):

        cluster_config = self.__get_config()
        config = cluster_config.get("config", {})
        if config.get("status", False) is False:
            return {"status": True, "msg": "停止集群成功！", "data": ""}
        public.ExecShell("cd {} && docker-compose down".format(self._CLUSTER_DIR))
        config["status"] = False
        self.__set_config(cluster_config)
        return {"status": True, "msg": "停止集群成功！", "data": ""}

    # 获取集群信息
    def get_cluster_info(self, get):
        cluster_config = self.__get_config()

        for cluster_info in cluster_config["cluster"]:
            cluster_info["port"] = int(cluster_info["port"])
            if cluster_config["config"]["pattern"] == "sentinel":
                cluster_info["port_2"] = cluster_info["port"] + 10000 if cluster_info["port"] + 10000 < 60000 else cluster_info["port"] - 10000
            if cluster_config["config"]["pattern"] == "cluster":
                cluster_info["port_2"] = cluster_info["port"] + 10000
            status = public.ExecShell("docker inspect -f '{{.State.Status}}' " + cluster_info["name"])[0]
            cluster_info["status"] = str(status).strip()

        cluster_config["cluster"].sort(key=lambda data: data["role"], reverse=True)
        cluster_config["redis_version"] = [
            "7.0.11",
            "6.2.7"
        ]
        public.set_module_logs("redis_cluster", "get_cluster_info", 1)
        return {"status": True, "msg": "ok", "data": cluster_config}

    # 删除实例
    def remove_cluster_node(self, get):
        if not hasattr(get, "node_id"):
            return public.returnMsg(False, "缺少参数! node_id")

        node_id = get.node_id

        cluster_config = self.__get_config()

        cluster_list = cluster_config.get("cluster", [])

        master_num = 0
        slave_num = 0
        for cluster_info in cluster_list:
            if cluster_info["role"] == 1:
                master_num += 1
            else:
                slave_num += 1

        if cluster_config["config"]["pattern"] != "cluster" and slave_num  < 3:
            return public.returnMsg(False, "集群最少保留 2 个从节点！")

        for i in range(len(cluster_list)):
            cluster_info = cluster_list[i]
            if cluster_info["node_id"] == node_id:

                if cluster_config["config"]["pattern"] == "cluster":
                    if cluster_info["role"] == 1 and master_num <= 3: # 删除主节点
                        return public.returnMsg(False, "集群最少保留 3 个主节点！")
                else:
                    if cluster_info["role"] == 1: # 删除主节点
                        return public.returnMsg(False, "不能删除主库节点！")
                    elif slave_num  < 3: # 删除从节点
                        return public.returnMsg(False, "集群最少保留 2 个从节点！")

                del cluster_list[i]
                public.ExecShell("docker stop {}".format(cluster_info["name"]))
                public.ExecShell("docker rm -f {}".format(cluster_info["name"]))
                break
        cluster_config["cluster"] = cluster_list
        self.__set_config(cluster_config)
        return public.returnMsg(True, "删除成功！")

    # 设置容器状态
    def set_container(self, get):
        if not hasattr(get, "node_id"):
            return public.returnMsg(False, "缺少参数! node_id")
        if not hasattr(get, "status"):
            return public.returnMsg(False, "缺少参数! status")

        node_id = get.node_id
        container_status = str(get.status).lower()

        container_command = {
            "start": "启动",
            "stop": "停止",
            "pause": "暂停",
            "unpause": "取消暂停",
            "restart": "重启",
        }
        if container_command.get(container_status) is None:
            public.returnMsg(False, "没有该操作！")

        cluster_config = self.__get_config()

        cluster_list = cluster_config.get("cluster", [])
        for i in range(len(cluster_list)):
            cluster_info = cluster_list[i]
            if cluster_info["node_id"] == node_id:
                if container_status == "start":
                    status = public.ExecShell("docker inspect -f '{{.State.Status}}' " + cluster_info["name"])[0]
                    if str(status).strip() == "paused":
                        public.ExecShell("docker unpause {}".format(cluster_info["name"]))
                        return public.returnMsg(True, "{} 成功！".format(container_command["unpause"]))

                public.ExecShell("docker {} {}".format(container_status, cluster_info["name"]))
                return public.returnMsg(True, "{} 成功！".format(container_command[container_status]))

        return public.returnMsg(False, "容器不存在！")

    def _replicate_conf(self, cluster_info: dict) -> dict:
        """
            # vim /www/server/redis_cluster/redis_1/redis.conf
            bind 127.0.0.1
            port 6379
            daemonize yes
            pidfile /www/server/redis_cluster/redis_1/redis.pid : /data/redis.pid
            logfile /www/server/redis_cluster/redis_1/redis.log : /data/redis.log
            dir /www/server/redis_cluster/redis_1 : /data
            databases 16

            replicaof 127.0.0.1 6379
            masterauth '86a1b907d54bf7010394bf316e183e67'
            requirepass '86a1b907d54bf7010394bf316e183e67'  #设置密码
            appendonly yes              #aof日志开启  有需要就开启，它会每次写操作都记录一条日志　
        """
        node_redis_conf = os.path.join(cluster_info["cluster_dir"], "redis.conf")
        # 拷贝文件
        shutil.copy(self._REDIS_CONF, node_redis_conf)

        node_redis_content = public.readFile(node_redis_conf)

        node_redis_content = re.sub(r"\nbind[^\n]+\n", "\nbind {}\n".format(cluster_info["host"]), node_redis_content)
        node_redis_content = re.sub(r"\nport[^\n]+\n", "\nport {}\n".format(cluster_info["port"]), node_redis_content)
        node_redis_content = re.sub(r"\npidfile[^\n]+\n", "\npidfile '/data/redis.pid'\n", node_redis_content)
        node_redis_content = re.sub(r"\nlogfile[^\n]+\n", "\nlogfile '/data/redis.log'\n", node_redis_content)
        node_redis_content = re.sub(r"\ndir[^\n]+\n", "\ndir '/data'\n", node_redis_content)
        node_redis_content = re.sub(r"\ndatabases[^\n]+\n", "\ndatabases {}\n".format(cluster_info["databases"]), node_redis_content)
        if cluster_info.get("role") != 1:
            node_redis_content = re.sub(r"\n#\s*replicaof[^\n]+\n", "\nreplicaof {} {}\n".format(cluster_info["master_host"], cluster_info["master_port"]), node_redis_content)
        node_redis_content = re.sub(r"\n#\s*masterauth[^\n]+\n", "\nmasterauth {}\n".format(cluster_info["requirepass"]), node_redis_content)
        node_redis_content = re.sub(r"\n#\s*requirepass[^\n]+\n", "\nrequirepass {}\n".format(cluster_info["requirepass"]), node_redis_content)
        node_redis_content = re.sub(r"\n#\s*appendonly[^\n]+\n", "\nappendonly yes\n", node_redis_content)

        public.writeFile(node_redis_conf, node_redis_content)

        # dockerfile 文件内容
        docker_file_content = {
            "image": "docker.io/library/redis:{}".format(cluster_info["redis_version"]),
            "container_name": cluster_info["name"],
            "restart": "always",
            "network_mode": "host",
            "volumes": [
                "{}:/data".format(cluster_info["cluster_dir"]),
            ],
            "environment": {
                "TZ": "Asia/Shanghai",
            },
            "command": "/usr/local/bin/redis-server /data/redis.conf",
            "deploy": {
                "resources": {
                    "limits": {
                        "cpus": cluster_info["use_cpu"],
                        "memory": cluster_info["use_memory"] + "M",
                    }
                }
            },
        }
        return docker_file_content

    def _sentinel_conf(self, cluster_info: dict) -> Tuple[dict, dict]:
        """
            # vim /www/server/redis_cluster/redis_1/redis.conf
            bind 127.0.0.1
            port 6379
            daemonize yes
            pidfile /www/server/redis_cluster/redis_1/redis.pid : /data/redis.pid
            logfile /www/server/redis_cluster/redis_1/redis.log : /data/redis.log
            dir /www/server/redis_cluster/redis_1 : /data
            databases 16

            replica-priority 30

            replicaof 127.0.0.1 6379
            masterauth '86a1b907d54bf7010394bf316e183e67'
            requirepass '86a1b907d54bf7010394bf316e183e67'  #设置密码
            appendonly yes

            # vim /www/server/redis_cluster/redis_1/sentinel.conf
            port 26379
            daemonize yes
            pidfile /www/server/redis_cluster/redis_1/redis-sentinel.pid : /data/redis-sentinel.pid
            logfile /www/server/redis_cluster/redis_1/redis-sentinel.log : /data/redis-sentinel.log
            dir /www/server/redis_cluster/redis_1 : /data                 #sentinel工作目录
            sentinel monitor mymaster 192.168.30.128 6379 2                 #判断master失效至少需要2个sentinel同意，建议设置为n/2+1，n为sentinel个数
            sentinel auth-pass mymaster 123456
            sentinel down-after-milliseconds mymaster 30000                 #判断master主观下线时间，默认30s

        """
        node_redis_conf = os.path.join(cluster_info["cluster_dir"], "redis.conf")
        # 拷贝文件
        shutil.copy(self._REDIS_CONF, node_redis_conf)

        node_redis_content = public.readFile(node_redis_conf)

        node_redis_content = re.sub(r"\nbind[^\n]+\n", "\nbind {}\n".format(cluster_info["host"]), node_redis_content)
        node_redis_content = re.sub(r"\nport[^\n]+\n", "\nport {}\n".format(cluster_info["port"]), node_redis_content)
        node_redis_content = re.sub(r"\npidfile[^\n]+\n", "\npidfile '/data/redis.pid'\n", node_redis_content)
        node_redis_content = re.sub(r"\nlogfile[^\n]+\n", "\nlogfile '/data/redis.log'\n", node_redis_content)
        node_redis_content = re.sub(r"\ndir[^\n]+\n", "\ndir '/data'\n", node_redis_content)
        node_redis_content = re.sub(r"\ndatabases[^\n]+\n", "\ndatabases {}\n".format(cluster_info["databases"]), node_redis_content)
        if cluster_info.get("role") != 1:
            node_redis_content = re.sub(r"\n#\s*replicaof[^\n]+\n", "\nreplicaof {} {}\n".format(cluster_info["master_host"], cluster_info["master_port"]), node_redis_content)
        node_redis_content = re.sub(r"\n#\s*masterauth[^\n]+\n", "\nmasterauth {}\n".format(cluster_info["requirepass"]), node_redis_content)
        node_redis_content = re.sub(r"\n#\s*requirepass[^\n]+\n", "\nrequirepass {}\n".format(cluster_info["requirepass"]), node_redis_content)
        node_redis_content = re.sub(r"\n#\s*appendonly[^\n]+\n", "\nappendonly yes\n", node_redis_content)
        # 故障转移优先级
        node_redis_content = re.sub(r"\nreplica-priority[^\n]+\n", "\nreplica-priority {}\n".format(cluster_info["replica-priority"]), node_redis_content)

        # dockerfile 文件内容
        docker_file_content = {
            "image": "docker.io/library/redis:{}".format(cluster_info["redis_version"]),
            "container_name": cluster_info["name"],
            "restart": "always",
            "network_mode": "host",
            "volumes": [
                "{}:/data".format(cluster_info["cluster_dir"]),
            ],
            "environment": {
                "TZ": "Asia/Shanghai",
            },
            "command": "/usr/local/bin/redis-server /data/redis.conf",
            "deploy": {
                "resources": {
                    "limits": {
                        "cpus": cluster_info["use_cpu"],
                        "memory": cluster_info["use_memory"] + "M",
                    }
                }
            },
        }

        public.writeFile(node_redis_conf, node_redis_content)

        node_redis_sentinel_conf = os.path.join(cluster_info["cluster_dir"], "sentinel.conf")
        shutil.copy(self._REDIS_SENTINEL_CONF, node_redis_sentinel_conf)
        node_redis_sentinel_content = public.readFile(node_redis_sentinel_conf)

        node_redis_sentinel_content = re.sub(r"\nport[^\n]+\n", "\nport {}\n".format(cluster_info["sentinel_port"]), node_redis_sentinel_content, 1)
        node_redis_sentinel_content = re.sub(r"\npidfile[^\n]+\n", "\npidfile '/data/sentinel.pid'\n", node_redis_sentinel_content, 1)
        node_redis_sentinel_content = re.sub(r"\nlogfile[^\n]+\n", "\nlogfile '/data/sentinel.log'\n", node_redis_sentinel_content, 1)
        node_redis_sentinel_content = re.sub(r"\ndir[^\n]+\n", "\ndir '/tmp'\n", node_redis_sentinel_content, 1)
        node_redis_sentinel_content = re.sub(r"\n#\s*requirepass[^\n]+\n", "\nrequirepass {}\n".format(cluster_info["requirepass"]), node_redis_sentinel_content)
        # node_redis_sentinel_content = re.sub(r"\n#\s*sentinel announce-ip[^\n]+\n", "\nsentinel announce-ip {}\n".format(public.GetLocalIp()), node_redis_sentinel_content, 1)
        # node_redis_sentinel_content = re.sub(r"\n#\s*sentinel announce-port[^\n]+\n", "\nsentinel announce-port {}\n".format(cluster_info["sentinel_port"]), node_redis_sentinel_content,1)
        node_redis_sentinel_content = re.sub(r"\nsentinel monitor[^\n]+\n", "\nsentinel monitor mymaster {} {} {}\n".format(cluster_info["master_host"], cluster_info["master_port"], cluster_info["quorum"]), node_redis_sentinel_content, 1)
        node_redis_sentinel_content = re.sub(r"\n#\s*sentinel auth-pass <master-name>[^\n]+\n", "\nsentinel auth-pass mymaster {}\n".format(cluster_info["requirepass"]), node_redis_sentinel_content, 1)
        node_redis_sentinel_content = re.sub(r"\nsentinel down-after-milliseconds[^\n]+\n", "\nsentinel down-after-milliseconds mymaster {}\n".format(cluster_info["milliseconds"]), node_redis_sentinel_content, 1)
        node_redis_sentinel_content = re.sub(r"\nsentinel parallel-syncs[^\n]+\n", "\nsentinel parallel-syncs mymaster 1\n", node_redis_sentinel_content, 1)
        node_redis_sentinel_content = re.sub(r"\nsentinel failover-timeout[^\n]+\n", "\nsentinel failover-timeout mymaster 10000\n", node_redis_sentinel_content, 1)

        public.writeFile(node_redis_sentinel_conf, node_redis_sentinel_content)

        # dockerfile 文件内容
        sentinel_docker_file_content = {
            "image": "docker.io/library/redis:{}".format(cluster_info["redis_version"]),
            "container_name": "redis_sentinel_{}".format(cluster_info["node_id"]),
            "network_mode": "host",
            "volumes": [
                "{}:/data".format(cluster_info["cluster_dir"]),
            ],
            "environment": {
                "TZ": "Asia/Shanghai"
            },
            "command": "/usr/local/bin/redis-sentinel /data/sentinel.conf",

        }
        return docker_file_content, sentinel_docker_file_content

    def _cluester_conf(self, cluster_info: dict) -> dict:
        """
            # vim /www/server/redis_cluster/redis_1/redis.conf
            bind 127.0.0.1
            port 6379
            daemonize yes
            pidfile /www/server/redis_cluster/redis_1/redis.pid : /data/redis.pid
            logfile /www/server/redis_cluster/redis_1/redis.log : /data/redis.log
            dir /www/server/redis_cluster/redis_1 : /data
            databases 16

            # replicaof 127.0.0.1 6379
            masterauth '86a1b907d54bf7010394bf316e183e67'
            requirepass '86a1b907d54bf7010394bf316e183e67'  #设置密码
            appendonly  yes              #aof日志开启  有需要就开启，它会每次写操作都记录一条日志　

            cluster-enabled  yes                    #开启集群  把注释#去掉
            cluster-config-file  nodes_7000.conf   #集群的配置  配置文件首次启动自动生成
            cluster-node-timeout  15000         #请求超时  默认15秒，可自行设置

            redis-cli -a admin --cluster create 127.0.0.1:30001 127.0.0.1:30002 127.0.0.1:30003 127.0.0.1:30004 127.0.0.1:30005 127.0.0.1:30006 --cluster-replicas 1
        """
        node_redis_conf = os.path.join(cluster_info["cluster_dir"], "redis.conf")
        # 拷贝文件
        shutil.copy(self._REDIS_CONF, node_redis_conf)

        node_redis_content = public.readFile(node_redis_conf)

        node_redis_content = re.sub(r"\nbind[^\n]+\n", "\nbind {}\n".format(cluster_info["host"]), node_redis_content)
        node_redis_content = re.sub(r"\nport[^\n]+\n", "\nport {}\n".format(cluster_info["port"]), node_redis_content)
        node_redis_content = re.sub(r"\npidfile[^\n]+\n", "\npidfile '/data/redis.pid'\n", node_redis_content)
        node_redis_content = re.sub(r"\nlogfile[^\n]+\n", "\nlogfile '/data/redis.log'\n", node_redis_content)
        node_redis_content = re.sub(r"\ndir[^\n]+\n", "\ndir '/data'\n", node_redis_content)
        node_redis_content = re.sub(r"\ndatabases[^\n]+\n", "\ndatabases {}\n".format(cluster_info["databases"]), node_redis_content)
        node_redis_content = re.sub(r"\n#\s*masterauth[^\n]+\n", "\nmasterauth {}\n".format(cluster_info["requirepass"]), node_redis_content)
        node_redis_content = re.sub(r"\n#\s*requirepass[^\n]+\n", "\nrequirepass {}\n".format(cluster_info["requirepass"]), node_redis_content)
        node_redis_content = re.sub(r"\n#\s*appendonly[^\n]+\n", "\nappendonly yes\n", node_redis_content)

        node_redis_content = re.sub(r"\n#\s*cluster-enabled[^\n]+\n", "\ncluster-enabled yes\n", node_redis_content)
        node_redis_content = re.sub(r"\n#\s*cluster-config-file[^\n]+\n", "\ncluster-config-file nodes.conf\n", node_redis_content)
        node_redis_content = re.sub(r"\n#\s*cluster-node-timeout[^\n]+\n", "\ncluster-node-timeout 15000\n", node_redis_content)

        # node_redis_content = re.sub(r"\n#\s*cluster-announce-ip[^\n]+\n", "\ncluster-announce-ip {}\n".format(cluster_info["announce_ip"]), node_redis_content)
        # node_redis_content = re.sub(r"\n#\s*cluster-announce-port[^\n]+\n", "\ncluster-announce-port {}\n".format(cluster_info["port"]), node_redis_content)
        # node_redis_content = re.sub(r"\n#\s*cluster-announce-bus-port[^\n]+\n", "\ncluster-announce-bus-port {}\n".format(cluster_info["port"] + 10000), node_redis_content)

        public.writeFile(node_redis_conf, node_redis_content)

        # dockerfile 文件内容
        docker_file_content = {
            "image": "docker.io/library/redis:{}".format(cluster_info["redis_version"]),
            "container_name": cluster_info["name"],
            "restart": "always",
            "network_mode": "host",
            "volumes": [
                "{}:/data".format(cluster_info["cluster_dir"]),
            ],
            "environment": {
                "TZ": "Asia/Shanghai",
            },
            "command": [
                "/usr/local/bin/redis-server",
                "/data/redis.conf",
            ],
            "deploy": {
                "resources": {
                    "limits": {
                        "cpus": cluster_info["use_cpu"],
                        "memory": cluster_info["use_memory"] + "M",
                    }
                }
            },
        }

        return docker_file_content
