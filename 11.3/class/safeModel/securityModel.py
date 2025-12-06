# coding: utf-8
# -------------------------------------------------------------------
# 宝塔Linux面板
# -------------------------------------------------------------------
# Copyright (c) 2014-2099 宝塔软件(http://bt.cn) All rights reserved.
# -------------------------------------------------------------------
# Author: wzz <wzz@bt.cn>
# -------------------------------------------------------------------

# 面板安全风险一键修复
# ------------------------------
import os, re, json, sys
import time

os.chdir("/www/server/panel")
sys.path.append("class/")
import public, config
from safeModel.base import safeBase


class main(safeBase):
    __path = '/www/server/panel/data/warning'
    __risk = __path + '/risk'
    __repair_history = __path + '/repair_history.json'
    __repair_list = []
    product_version = __path + '/product_version.json'  # 包-版本号缓存文件
    one_repair_data = {"time": time.time(), "m_name": "", "describe": "", "recover": ""}  # 生成单个漏洞的历史修复记录
    sys_version = "None"  # 当前系统版本

    def __init__(self):
        self.configs = config.config()
        # # 修复历史记录
        # self.__sql = db.Sql().dbfile("warning/repair_history.db")
        # if not self.__sql.table('sqlite_master').where('type=? AND name=?', ('table', 'repair_history')).count():
        #     sql = '''CREATE TABLE IF NOT EXISTS `repair_history` (
        #        `id` INTEGER PRIMARY KEY AUTOINCREMENT,
        #        "Type" VARCHAR(30) NULL,
        #        "Time" VARCHAR(50) NULL,
        #        "Name" TEXT NULL,
        #        "Describe" TEXT NULL,
        #        "Recover" TEXT NULL
        #        )'''
        #     self.__sql.execute(sql)

    def set_security(self, get):
        '''
        自动修复对应的安全风险项
        @param get: 传 < dict_obj > 里面包含风险名列表 < list > m_name
        @return: 返回 dict_obj
        '''
        public.set_module_logs('panelWarning', 'set_security', 1)
        all_repair_data = []  # 全部修复历史数据
        self.sys_version = self.get_sys_version()  # 初始化获取当前系统版本
        public.WriteFile(self.__path + '/repair_bar.txt', json.dumps({"status": "准备修复", "percentage": 0.0}))  # 修复进度条归零
        # m_name_list = get.m_name
        # list_length = len(m_name_list)  # 传过来的要修复的风险数量
        fist_list = get.m_name
        list_length = len(fist_list)
        cve_list = []  # CVE编号
        RHSA_list = []  # 红帽安全编号
        m_name_list = []  # 安全风险
        for m_name in fist_list:
            if m_name.startswith('CVE'):
                cve_list.append(m_name)
            elif m_name.startswith('RH') or m_name.startswith("ALINUX"):
                RHSA_list.append(m_name)
            else:
                m_name_list.append(m_name)
        # cve_list = [s for s in m_name_list if s.startswith('CVE')] # 提取出CVE的列表
        # m_name_list[:] = [s for s in m_name_list if not s.startswith('CVE')] # 提取出属于风险的列表
        is_autofix = public.read_config("safe_autofix")
        success = []
        failed = []
        cannot_automatically = []
        data = {
            "success": None,
            "failed": None,
            "cannot_automatically": None
        }
        # risk_list = json.loads(public.ReadFile(self.__path + "/result.json"))["risk"]
        bar_num = 0  # 修复进度条
        # if cve_list:
        #     for cve in cve_list:
        #         bar = ("%.2f" % (float(bar_num) / float(list_length) * 100))
        #         bar_text = {"status": "正在修复系统漏洞{}，耗时较久".format(cve), "percentage": bar}
        #         public.WriteFile(self.__path + '/repair_bar.txt', json.dumps(bar_text))
        #         bar_num += 1
        #         tmp = 0
        #         for risk in risk_list:
        #             if cve == risk["cve_id"]:
        #                 tmp = 2
        #                 for soft in risk["soft_name"].keys():
        #                     if self.upgrade_soft(soft) == 1:
        #                         tmp = 1
        #             if tmp == 1:
        #                 success.append(
        #                     {"result": {"status": True, "msg": "已修复{}".format(risk["cve_id"]), "type": ""},
        #                      "m_name": risk["vuln_name"]})
        #                 break
        #             elif tmp == 2:
        #                 failed.append({"result": {"status": True, "msg": "修复失败{}".format(risk["cve_id"]), "type": ""},
        #                                "m_name": risk["vuln_name"]})
        #                 break
        # 新漏洞检测修复
        # debian、ubuntu的走这里
        if cve_list:
            repair_dict = {}  # {RHSA: [package]}
            repaired_pk = {}  # 已修复的软件包字典，避免重复修复{"soft": 1或2}
            # 读取上一次首页扫描结果，获取可修复的软件包{cve: [package]}
            riskrisk_list = json.loads(public.ReadFile(self.__path + "/resultresult.json"))["risk"]
            for rrl in riskrisk_list:
                # 目前属于漏洞的才有type字段
                if "type" in rrl:
                    repair_dict[rrl["m_name"]] = rrl["package"]
            for cve in cve_list:
                public.set_module_logs("securityModel", "cve")
                # 初始化修复历史记录
                self.one_repair_data["time"] = time.time()
                self.one_repair_data["m_name"] = cve
                old_version = self.get_dpkg_version(repair_dict[cve])
                bar = ("%.f" % (float(bar_num) / float(list_length) * 100))
                bar_text = {"status": "正在修复系统漏洞{}，耗时较久".format(cve), "percentage": bar}
                public.WriteFile(self.__path + '/repair_bar.txt', json.dumps(bar_text))
                bar_num += 1
                tmp = 1  # 默认为1，2需要关闭系统加固、3修复失败原因未知
                try:
                    for pk in repair_dict[cve]:
                        # 已修复的包直接跳过
                        if pk in repaired_pk:
                            # 如果前面修复失败了，标识上
                            if repaired_pk[pk] == 2:
                                tmp = 2
                            continue
                        tmp = self.upgrade_soft(pk)
                        repaired_pk[pk] = tmp  # 修复过的包，标识上是否成功
                    if tmp == 1:
                        success.append({"result": {"status": True, "msg": "{}修复成功".format(cve), "type": [""]},
                             "m_name": "{}".format(cve)})
                    elif tmp == 2:
                        failed.append({"result": {"status": False, "msg": "{}修复失败，请关闭系统加固后再次执行修复".format(cve), "type": ["请关闭系统加固后再次修复"]},
                                        "m_name": "{}".format(cve)})
                    elif tmp == 3:
                        success.append({"result": {"status": True, "msg": "{}修复成功".format(cve),
                                                  "type": ["若漏洞依旧存在，则联系堡塔运维https://www.bt.cn/bbs发送漏洞信息"]},
                                       "m_name": "{}".format(cve)})
                except Exception as e:
                    # public.print_log("{}修复出错：{}".format(cve, e))
                    failed.append({"result": {"status": False, "msg": "{}修复失败，联系堡塔运维https://www.bt.cn/bbs发送错误信息".format(cve), "type": [e]},
                                   "m_name": "{}".format(cve)})
                new_version = self.get_dpkg_version(repair_dict[cve])
                self.one_repair_data["describe"] = "修复前版本：<br/>{}<br/>修复后版本：{}".format(old_version, new_version)
                self.one_repair_data["recover"] = "执行命令降级安装：<br/>apt-get install 【软件包】=【修复前版本】<br/>注意降级安装可能需要相关的依赖包也同时降级安装"
                all_repair_data.append(self.one_repair_data)
            # 修复完成后重新扫描
            try:
                import panelWarning
                # flage为True代表强制更新软件版本列表
                panelWarning.panelWarning().new_get_sys_product(flag=True)
            except Exception as e:
                public.print_log("修复完漏洞再次扫描失败：{}".format(e))
        # redhat系列走这里
        if RHSA_list:
            repair_dict = {}  # {RHSA: [package]}
            repaired_pk = {}  # 已修复的软件包列表，避免重复修复
            # 读取上一次首页扫描结果，获取可修复的软件包{RHSA: [package]}
            riskrisk_list = json.loads(public.ReadFile(self.__path + "/resultresult.json"))["risk"]
            for rrl in riskrisk_list:
                # 目前属于漏洞的才有type字段
                if "type" in rrl:
                    repair_dict[rrl["m_name"]] = rrl["package"]

            for RHSA in RHSA_list:
                public.set_module_logs("securityModel", "cve")
                # 初始化修复历史
                self.one_repair_data["time"] = time.time()
                self.one_repair_data["m_name"] = RHSA
                old_version = self.get_rpm_version(repair_dict[RHSA])
                bar = ("%.f" % (float(bar_num) / float(list_length) * 100))
                bar_text = {"status": "正在修复系统漏洞{}，耗时较久".format(RHSA), "percentage": bar}
                public.WriteFile(self.__path + '/repair_bar.txt', json.dumps(bar_text))
                bar_num += 1
                tmp = 1
                try:
                    for pk in repair_dict[RHSA]:
                        # 已修复的包直接跳过
                        if pk in repaired_pk:
                            # 如果前面修复失败了，标识上
                            if repaired_pk[pk] == 2:
                                tmp = 2
                            continue
                        tmp = self.upgrade_soft(pk)
                        repaired_pk[pk] = tmp  # 修复过的包
                    if tmp == 1:
                        success.append({"result": {"status": True, "msg": "{}修复成功".format(RHSA), "type": [""]},
                                        "m_name": "{}".format(RHSA)})
                    elif tmp == 2:
                        failed.append({"result": {"status": False,
                                                  "msg": "修复失败，请关闭系统加固后再次执行修复",
                                                  "type": ["请关闭系统加固后再次修复"]},
                                       "m_name": "{}".format(RHSA)})
                    elif tmp == 3:
                        success.append({"result": {"status": True,
                                                  "msg": "{}修复成功".format(RHSA),
                                                  "type": ["若漏洞依旧存在，则联系堡塔运维https://www.bt.cn/bbs发送漏洞信息"]},
                                       "m_name": "{}".format(RHSA)})
                except Exception as e:
                    # public.print_log("{}修复出错：{}".format(RHSA, e))
                    failed.append({"result": {"status": False, "msg": "修复失败，联系堡塔运维https://www.bt.cn/bbs发送错误信息", "type": [e]},
                                   "m_name": "{}".format(RHSA)})
                new_version = self.get_rpm_version(repair_dict[RHSA])
                self.one_repair_data["describe"] = "修复前版本：<br/>{}<br/>修复后版本：{}".format(old_version, new_version)
                self.one_repair_data["recover"] = "执行命令降级安装：<br/>yum downgrade 【软件包】-【修复前版本】<br/>注意降级安装可能需要相关的依赖包也同时降级安装"
                all_repair_data.append(self.one_repair_data)
            try:
                import panelWarning
                panelWarning.panelWarning().new_get_sys_product(flag=True)
            except Exception as e:
                public.print_log("修复完漏洞再次扫描失败：{}".format(e))

        # 将开发者模式修复放到最后，防止重载面板导致其他漏洞修复失败
        element_to_move = "sw_debug_mode"
        if element_to_move in m_name_list:
            m_name_list.remove(element_to_move)
            m_name_list.append(element_to_move)
        for m_name in m_name_list:
            public.set_module_logs("securityModel", "m_name")
            # 初始化修复历史
            self.one_repair_data["time"] = time.time()
            self.one_repair_data["m_name"] = m_name
            bar = ("%.f" % (float(bar_num) / float(list_length) * 100))
            bar_text = {"status": "正在修复{}".format(m_name), "percentage": bar}
            public.WriteFile(self.__path + '/repair_bar.txt', json.dumps(bar_text))
            bar_num += 1
            result = {"type": []}
            risk_file = self.__risk + '/' + m_name + '.pl'
            # 检测是否真的是风险项
            if not os.path.exists(risk_file): continue
            if m_name not in is_autofix:
                cannot_automatically.append(m_name)
                continue
            for index, value in enumerate(is_autofix):
                if m_name == value:
                    func = getattr(self, value)
                    result = func()
                    # 修复历史添加到列表
                    copy_data = self.one_repair_data.copy()
                    all_repair_data.append(copy_data)
            try:
                if "type" not in result.keys(): result["type"] = []
                r_data = {
                    "result": result,
                    "m_name": m_name
                }
                if r_data["result"]["status"]:
                    success.append(r_data)
                    continue
                else:
                    failed.append(r_data)
                    continue
            except Exception as e:
                raise public.PanelError(e)

        data["success"] = success
        data["failed"] = failed
        data["cannot_automatically"] = cannot_automatically

        public.WriteFile(self.__path + '/repair_bar.txt',
                         json.dumps({"status": "修复完成", "percentage": "100"}))  # 修复进度100
        # try:
        #     panelWarning.panelWarning()._get_list()
        # except:
        #     public.print_log("重新扫描失败")
        #     pass
        # 将修复日志写入
        if os.path.exists(self.__repair_history):
            old_hisory = json.loads(public.ReadFile(self.__repair_history))
            public.WriteFile(self.__repair_history, json.dumps(all_repair_data + old_hisory))
        else:
            public.WriteFile(self.__repair_history, json.dumps(all_repair_data))
        return data

    def sw_pip_poison(self):
        """
        pypi供应链投毒检测
        @return:
        """
        result = {"status": False, "msg": "pypi供应链投毒检测处理失败,请手动设置"}
        try:
            evil_list = public.ExecShell("btpip freeze |grep -E \"istrib|djanga|easyinstall|junkeldat|libpeshka|mumpy|mybiubiubiu|nmap-python|openvc"
                "|python-ftp|pythonkafka|python-mongo|python-mysql|python-mysqldb|python-openssl"
                "|python-sqlite|virtualnv|mateplotlib|request=\"")[0].strip().split("\n")
            self.one_repair_data["describe"] = "删除以下恶意btpython库:<br/>{}".format(' '.join(evil_list))
            self.one_repair_data["recover"] = "执行命令恢复：btpip install 【python库名】"
        except Exception as e:
            self.one_repair_data["describe"] = str(e)

        c_result = public.ExecShell(
            "piplist=`btpip freeze | grep -E "
            "\"istrib|djanga|easyinstall|junkeldat|libpeshka|mumpy|mybiubiubiu|nmap-python|openvc"
            "|python-ftp|pythonkafka|python-mongo|python-mysql|python-mysqldb|python-openssl"
            "|python-sqlite|virtualnv|mateplotlib|request=\"`;"
            "for pip in ${piplist[@]};do btpip uninstall ${pip} -y;done")
        if not c_result[1]:
            result["status"] = True
            result["msg"] = "pypi供应链投毒检测处理成功"
        return result

    def sw_docker_mod(self):
        '''
        Docker关键性文件权限检查
        @return:
        '''
        file_list = (
            "/usr/lib/systemd/system/docker.service",
            "/usr/lib/systemd/system/docker.socket",
            "/etc/docker"
        )
        result = {"status": False, "msg": "设置Docker关键性文件权限失败,请手动设置"}
        old_version = []
        new_version = []
        try:
            import pwd
            for file in file_list:
                if not os.path.exists(file):
                    continue
                stat = public.GetFileMode(file)  # 获取文件原始权限
                file_stat = os.stat(file)
                user = pwd.getpwuid(file_stat.st_uid).pw_name
                group = pwd.getpwuid(file_stat.st_gid).pw_name
                old_version.append("{} {} {} {}".format(file, stat, user, group))
                if "service" in file or "socket" in file:
                    os.chmod(file, 0o644)
                    os.chown(file, 0, 0)
                    new_version.append("{} {} {} {}".format(file, "644", "root", "root"))
                else:
                    os.chmod(file, 0o755)
                    os.chown(file, 0, 0)
                    new_version.append("{} {} {} {}".format(file, "755", "root", "root"))
            result["status"] = True
            result["msg"] = "设置Docker关键性文件权限成功"
            self.one_repair_data["describe"] = "修复前权限：<br/>{}<br/>修复后权限：<br/>{}".format('<br/>'.join(old_version),
                                                                                               '<br/>'.join(new_version))
            self.one_repair_data["recover"] = "执行命令chmod 【权限】 【文件】<br/>chown 【属主名:属组名】 【文件】"
        except:
            pass
        return result

    def sw_ftp_root(self):
        '''
        禁止root用户登录FTP
        @return:
        '''
        result = {"status": False, "msg": "设置禁止root用户登录FTP失败,请手动设置"}
        old_version = public.ExecShell("cat /www/server/pure-ftpd/etc/pure-ftpd.conf |grep MinUID")[0].strip()
        self.one_repair_data["describe"] = "【/www/server/pure-ftpd/etc/pure-ftpd.conf】<br/>修复前：{}<br/>修复后：MinUID 100".format(old_version)
        self.one_repair_data["recover"] = "修改文件【/www/server/pure-ftpd/etc/pure-ftpd.conf】里MinUID的值为修复前的内容"
        file = "/www/server/pure-ftpd/etc/pure-ftpd.conf"
        f_data = public.readFile(file)
        MinUID = "\nMinUID\\s*([0-9]{1,4})"
        file_result = re.sub(MinUID, "\nMinUID                       100", f_data)
        public.writeFile(file, file_result)
        f_data = public.readFile(file)
        if f_data.find("MinUID                       100"):
            result["status"] = True
            result["msg"] = "设置禁止root用户登录FTP成功"
        return result

    def sw_chmod_stickybit(self):
        '''
        检查临时目录是否有粘滞位
        @return:
        '''
        tmp_path = ('/var/tmp', '/tmp')
        self.one_repair_data["describe"] = "添加粘滞位chmod +t {}".format(' '.join(tmp_path))
        self.one_repair_data["recover"] = "执行命令chmod -t {}".format(' '.join(tmp_path))
        result = {"status": False, "msg": "添加临时目录粘滞位失败,请手动设置"}
        # try:
        for file in tmp_path:
            if not os.path.exists(file):
                continue
            c_result = public.ExecShell("chmod +t {}".format(file))
            if c_result[1]: return result
        result["status"] = True
        result["msg"] = "添加临时目录粘滞位成功"
        # except:
        #     pass
        return result

    def sw_telnet_server(self):
        '''
        关闭非加密远程管理telnet
        @return:
        '''
        result = {"status": False, "msg": "关闭telnet服务失败,请手动设置"}
        self.one_repair_data["describe"] = "关闭telnet服务【systemctl stop telnet.socket】"
        self.one_repair_data["recover"] = "执行命令<br/>systemctl start telnet.socket<br/>systemctl enable telnet.socket"
        public.ExecShell('systemctl stop telnet.socket')
        c_result = public.ExecShell('systemctl disable telnet.socket')
        if not c_result[1]:
            result["status"] = True
            result["msg"] = "关闭telnet服务成功"
        else:
            result["type"] = ["修复被系统加固拦截，请先关闭系统加固，修复完后再开启"]
        return result

    def sw_strace_backdoor(self):
        '''
        strace获取登录凭证后门检测
        @return:
        '''
        result = {"status": False, "msg": "停止strace进程失败,请手动设置"}
        pid = public.ExecShell("pgrep strace")[0].strip()
        cmd = public.ExecShell("ps -p {} -o cmd".format(pid))[0].strip()
        self.one_repair_data["describe"] = "终止恶意进程{}".format(cmd)
        self.one_repair_data["recover"] = "重新恢复进程{}".format(cmd)
        import psutil
        process_name = "strace"
        all_processes = psutil.process_iter()
        for process in all_processes:
            try:
                if process.name() == process_name:
                    process.terminate()
                    result["status"] = True
                    result["msg"] = "停止strace成功"
                    break
            except:
                pass
        return result

    def sw_mongodb_auth(self):
        import subprocess
        '''
        MongoDB是否开启安全认证
        @return:
        '''
        result = {"status": False, "msg": "MongoDB开启安全认证失败,请手动设置"}
        self.one_repair_data["describe"] = "开启MongoDB安全认证"
        self.one_repair_data["recover"] = "打开面板数据库-MongoDB-安全认证-关闭开关"
        try:
            __conf_path = '{}/mongodb/config.conf'.format(public.get_setup_path())
            conf = public.readFile(__conf_path)
            conf = re.sub('authorization\s*\:\s*disabled', 'authorization: enabled', conf)
            public.writeFile(__conf_path, conf)
            subprocess.Popen(["/etc/init.d/mongodb", "restart"])
            # public.ExecShell('/etc/init.d/mongodb restart')
            result["status"] = True
            result["msg"] = "MongoDB开启安全认证成功"
        except:
            pass
        return result

    def sw_system_user(self):
        '''
        系统后门用户检测
        @return:
        '''
        result = {"status": False, "msg": "系统后门用户删除失败,请手动设置"}
        cfile = '/etc/passwd'
        backdoor_user = []
        if os.path.exists(cfile):
            f = open(cfile, 'r')
            for i in f:
                i = i.strip().split(":")
                if i[2] == '0' and i[3] == '0':
                    if i[0] == 'root': continue
                    backdoor_user.append(i[0])
                    c_result = public.ExecShell("userdel -f {}".format(i[0]))
                    # public.print_log("修复结果：{}".format(c_result))
                    if not c_result[1]:
                        result["status"] = True
                        result["msg"] = "系统后门用户成功"
                    else:
                        result["type"] = ["修复被系统加固拦截，请先关闭系统加固，修复完后再开启"]
        self.one_repair_data["describe"] = "删除以下后门用户：<br/>{}".format(' '.join(backdoor_user))
        self.one_repair_data["recover"] = "重新添加用户useradd -m 【用户名】"
        return result

    def sw_debug_mode(self):
        '''
        开发者模式检测
        @return:
        '''
        self.one_repair_data["describe"] = "关闭开发者模式"
        self.one_repair_data["recover"] = "打开面板设置-开启开发者模式"
        get = public.dict_obj()
        result = self.configs.set_debug(get)
        if result["status"]: result["msg"] = "已禁用开发者模式"
        return result

    def sw_time_out(self):
        '''
        检查是否设置命令行界面超时退出
        @return:
        '''
        self.one_repair_data["describe"] = "【/etc/profile】添加命令哈超时600秒自动退出【tmout=600】"
        self.one_repair_data["recover"] = "打开文件【/etc/profile】，删除【tmout=600】"
        result = {"status": False, "msg": "设置命令行界面超时退出失败,请手动设置"}
        filename = "/etc/profile"
        w_result = public.ExecShell("echo \"tmout=600\" >> {}".format(filename))
        if not w_result[1]:
            result["status"] = True
            result["msg"] = "已设置命令行界面超时为600秒退出"
        if "Permission denied" in w_result[1] or "Operation not permitted" in w_result[1]:
            result["msg"] = "修复被系统加固拦截，请先关闭系统加固，修复完后再开启"
            result["type"] = ["修复被系统加固拦截，请先关闭系统加固，修复完后再开启"]
        return result

    def sw_chmod_sid(self):
        '''
        检查拥有suid和sgid权限的文件
        @return:
        '''
        result = {"status": True, "msg": "设置suid和sgid权限成功"}
        file_list = ['/usr/bin/chage', '/usr/bin/gpasswd', '/usr/bin/wall', '/usr/bin/chfn',
                     '/usr/bin/chsh', '/usr/bin/newgrp',
                     '/usr/bin/write', '/usr/sbin/usernetctl', '/bin/mount', '/bin/umount',
                     '/bin/ping', '/sbin/netreport']
        suid = []
        sgid = []
        suid = public.ExecShell("find {} -type f -perm /04000".format(' '.join(file_list)))[0].strip().split('\n')
        sgid = public.ExecShell("find {} -type f -perm /02000".format(' '.join(file_list)))[0].strip().split('\n')
        self.one_repair_data["describe"] = "去掉文件的suid或sgid权限：<br/>chmod u-s {}<br/>chmod g-s {}".format(' '.join(suid), ' '.join(sgid))
        self.one_repair_data["recover"] = "执行命令恢复权限：<br/>chmod u+s 【文件名】<br/>chmod g+s 【文件名】"
        s_successes_list = []
        g_successes_list = []
        s_failed_list = []
        g_failed_list = []
        try:
            for file in file_list:
                if not os.path.exists(file):
                    continue
                s_result = public.ExecShell("chmod u-s {}".format(file))
                g_result = public.ExecShell("chmod g-s {}".format(file))
                s_successes_list.append(file) if not s_result[1] else s_failed_list.append(file)
                g_successes_list.append(file) if not g_result[1] else g_failed_list.append(file)
        except:
            pass

        data = [{
            "successes": {
                "suid_success": len(s_successes_list),
                "sgid_success": len(g_successes_list)
            },
            "set_suid": s_successes_list,
            "set_sgid": g_successes_list
        }, {
            "failed": {
                "suid_failed": len(s_failed_list),
                "sgid_failed": len(g_failed_list)
            },
            "set_suid": s_failed_list,
            "set_sgid": g_failed_list
        }]
        # result["type"] = data
        return result

    def sw_ftp_umask(self):
        '''
        用户FTP访问安全配置
        @return:
        '''
        result = {"status": False, "msg": "设置用户FTP访问安全配置失败,请手动设置"}
        file = "/www/server/pure-ftpd/etc/pure-ftpd.conf"
        old_result = public.ExecShell("cat /www/server/pure-ftpd/etc/pure-ftpd.conf|grep Umask")[0].strip()
        self.one_repair_data["describe"] = "ftp访问安全配置【/www/server/pure-ftpd/etc/pure-ftpd.conf】<br/>修复前：{}<br/>修复后：Umask                       177:077".format(old_result)
        self.one_repair_data["recover"] = "打开文件【/www/server/pure-ftpd/etc/pure-ftpd.conf】修改Umask值为177:077"
        f_data = public.readFile(file)
        Umask = "\nUmask\s+.*"
        file_result = re.sub(Umask, "\nUmask                       177:077", f_data)
        public.writeFile(file, file_result)
        f_data = public.readFile(file)
        if f_data.find("177:077"):
            result["status"] = True
            result["msg"] = "用户FTP访问安全配置成功"
        return result

    def sw_ssh_v2(self):
        '''
        是否使用加密的远程管理ssh
        @return:
        '''
        result = {"status": False, "msg": "设置加密的远程管理ssh失败,请手动设置"}
        file = "/etc/ssh/sshd_config"
        self.one_repair_data["describe"] = "设置ssh使用v2加密协议【/etc/ssh/sshd_config】<br/>Protocol 2"
        self.one_repair_data["recover"] = "打开文件【/etc/ssh/sshd_config】删除【Protocol 2】即可恢复"
        f_data = public.readFile(file)
        try:
            if f_data.find("Protocol") != -1:
                Protocol = "\nProtocol\s+."
                file_result = re.sub(Protocol, "\nProtocol 2", f_data)
                public.writeFile(file, file_result)
            else:
                public.ExecShell("echo '\nProtocol 2' >> {}".format(file))
        except:
            pass
        f_data = public.readFile(file)
        if f_data.find("Protocol 2"):
            c_result = public.ExecShell("systemctl restart sshd")
            if not c_result[1]:
                result["status"] = True
                result["msg"] = "设置加密的远程管理ssh成功"
        return result

    def sw_bootloader_mod(self):
        '''
        bootloader配置权限
        @return:
        '''
        old_version = []
        new_version = []
        files = ["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"]
        result = {"status": False, "msg": "设置bootloader权限失败,请手动设置"}
        try:
            import pwd
            for file in files:
                if os.path.exists(file):
                    stat = public.GetFileMode(file)  # 获取文件原始权限
                    file_stat = os.stat(file)
                    user = pwd.getpwuid(file_stat.st_uid).pw_name
                    group = pwd.getpwuid(file_stat.st_gid).pw_name
                    old_version.append("{} {} {} {}".format(file, stat, user, group))
                    new_version.append("{} {} {} {}".format(file, "600", "root", "root"))
                    os.chmod(file, 0o600)
                    os.chown(file, 0, 0)
                    result["status"] = True
                    result["msg"] = "设置bootloader权限成功"
            self.one_repair_data["describe"] = "修复前权限：<br/>{}<br/>修复后权限：<br/>{}".format('<br/>'.join(old_version),
                                                                                               '<br/>'.join(new_version))
            self.one_repair_data["recover"] = "执行命令chmod 【权限】 【文件】<br/>chown 【属主名:属组名】 【文件】"
        except Exception as e:
            pass
        return result

    def sw_alias_ls_rm(self):
        '''
        检查别名配置
        @return:
        '''
        result = {"status": False, "msg": "设置安全别名失败,请手动设置"}
        file = "/root/.bashrc"
        self.one_repair_data["describe"] = "修改rm别名为[rm -i]"
        self.one_repair_data["recover"] = "打开文件【/root/.bashrc】，删除【alias rm='rm -i'】一行可恢复rm命令"
        # ls_result = public.ExecShell("echo \"alias ls='ls -alh'\" >> {}".format(file))
        rm_result = public.ExecShell("echo \"alias rm='rm -i'\" >> {}".format(file))
        if not rm_result[1]:
            result["status"] = True
            result["msg"] = "设置安全别名成功"
        if "Permission denied" in rm_result[1] or "Operation not permitted" in rm_result[1]:
            result["msg"] = "修复被系统加固拦截，请先关闭系统加固，修复完后再开启"
            result["type"] = ["修复被系统加固拦截，请先关闭系统加固，修复完后再开启"]
        return result

    def sw_tcp_syn_cookie(self):
        '''
        TCP-SYNcookie保护检测
        @return:
        '''
        result = {"status": False, "msg": "设置TCP-SYNcookie保护失败,请手动设置"}
        file = "/etc/sysctl.conf"
        self.one_repair_data["describe"] = "设置tcp_syncookies保护<br/>【sysctl -w net.ipv4.tcp_syncookies=1】"
        self.one_repair_data["recover"] = "打开文件【/etc/sysctl.conf】修改net.ipv4.tcp_syncookies=0<br/>再执行命令【sysctl -p】"
        public.ExecShell("sed -i \"/net.ipv4.tcp_syncookies/d\" {}".format(file))
        e_result = public.ExecShell("echo \"net.ipv4.tcp_syncookies=1\" >> {}".format(file))
        public.ExecShell("sysctl -p")
        if not e_result[1]:
            result["status"] = True
            result["msg"] = "设置TCP-SYNcookie保护成功"
        if "Permission denied" in e_result[1] or "Operation not permitted" in e_result[1]:
            result["msg"] = "修复被系统加固拦截，请先关闭系统加固，修复完后再开启"
            result["type"] = ["修复被系统加固拦截，请先关闭系统加固，修复完后再开启"]

        return result

    def sw_ping(self):
        '''
        设置禁ping
        @return:
        '''
        import firewalls
        self.one_repair_data["describe"] = "开启禁止ping"
        self.one_repair_data["recover"] = "打开面板安全-系统防火墙-关闭禁ping开关"
        firewalls = firewalls.firewalls()
        get = public.dict_obj()
        get["status"] = 0
        result = firewalls.SetPing(get)
        if result["status"]: result["msg"] = "已开启禁ping"
        else:
            result["msg"] = "修复被系统加固拦截，请先关闭系统加固，修复完后再开启"
            result["type"] = ["修复被系统加固拦截，请先关闭系统加固，修复完后再开启"]
        return result

    def sw_panel_swing(self):
        '''
        设置面板告警
        @return:
        '''
        keys_list = ("mail", "dingding", "feishu", "weixin", "wx_account", "sms")
        self.one_repair_data["describe"] = "设置面板登录告警"
        self.one_repair_data["recover"] = "打开面板设置-告警通知-告警列表-删除面板登录告警"
        get = public.dict_obj()
        result = {}
        for key in keys_list:
            get["type"] = str(key)
            result = self.configs.set_login_send(get)
            if not result["status"]: continue
            result["type"] = key
            break
        return result

    def sw_ssh_passmin(self):
        '''
        设置SSH密码修改最小时间间隔
        @return:
        '''
        old_version = public.ExecShell("cat /etc/login.defs |grep PASS_MIN_DAYS |grep -v \"#\"")[0].strip()
        self.one_repair_data["describe"] = "修改密码最小间隔时间：<br/>【/etc/login.defs】<br/>{}<br/>执行命令：chage --mindays 7 root".format(old_version)
        self.one_repair_data["recover"] = "取消修改密码最小间隔：<br/>打开文件【/etc/login.defs】，修改PASS_MIN_DAYS的值为0<br/>执行命令chage --mindays 0 root"
        file = "/etc/login.defs"
        result = {"status": False, "msg": "SSH密码修改最小间隔时间设置失败,请手动设置"}
        f_data = public.readFile(file)
        ssh_pass_min_days = "\nPASS_MIN_DAYS.+\d+"
        file_result = re.sub(ssh_pass_min_days, "\nPASS_MIN_DAYS	7", f_data)
        public.writeFile(file, file_result)
        cmd_result = public.ExecShell("chage --mindays 7 root")
        if cmd_result[1] != "":
            result["type"] = [cmd_result[1]]
            return result
        f_data = public.readFile(file)
        if f_data.find("PASS_MIN_DAYS	7") != -1:
            result["status"] = True
            result["msg"] = "已设置SSH密码修改最小间隔时间为7天"
        return result

    def sw_ssh_passmax(self):
        '''
        设置SSH密码过期时间
        @return:
        '''
        file = "/etc/login.defs"
        old_version = public.ExecShell("cat /etc/login.defs |grep PASS_MAX_DAYS |grep -v \"#\"")[0].strip()
        self.one_repair_data[
            "describe"] = "修改密码最大间隔时间：<br/>【/etc/login.defs】<br/>{}<br/>执行命令：chage --maxdays 180 root".format(
            old_version)
        self.one_repair_data[
            "recover"] = "取消修改密码最大间隔：<br/>打开文件【/etc/login.defs】，修改PASS_MIN_DAYS的值为99999<br/>执行命令chage --maxdays 99999 root"
        result = {"status": False, "msg": "SSH密码过期时间设置失败,请手动设置"}
        f_data = public.readFile(file)
        ssh_pass_max_days = "\nPASS_MAX_DAYS.+\d+"
        file_result = re.sub(ssh_pass_max_days, "\nPASS_MAX_DAYS	180", f_data)
        public.writeFile(file, file_result)
        cmd_result = public.ExecShell("chage --maxdays 180 root")
        if cmd_result[1] != "":
            result["type"] = [cmd_result[1]]
            return result
        f_data = public.readFile(file)
        if f_data.find("PASS_MAX_DAYS	180") != -1:
            result["status"] = True
            result["msg"] = "已设置SSH密码过期时间为180天"
        return result

    def sw_ssh_passwarn(self):
        '''
        SSH密码过期提前警告天数
        @return:
        '''
        file = "/etc/login.defs"
        old_version = public.ExecShell("cat /etc/login.defs |grep PASS_WARN_AGE |grep -v \"#\"")[0].strip()
        self.one_repair_data["describe"] = "设置ssh密码过期提前告警：<br/>【/etc/login.defs】<br/>{}<br/>执行命令：chage --warndays 7 root".format(
            old_version)
        self.one_repair_data[
            "recover"] = "设置ssh密码过期提前告警：<br/>打开文件【/etc/login.defs】，修改{}".format(old_version)
        result = {"status": False, "msg": "SSH密码过期提前警告天数设置失败,请手动设置"}
        f_data = public.readFile(file)
        ssh_pass_war_age = "\nPASS_WARN_AGE.+\d+"
        file_result = re.sub(ssh_pass_war_age, "\nPASS_WARN_AGE 7", f_data)
        public.writeFile(file, file_result)
        cmd_result = public.ExecShell("chage --warndays 7 root")
        if cmd_result[1] != "":
            result["type"] = [cmd_result[1]]
            return result
        f_data = public.readFile(file)
        if f_data.find("PASS_WARN_AGE 7") != -1:
            result["status"] = True
            result["msg"] = "已设置SSH密码过期提前警告天数为7天"
        return result

    def sw_ssh_security(self):
        '''
        SSH密码最小长度设置
        @return:
        '''
        file = "/etc/security/pwquality.conf"
        self.one_repair_data[
            "describe"] = "设置ssh密码最小长度：<br/>【/etc/security/pwquality.conf】<br/>minlen = 9"
        self.one_repair_data[
            "recover"] = "打开文件【/etc/security/pwquality.conf】删除minlen = 9"
        result = {"status": False, "msg": "SSH密码最小长度设置失败,请手动设置"}
        if not os.path.exists(file): public.ExecShell("apt install libpam-pwquality -y")
        if os.path.exists(file):
            f_data = public.readFile(file)
            ssh_minlen = "\n#?\s*minlen\s*=\s*\d*"
            file_result = re.sub(ssh_minlen, "\nminlen = 9", f_data)
            public.writeFile(file, file_result)
            f_data = public.readFile(file)
            if f_data.find("minlen = 9") != -1:
                result["status"] = True
                result["msg"] = "已设置SSH密码最小长度为9"
        return result

    def sw_ssh_clientalive(self):
        '''
        设置SSH空闲超时时间
        @return:
        '''
        import ssh_security
        ssh_security = ssh_security.ssh_security()
        file = "/etc/ssh/sshd_config"
        self.one_repair_data[
            "describe"] = "设置SSH空闲超时900秒退出：<br/>【/etc/ssh/sshd_config】<br/>ClientAliveInterval 900"
        self.one_repair_data[
            "recover"] = "取消方式：打开文件【/etc/ssh/sshd_config】删除ClientAliveInterval 900"
        result = {"status": False, "msg": "SSH空闲超时时间设置失败,请手动设置"}
        f_data = public.readFile(file)
        ssh_ClientAliveInterval = "\n#?ClientAliveInterval\s+\d+"
        file_result = re.sub(ssh_ClientAliveInterval, "\nClientAliveInterval 900", f_data)
        public.writeFile(file, file_result)
        ssh_security.restart_ssh()
        f_data = public.readFile(file)
        if f_data.find("ClientAliveInterval 900") != -1:
            result["status"] = True
            result["msg"] = "已设置SSH空闲超时时间为900秒"
        return result

    def sw_ssh_maxauth(self):
        '''
        设置SSH最大连接数
        @return:
        '''
        import ssh_security
        ssh_security = ssh_security.ssh_security()
        file = "/etc/ssh/sshd_config"
        self.one_repair_data[
            "describe"] = "设置SSH最大连接数为5：<br/>【/etc/ssh/sshd_config】<br/>MaxAuthTries 5"
        self.one_repair_data[
            "recover"] = "取消方式：打开文件【/etc/ssh/sshd_config】删除MaxAuthTries 5"
        result = {"status": False, "msg": "设置SSH最大连接数失败,请手动设置"}
        f_data = public.readFile(file)
        ssh_MaxAuthTries = "\n#?MaxAuthTries\s+\d+"
        file_result = re.sub(ssh_MaxAuthTries, "\nMaxAuthTries 5", f_data)
        public.writeFile(file, file_result)
        ssh_security.restart_ssh()
        f_data = public.readFile(file)
        if f_data.find("MaxAuthTries 5") != -1:
            result["status"] = True
            result["msg"] = "已设置SSH最大连接数为5"
        return result

    def sw_ssh_notpass(self):
        '''
        禁止SSH空密码登录
        @return:
        '''
        import ssh_security
        ssh_security = ssh_security.ssh_security()
        file = "/etc/ssh/sshd_config"
        self.one_repair_data[
            "describe"] = "设置禁止SSH空密码登录：<br/>【/etc/ssh/sshd_config】<br/>PermitEmptyPasswords no"
        self.one_repair_data[
            "recover"] = "取消方式：打开文件【/etc/ssh/sshd_config】将PermitEmptyPasswords no改为yes"
        result = {"status": False, "msg": "SSH禁止空密码登录设置失败,请手动设置"}
        f_data = public.readFile(file)
        ssh_PermitEmptyPasswords = "\n#?PermitEmptyPasswords\s+yes"
        file_result = re.sub(ssh_PermitEmptyPasswords, "\nPermitEmptyPasswords no", f_data)
        public.writeFile(file, file_result)
        ssh_security.restart_ssh()
        f_data = public.readFile(file)
        if f_data.find("PermitEmptyPasswords no") != -1:
            result["status"] = True
            result["msg"] = "SSH禁止空密码登录成功"
        return result

    def sw_panel_control(self):
        '''
        开启面板监控
        @return:
        '''
        get = public.dict_obj()
        self.one_repair_data["describe"] = "打开面板监控功能"
        self.one_repair_data["recover"] = "取消方式：打开面板-监控-关闭监控开关"
        get["type"] = "1"
        get["day"] = "30"
        result = {"status": False, "msg": "面板监控开启失败,请手动设置"}
        r_data = self.configs.SetControl(get)
        if r_data["status"]:
            result["status"] = True
            result["msg"] = "面板监控开启成功"
            result["type"] = get["day"]
        return result

    def sw_cve_2021_4034(self):
        '''
        修复CVE-2021-4034 polkit pkexec 本地提权漏洞
        @return:
        '''
        old_version = self.get_rpm_version(["polkit"])
        result = {"status": False, "msg": "polkit_pkexec本地提权漏洞修复失败,请手动修复"}
        py_path = "/www/server/panel/pyenv/bin/python3"
        script_path = "/www/server/panel/script/polkit_upgrade.py"
        if os.path.exists(script_path):
            c_result = public.ExecShell("{} {}".format(py_path, script_path))
            if c_result[1] == "":
                result["status"] = True
                result["msg"] = "polkit_pkexec本地提权漏洞修复成功"
            else:
                result["type"] = c_result[1]
        new_version = self.get_rpm_version(["polkit"])
        self.one_repair_data["describe"] = "修复polkit本地提权漏洞：<br/>修复前版本：{}<br/>修复后版本：{}".format(old_version, new_version)
        self.one_repair_data["recover"] = "执行命令降级安装：yum downgrade polkit-【修复前版本】"
        return result

    def sw_php_expose(self):
        '''
        关闭php版本泄露配置
        @return:
        '''
        path = "/www/server/php"
        expose_list = []
        dirs = os.listdir(path)
        result = {"status": True, "msg": "关闭php版本显示成功", "type": []}
        for dir in dirs:
            if dir in ("52", "53", "54", "55", "56", "70", "71", "72", "73", "74", "80", "81", "82"):
                file_path = path + "/" + dir + "/etc/php.ini"
                if os.path.exists(file_path):
                    expose_list.append(dir)
                    php_ini = public.readFile(file_path)
                    r_str = "\nexpose_php\\s*=\\s*(\\w+)"
                    r_result = re.sub(r_str, "\nexpose_php = off", php_ini)
                    public.writeFile(file_path, r_result)
                    f_data = public.readFile(file_path)
                    if f_data.find("expose_php = off") != -1:
                        public.phpReload(str(dir))
                        result["type"].append(dir)
        if len(result["type"]) < 1:
            result["status"] = False
            result["msg"] = "关闭php版本显示失败或无需要关闭的php版本,请手动设置"
            result["type"] = ["修复被系统加固拦截，请先关闭系统加固，修复完后再开启"]
        self.one_repair_data["describe"] = "关闭以下PHP版本泄露配置：<br/>{}".format('、'.join(expose_list))
        self.one_repair_data["recover"] = "取消关闭php版本泄露：<br/>打开面板软件商店-运行环境-对应PHP配置文件，找到【expose_php】改为On"
        return result

    def sw_files_recycle_bin(self):
        get = public.dict_obj()
        self.one_repair_data["describe"] = "开启文件回收站功能"
        self.one_repair_data["recover"] = "打开面板文件-回收站-关闭文件回收站开关"
        import files
        files = files.files()
        os.system("rm -rf /www/server/panel/data/recycle_bin.pl")
        if not os.path.exists('/www/server/panel/data/recycle_bin.pl'):
            return files.Recycle_bin(get)

    def sw_kernel_space(self):
        result = {"status": False, "msg": "开启地址空间布局随机化失败,请手动设置"}
        old_version = public.ReadFile("/proc/sys/kernel/randomize_va_space").strip()
        self.one_repair_data["describe"] = "开启地址空间布局随机化：<br/>【/proc/sys/kernel/randomize_va_space】<br/>{}".format(old_version)
        self.one_repair_data["recover"] = "关闭方式：<br/>打开文件【/proc/sys/kernel/randomize_va_space】，修改内容为{}<br/>执行命令：sysctl -w kernel.randomize_va_space={}".format(old_version, old_version)
        file = "/proc/sys/kernel/randomize_va_space"
        if os.path.exists(file):
            c_result = public.ExecShell("echo 2 > {}".format(file))
            if c_result[1] == "":
                result["status"] = True
                result["msg"] = "已开启地址空间布局随机化"
            else:
                result["type"] = [c_result[1]]
        public.ExecShell("sysctl -w kernel.randomize_va_space=2")
        return result

    def sw_httpd_version_leak(self):
        '''
        Apache 版本泄露
        @return:
        '''
        result = {"status": False, "msg": "Apache 版本泄露修复失败,请手动设置"}
        conf = "/www/server/apache/conf/httpd.conf"
        self.one_repair_data["describe"] = "关闭Apache版本泄露配置"
        self.one_repair_data["recover"] = "取消方式：<br/>打开文件【/www/server/apache/conf/httpd.conf】<br/>设置ServerSignature为on<br/>删除ServerTokens Prod<br/>最后重启apache"
        if os.path.exists(conf):
            try:
                info_data = public.ReadFile(conf)
                if info_data:
                    if not re.search('ServerSignature', info_data) and not re.search(
                            'ServerTokens', info_data):
                        result["status"] = True
                        result["msg"] = "Apache 版本泄露修复成功"
                        return result
                    ServerSignature = "\n\s*ServerSignature\s*on\s*;"
                    ServerTokens = "\n\s*ServerTokens\s*.\s*;"
                    file_result1 = re.sub(ServerSignature, "\nServerSignature Off", info_data)
                    file_result2 = re.sub(ServerTokens, "\nServerTokens Prod", file_result1)
                    public.writeFile(conf, file_result2)
                    if re.search('ServerSignature Off', info_data) and re.search(
                            'ServerTokens Prod', info_data):
                        result["status"] = True
                        result["msg"] = "Apache 版本泄露修复成功"
                        return result
                    else:
                        result["type"] = ["修复被系统加固拦截，请先关闭系统加固，修复完后再开启"]
            except:
                return result
        return result

    def sw_nginx_server(self):
        '''
        关闭Nginx版本显示
        @return:
        '''
        file = "/www/server/nginx/conf/nginx.conf"
        result = {"status": False, "msg": "关闭nginx版本显示失败,请手动设置"}
        self.one_repair_data["describe"] = "关闭闭Nginx版本显示"
        self.one_repair_data["recover"] = "取消方式：<br/>打开文件【/www/server/nginx/conf/nginx.conf】<br/>修改server_tokens off为on<br/>最后重启nginx"
        if os.path.exists(file):
            f_data = public.readFile(file)
            nginx_server_tokens = "\n\s*server_tokens\s*on\s*;"
            file_result = re.sub(nginx_server_tokens, "\n        server_tokens off;", f_data)
            public.writeFile(file, file_result)
            f_data = public.readFile(file)
            public.ServiceReload()
            if f_data.find("        server_tokens off;") != -1:
                result["status"] = True
                result["msg"] = "关闭nginx版本显示成功"
            else:
                result["type"] = ["修复被系统加固拦截，请先关闭系统加固，修复完后再开启"]
        return result

    def sw_site_spath(self):
        '''
        开启指定网站防跨站攻击
        @return:
        '''
        def SetUserINI():
            result = {"status": True, "msg": "指定网站防跨站攻击开启成功", "type": []}
            import panelSite
            get = public.dict_obj()
            panelSite = panelSite.panelSite()
            site_list = public.M('sites').where('status=? AND project_type=?', (1, 'PHP')).field(
                'name,path,id').select()
            for s in site_list:
                path = get_site_run_path(s['name'], s['path'])
                get["path"] = s['path']
                get["id"] = s["id"]
                filename = path + '/.user.ini'
                if os.path.exists(filename): continue
                u_result = panelSite.SetDirUserINI(get)
                if not u_result["status"]:
                    result["status"] = False
                    result["msg"] = "指定网站防跨站攻击开启失败,请手动设置"
                    return result
                if u_result["status"]:
                    result["type"].append(s['name'])
            if len(result["type"]) < 1:
                result["status"] = False
                result["msg"] = "指定网站防跨站攻击开启失败,请手动设置"
            return result

        def get_site_run_path(siteName, sitePath):
            '''
                @name 获取网站运行目录
                @author hwliang<2020-08-05>
                @param siteName(string) 网站名称
                @param sitePath(string) 网站根目录
                @return string
            '''
            setupPath = '/www/server'
            webserver_type = public.get_webserver()
            path = None
            if webserver_type == 'nginx':
                filename = setupPath + '/panel/vhost/nginx/' + siteName + '.conf'
                if os.path.exists(filename):
                    conf = public.readFile(filename)
                    rep = r'\s*root\s+(.+);'
                    tmp1 = re.search(rep, conf)
                    if tmp1: path = tmp1.groups()[0]

            elif webserver_type == 'apache':
                filename = setupPath + '/panel/vhost/apache/' + siteName + '.conf'
                if os.path.exists(filename):
                    conf = public.readFile(filename)
                    rep = r'\s*DocumentRoot\s*"(.+)"\s*\n'
                    tmp1 = re.search(rep, conf)
                    if tmp1: path = tmp1.groups()[0]
            else:
                filename = setupPath + '/panel/vhost/openlitespeed/' + siteName + '.conf'
                if os.path.exists(filename):
                    conf = public.readFile(filename)
                    rep = r"vhRoot\s*(.*)"
                    path = re.search(rep, conf)
                    if not path:
                        path = None
                    else:
                        path = path.groups()[0]

            if not path:
                path = sitePath

            return path
        self.one_repair_data["describe"] = "开启网站防跨站攻击"
        self.one_repair_data["recover"] = "恢复方式：打开面板网站-网站设置-网站目录-关闭防跨站攻击开关"
        return SetUserINI()

    def sw_php_display_errors(self):
        '''
        关闭PHP的错误信息提示选项
        @author lwh<2023-08-09>
        @return:
        '''
        error_list = []
        path = "/www/server/php"
        # 获取目录下的文件夹
        dirs = os.listdir(path)
        fail_list = []
        for dir in dirs:
            if dir in ["52", "53", "54", "55", "56", "70", "71", "72", "73", "74", "80", "81"]:
                file_path = path + "/" + dir + "/etc/php.ini"
                if os.path.exists(file_path):
                    # 获取文件内容
                    try:
                        php_ini = public.readFile(file_path)
                        rep = "\ndisplay_errors\\s?=\\s?(.+)"
                        if re.search(rep, php_ini):
                            status = re.findall(rep, php_ini)
                            if 'On' in status or 'on' in status:
                                error_list.append(dir)
                                new = re.sub("\ndisplay_errors\\s?=\\s?(.+)", "\ndisplay_errors = Off", php_ini)
                                public.writeFile(file_path, new)
                                public.phpReload(str(dir))  # 重启指定PHP
                    except:
                        fail_list.append(dir)
        self.one_repair_data["describe"] = "修复以下PHP版本错误信息泄露：{}".format('、'.join(error_list))
        self.one_repair_data["recover"] = "恢复方式：<br/>打开面板-软件商店-运行环境-对应PHP-配置修改-开启display_errors选项"
        if fail_list:
            return {"status": False, "msg": "【PHP配置文件{}】关闭错误提示失败".format('、'.join(fail_list)), "type": ["修复被系统加固拦截，请先关闭系统加固，修复完后再开启"]}
        else:
            return {"status": True, "msg": "关闭PHP错误信息提示成功"}

    def sw_php_backdoor(self):
        '''
        清除php.ini挂马
        @author lwh<2023-08-09>
        @return:
        '''
        path = "/www/server/php"
        # 获取目录下的文件夹
        dirs = os.listdir(path)
        fail_list = []  # 失败列表
        repair_list = []  #记录修复历史
        for dir in dirs:
            if dir in ["52", "53", "54", "55", "56", "70", "71", "72", "73", "74", "80", "81"]:
                file_path = path + "/" + dir + "/etc/php.ini"
                if os.path.exists(file_path):
                    # 获取文件内容
                    try:
                        tmp = 0  # 是否存在挂马判断
                        php_ini = public.readFile(file_path)
                        rep1 = "\nauto_prepend_file\\s?=\\s?(.+)"
                        if re.search(rep1, php_ini):
                            prepend = re.findall(rep1, php_ini)
                            if "data:;base64" in prepend[0]:
                                php_ini = re.sub(rep1, "\nauto_prepend_file =", php_ini)
                                public.WriteFile(file_path, php_ini)
                                tmp = 1
                        rep2 = "\nauto_append_file\\s?=\\s?(.+)"
                        if re.search(rep2, php_ini):
                            append = re.findall(rep2, php_ini)
                            if "data:;base64" in append[0]:
                                repair_list.append("php版本：{};内容：{}".format(dir, append[0]))
                                new = re.sub(rep2, "\nauto_append_file =", php_ini)
                                public.WriteFile(file_path, new)
                                tmp = 1
                        if tmp:
                            public.phpReload(str(dir))
                    except:
                        fail_list.append(dir)
        self.one_repair_data["describe"] = "清除以下php版本配置文件挂马：<br/>{}".format('<br/>'.join(repair_list))
        self.one_repair_data["recover"] = "打开面板软件商店-运行环境-对应php版本-配置文件<br/>在auto_append_file=或auto_prepend_file=后面重新添加内容"
        if fail_list:
            return {"status": False, "msg": "【PHP配置文件{}】清除挂马失败".format('、'.join(fail_list)), "type": ["修复被系统加固拦截，请先关闭系统加固，修复完后再开启"]}
        else:
            return {"status": True, "msg": "清除PHP配置文件挂马成功"}

    def sw_httpd_trace_enable(self):
        '''
        Apache TRACE请求
        @return:
        '''
        result = {"status": False, "msg": "Apache 关闭TRACE请求修复失败,请手动设置"}
        path = '/www/server/apache/conf/httpd.conf'
        if os.path.exists(path):
            try:
                rep1 = "[\s]+(?!#)[\s]*TraceEnable[\s]+(.+).*"
                output = public.ReadFile(path)
                if re.search(rep1, output):
                    tmp = re.findall(rep1, output)
                    if "on" in tmp[0]:
                        httpd_conf = re.sub(rep1, "\nTraceEnable off", output)
                        public.WriteFile(path, httpd_conf)
                else:
                    with open(path, 'a+') as file:
                        file.write("TraceEnable off \n")
            except:
                return {"status": False, "msg": "关闭Apache Trace请求失败", "type": ["修复被系统加固拦截，请先关闭系统加固，修复完后再开启"]}
        self.one_repair_data["describe"] = "关闭Apache TRACE请求配置"
        self.one_repair_data["recover"] = "恢复方式：<br/>打开文件【/www/server/apache/conf/httpd.conf】<br/>修改TraceEnable off为on"
        return {"status": True, "msg": "关闭Apache Trace请求成功"}

    def sw_nginx_malware(self):
        '''
        @name nginx 配置文件挂马检测
        @author lwh<2023-11-22>
        '''
        path = '/www/server/panel/vhost/nginx/'
        fail_file = []
        nginx_malwares = []  # 存在挂马的内容
        import glob
        rep1 = "[\s]+sub_filter[\s]+.*"
        for filename in glob.glob(os.path.join(path, '*.conf')):
            try:
                if os.path.isdir(filename):
                    continue
                output = public.ReadFile(filename)
                if re.search(rep1, output):
                    tmp = re.findall(rep1, output)
                    if "<script" in tmp[0]:
                        nginx_malwares.append("文件：{}；内容：{}".format(filename, tmp[0]))
                        nginx_conf = re.sub(rep1, "", output)
                        public.writeFile(filename, nginx_conf)
            except:
                fail_file.append(filename)
                continue
        if len(fail_file) > 0:
            return {"status": False, "msg": "以下文件清除nginx配置挂马内容失败：".format('、'.join(fail_file)), "type": ["请先关闭系统加固，修复完后再开启"]}
        self.one_repair_data["describe"] = "清除以下nginx文件挂马：<br/>{}".format('<br/>'.format(nginx_malwares))
        self.one_repair_data["recover"] = "打开被清除的nginx文件，重新添加对应内容"
        return {"status": True, "msg": "清除挂马内容成功"}

    def sw_protected_hardlinks(self):
        '''
        @name 内核参数硬链接保护开启
        @author lwh<2023-11-22>
        '''
        old_version = public.ReadFile("/proc/sys/fs/protected_hardlinks").strip()
        try:
            if os.path.exists("/proc/sys/fs/protected_hardlinks"):
                protected_hardlinks = public.ReadFile("/proc/sys/fs/protected_hardlinks")
                if int(protected_hardlinks) != 1:
                    output, err = public.ExecShell("sysctl -w fs.protected_hardlinks=1")
                    if err == "":
                        return {"status": True, "msg": "开启硬链接保护成功"}
        except:
            return {"status": False, "msg": "开启硬链接保护失败", "type": ["请先关闭系统加固，修复完后再开启"]}
        self.one_repair_data["describe"] = "修复内核参数硬链接保护：<br/>【/proc/sys/fs/protected_hardlinks】{}改为1".format(old_version)
        self.one_repair_data["recover"] = "执行命令：【echo {} > /proc/sys/fs/protected_hardlinks】<br/>【sysctl -w fs.protected_hardlinks={}】".format(old_version, old_version)
        return {"status": False, "msg": "开启硬链接保护失败", "type": ["请先关闭系统加固，修复完后再开启"]}

    def sw_protected_symlinks(self):
        '''
        @name 内核参数软链接保护开启
        @author lwh<2023-11-22>
        '''
        old_version = public.ReadFile("/proc/sys/fs/protected_symlinks").strip()
        try:
            if os.path.exists("/proc/sys/fs/protected_symlinks"):
                protected_hardlinks = public.ReadFile("/proc/sys/fs/protected_symlinks")
                if int(protected_hardlinks) != 1:
                    output, err = public.ExecShell("sysctl -w fs.protected_symlinks=1")
                    if err == "":
                        return {"status": True, "msg": "开启软链接保护成功"}
        except:
            return {"status": False, "msg": "开启软链接保护失败", "type": ["请先关闭系统加固，修复完后再开启"]}
        self.one_repair_data[
            "describe"] = "修复内核参数软链接保护：<br/>【/proc/sys/fs/protected_symlinks】{}改为1".format(old_version)
        self.one_repair_data[
            "recover"] = "执行命令：【echo {} > /proc/sys/fs/protected_symlinks】<br/>【sysctl -w fs.protected_symlinks={}】".format(
            old_version, old_version)
        return {"status": False, "msg": "开启软链接保护失败", "type": ["请先关闭系统加固，修复完后再开启"]}

    def sw_ssh_login_grace(self):
        '''
        @name ssh登录超时配置
        @author lwh<2023-11-22>
        '''
        path = '/etc/ssh/sshd_config'
        if os.path.exists(path):
            try:
                output = public.ReadFile(path)
                rep = "[\s]+(?!#)[\s]*LoginGraceTime[\s].*"
                if not re.search(rep, output):
                    with open(path, 'a+') as file:
                        file.write("LoginGraceTime 60\n")
                    result, err = public.ExecShell("systemctl restart sshd")
                    if err != "":
                        return {"status": False, "msg": "添加ssh登录超时配置失败", "type": ["请先关闭系统加固，修复完后再开启"]}
                    return {"status": True, "msg": "添加ssh登录超时配置成功"}
            except:
                return {"status": False, "msg": "添加ssh登录超时配置失败", "type": ["请先关闭系统加固，修复完后再开启"]}
        self.one_repair_data["describe"] = "添加ssh登录超时60秒配置"
        self.one_repair_data["recover"] = "打开文件【/etc/ssh/sshd_config】删除LoginGraceTime 60<br/>并执行命令重启ssh服务systemctl restart sshd"
        return {"status": False, "msg": "添加ssh登录超时配置失败", "type": ["请先关闭系统加固，修复完后再开启"]}

    def sw_sudoers_nopasswd(self):
        '''
        @name 空密码sudo提权
        @author lwh<2023-11-22>
        '''
        import glob
        fail_file = []
        sudo_file = "/etc/sudoers"
        sudo_dir = "/etc/sudoers.d/"
        repair_sudofile = []
        rep = ".*[\s]+NOPASSWD[\s]*\:.*"
        if os.path.exists(sudo_file):
            try:
                output1 = public.readFile(sudo_file)
                if re.search(rep, output1):
                    tmp = re.findall(rep, output1)
                    if "#" not in tmp[0]:
                        repair_sudofile.append("文件：{}；内容：{}".format(sudo_file, tmp[0]))
                        new_sudo_conf = re.sub(rep, "", output1)
                        public.WriteFile(sudo_file, new_sudo_conf)
            except:
                fail_file.append(sudo_file)
        for filename in glob.glob(os.path.join(sudo_dir, '*')):
            try:
                output = public.ReadFile(filename)
                if re.search(rep, output):
                    tmp = re.findall(rep, output)
                    if '#' not in tmp[0]:
                        repair_sudofile.append("文件：{}；内容：{}".format(filename, tmp[0]))
                        new_sudo_conf = re.sub(rep, "", output)
                        public.WriteFile(filename, new_sudo_conf)
            except:
                fail_file.append(filename)
        if len(fail_file) > 0:
            return {"status": False, "msg": "以下文件关闭空密码sudo提权失败：".format('、'.join(fail_file)), "type": ["请先关闭系统加固，修复完后再开启"]}
        self.one_repair_data["describe"] = "清除以下文件空密码提权：<br/>{}".format('<br/>'.join(repair_sudofile))
        self.one_repair_data["recover"] = "打开sudo文件，重新添加对应内容"
        return {"status": True, "msg": "关闭空密码sudo提权成功"}

    def sw_suid_dumpable(self):
        '''
        @name 内核参数核心转储关闭
        @author lwh<2023-11-22>
        '''
        try:
            if os.path.exists("/proc/sys/fs/suid_dumpable"):
                suid_dumpable = public.ReadFile("/proc/sys/fs/suid_dumpable")
                if int(suid_dumpable) != 0:
                    output, err = public.ExecShell("sysctl -w fs.suid_dumpable=0")
                    if err == "":
                        return {"status": True, "msg": "限制核心转储成功"}
        except:
            return {"status": False, "msg": "限制核心转储失败", "type": ["请先关闭系统加固，修复完后再开启"]}
        self.one_repair_data["describe"] = "关闭内核参数核心转储：<br/>【/proc/sys/fs/suid_dumpable】改为0"
        self.one_repair_data["recover"] = "执行命令：【echo 1 > /proc/sys/fs/suid_dumpable】<br/>【sysctl -w fs.suid_dumpable=1】"
        return {"status": False, "msg": "限制核心转储失败", "type": ["请先关闭系统加固，修复完后再开启"]}

    def sw_tmp_malware(self):
        '''
        @name /var/tmp目录恶意木马
        @author lwh<2023-11-22>
        '''
        malware_file = []
        fail_list = []
        list1 = ['/var/tmp/systemd-private-56d86f7d8382402517f3b51625789161d2cb-chronyd.service-jP37av',
                 '/var/tmp/systemd-private-56d86f7d8382402517f3b5-jP37av',
                 '/tmp/systemd-private-56d86f7d8382402517f3b5-jP37av', '/var/tmp/count', '/var/tmp/count.txt',
                 '/var/tmp/backkk', '/var/tmp/msglog.txt']
        for filename in list1:
            try:
                if not os.path.exists(filename):
                    continue
                if os.path.isdir(filename):
                    continue
                output, err = public.ExecShell("rm -rf {}".format(filename))
                malware_file.append(filename)
                if err != '':
                    fail_list.append(filename)
            except:
                fail_list.append(filename)
        if len(fail_list) > 0:
            return {"status": False, "msg": "删除恶意木马文件失败"}
        self.one_repair_data["describe"] = "删除以下恶意木马文件{}".format('、'.join(malware_file))
        self.one_repair_data["recover"] = "恶意木马文件无法恢复"
        return {"status": True, "msg": "删除恶意木马文件成功"}

    def sw_firewall_open(self):
        """
        @name 开启防火墙开关
        """
        result = {"status": False, "msg": "开启系统防火墙失败，请检查是否被系统加固拦截，并关闭系统加固"}
        from safeModel import firewallModel
        get = public.dict_obj()
        get.status = "start"
        obj = firewallModel.main()
        fire = obj.firewall_admin(get)
        if fire["status"]:
            result = {"status": True, "msg": "开启系统防火墙成功"}
            self.one_repair_data["describe"] = "启动系统防火墙"
            self.one_repair_data["recover"] = "打开面板-安全-系统防火墙-关闭防火墙开关"
        return result

    def sw_php_disable_functions(self):
        """
        @name 禁用PHP危险函数
        """
        result = {"status": True, "msg": "禁用PHP危险函数成功"}
        path = "/www/server/php"
        repair_list = []  # 修复历史
        # 获取目录下的文件夹
        dirs = os.listdir(path)
        fail_list = []
        disa_fun = ["system", "exec", "passthru", "shell_exec", "popen", "proc_open", "putenv"]
        for dir in dirs:
            if dir in ["52", "53", "54", "55", "56", "70", "71", "72", "73", "74", "80", "81"]:
                file_path = path + "/" + dir + "/etc/php.ini"
                if os.path.exists(file_path):
                    # 获取文件内容
                    try:
                        php_ini = public.readFile(file_path)
                        if re.search("\ndisable_functions\\s?=\\s?(.+)", php_ini):
                            disable_functions = re.findall("\ndisable_functions\\s?=\\s?(.+)", php_ini)
                            if len(disable_functions) > 0:
                                disable_functions = disable_functions[0].split(",")
                                new_disable_functions = disable_functions[0]
                                for i2 in disa_fun:
                                    if i2 not in disable_functions:
                                        # 添加禁止函数
                                        new_disable_functions = new_disable_functions + "," + i2
                                        repair_list.append("php版本：{}；禁用函数：{}".format(dir, i2))
                                # 替换文本
                                r_result = re.sub(disable_functions[0], new_disable_functions, php_ini)
                                if not public.writeFile(file_path, r_result):
                                    fail_list.append(file_path)
                    except:
                        fail_list.append(file_path)
                        pass
        if len(fail_list) > 0:
            return {"status": False, "msg": "以下PHP文件修复失败，请检查是否被系统加固拦截，并关闭系统加固后再尝试修复：<br/>{}".format('<br/>'.join(fail_list))}
        self.one_repair_data["describe"] = "禁用以下PHP版本的危险函数：{}".format('<br/>'.join(repair_list))
        self.one_repair_data["recover"] = "恢复方式：打开面板-软件商店-运行环境-对应PHP管理-禁用函数-删除被禁用的函数"
        return result

    def sw_ssh_minclass(self):
        """
        @name SSH密码复杂度检查
        @author lwh<2024-02-22>
        """
        file = "/etc/security/pwquality.conf"
        self.one_repair_data[
            "describe"] = "设置ssh密码最小复杂度为3：<br/>【/etc/security/pwquality.conf】<br/>minclass = 3"
        self.one_repair_data[
            "recover"] = "打开文件【/etc/security/pwquality.conf】删除minclass = 3"
        result = {"status": False, "msg": "SSH密码最小长度设置失败,请关闭系统加固或手动设置"}
        if not os.path.exists(file): public.ExecShell("apt install libpam-pwquality -y")
        if os.path.exists(file):
            f_data = public.readFile(file)
            if re.findall("\n\s*minclass\s*=\s*\d*", f_data):
                file_result = re.sub("\n\s*minclass\s*=\s*\d*", "\nminclass = 3", f_data)
            else:
                file_result = f_data + "\nminclass = 3"
            public.writeFile(file, file_result)
            f_data = public.readFile(file)
            if f_data.find("minclass = 3") != -1:
                result["status"] = True
                result["msg"] = "已设置ssh密码最小复杂度"
        return result

    def sw_ftp_login(self):
        """
        @name ftp禁止匿名用户登录
        @author lwh<2024-02-22>
        """
        file = "/www/server/pure-ftpd/etc/pure-ftpd.conf"
        self.one_repair_data[
            "describe"] = "设置ftp禁止匿名用户登录：<br/>【/www/server/pure-ftpd/etc/pure-ftpd.conf】<br/>NoAnonymous                 yes"
        self.one_repair_data[
            "recover"] = "打开文件【/www/server/pure-ftpd/etc/pure-ftpd.conf】修改NoAnonymous yes为no"
        result = {"status": False, "msg": "设置ftp禁止匿名用户登录失败，请关闭系统加固，或手动设置"}
        if os.path.exists(file):
            f_data = public.readFile(file)
            if re.findall("\n\s*NoAnonymous\s*no", f_data):
                file_result = re.sub("\n\s*NoAnonymous\s*no", "\nNoAnonymous                 yes", f_data)
            else:
                file_result = f_data + "\nNoAnonymous                 yes"
            public.writeFile(file, file_result)
            f_data = public.readFile(file)
            if f_data.find("NoAnonymous                 yes") != -1:
                result["status"] = True
                result["msg"] = "设置ftp禁止匿名用户登录成功"
        return result

    def sw_passwd_repeat(self):
        """
        @name 设置限制密码重复使用次数
        """
        result = {"status": False, "msg": "设置限制密码重复使用次数失败，请关闭系统加固或联系运维"}
        cfile = '/etc/pam.d/system-auth'
        if os.path.exists(cfile):
            conf = public.ReadFile(cfile)
            try:
                rep = "\n\s*password\s*sufficient\s*pam_unix.so.*"
                tmp = re.findall(rep, conf)
                if tmp[0]:
                    c_result = re.sub(tmp[0], tmp[0]+" remember=3", conf)
                    public.WriteFile(cfile, c_result)
                    result = {"status": True, "msg": "设置限制密码重复使用次数成功"}
                    self.one_repair_data[
                        "describe"] = "设置用户不能重复使用最近3次内已使用的密码：<br/>【/etc/pam.d/system-auth】<br/>remember=3"
                    self.one_repair_data["recover"] = "打开文件【/etc/pam.d/system-auth】删除remember=3后重启服务器生效"
            except:
                return result
        return result

    def sw_su_root(self):
        """
        @name 禁止非wheel组用户切换至root
        """
        cfile = '/etc/pam.d/su'
        conf = public.readFile(cfile)
        rep1 = '\n\s*auth\s*sufficient\s*pam_rootok.so'
        tmp1 = re.search(rep1, conf)
        if tmp1:
            rep2 = '\n\s*auth\s*required\s*pam_wheel.so'
            tmp2 = re.search(rep2, conf)
            if not tmp2:
                try:
                    public.ExecShell("echo \"auth       required   pam_wheel.so\" >> {}".format(cfile))
                    self.one_repair_data[
                        "describe"] = "设置用户不能重复使用最近3次内已使用的密码：<br/>【/etc/pam.d/system-auth】<br/>remember=3"
                    self.one_repair_data["recover"] = "打开文件【/etc/pam.d/system-auth】删除remember=3后重启服务器"
                except Exception as e:
                    return {"status": False, "msg": "设置限制密码重复使用次数失败，请关闭系统加固或联系运维协助修复"}
        return {"status": True, "msg": "设置限制密码重复使用次数成功"}

    def sw_php_url_include(self):
        """
        @name 关闭php远程包含
        @author lwh<2024-02-23>
        """
        path = "/www/server/php"
        # 获取目录下的文件夹
        dirs = os.listdir(path)
        repair_resulit = []
        for dir in dirs:
            if dir in ["52", "53", "54", "55", "56", "70", "71", "72", "73", "74", "80", "81"]:
                file_path = path + "/" + dir + "/etc/php.ini"
                if os.path.exists(file_path):
                    # 获取文件内容
                    try:
                        php_ini = public.readFile(file_path)
                        # 查找include
                        if re.search("\nallow_url_include\\s*=\\s*(\\w+)", php_ini):
                            new_php = re.sub("\nallow_url_include\\s*=\\s*(\\w+)", "\nallow_url_include = Off", php_ini)
                            tmp = public.WriteFile(file_path, new_php)
                            repair_resulit.append(dir)
                            if not tmp:
                                return {"status": False, "msg": "修复失败，请临时关闭系统加固，等修复完成后再开启"}
                    except:
                        pass
        self.one_repair_data["describe"] = "修复以下php远程包含风险：<br>{}".format('、'.join(repair_resulit))
        self.one_repair_data["recover"] = "打开面板软件商店-运行环境-对应php管理器-配置文件-修改allow_url_include = On"
        return {"status": True, "msg": "修复远程包含风险成功"}

    # 取系统版本
    def get_sys_version(self):
        '''
        获取当前系统版本
        :return: string
        '''
        sys_version = "None"
        if os.path.exists("/etc/redhat-release"):
            result = public.ReadFile("/etc/redhat-release")
            if "CentOS Linux release 7" in result:
                sys_version = "centos_7"
            elif "CentOS Linux release 8" in result or "CentOS Stream release 8" in result:
                sys_version = "centos_8"
            elif result.find("Alibaba Cloud Linux release 3") != -1:
                sys_version = "alicloud_3"
            elif result.find("Alibaba Cloud Linux (Aliyun Linux) release 2") != -1:
                sys_version = "alicloud_2"
        elif os.path.exists("/etc/lsb-release"):
            if "Ubuntu 20.04" in public.ReadFile("/etc/lsb-release"):
                sys_version = "ubuntu_20.04"
            elif "Ubuntu 22.04" in public.ReadFile("/etc/lsb-release"):
                sys_version = "ubuntu_22.04"
            elif "Ubuntu 18.04" in public.ReadFile("/etc/lsb-release"):
                sys_version = "ubuntu_18.04"
        elif os.path.exists("/etc/debian_version"):
            result = public.ReadFile("/etc/debian_version")
            if "10." in result:
                sys_version = "debian_10"
            elif "11." in result:
                sys_version = "debian_11"
            elif "12." in result:
                sys_version = "debian_12"
        return sys_version

    def upgrade_soft(self, soft):
        '''
        升级软件包
        :param soft: 软件包名
        :return: int 1为成功，2为关闭系统加固，3为无法升级
        '''
        error_message = ['Error', 'Operation not permitted']
        nothing_message = ['Couldn\'t find', 'Nothing to do', 'already the newest', 'Nothing to do.']
        # sys_version = self.get_sys_version()
        result = ''
        err = ''
        if "centos" in self.sys_version:
            # public.ExecShell('yum update -y '+soft+' > '+self.__path+'/log.txt 2>&1')
            # public.ExecShell('yum update -y {} 2>&1 |tee {}/log.txt'.format(soft, self.__path))
            result, err = public.ExecShell('yum update -y {}'.format(soft))
            # subprocess.check_output(['yum', 'update', '-y', soft])
        elif "alicloud" in self.sys_version:
            result, err = public.ExecShell('yum update -y {}'.format(soft))
        elif "ubuntu" in self.sys_version:
            # public.ExecShell('apt install -y '+soft+' > '+self.__path+'/log.txt 2>&1')
            # public.ExecShell('apt install -y {} 2>&1 |tee {}/log.txt'.format(soft, self.__path))
            result, err = public.ExecShell('apt install -y {}'.format(soft))
        elif "debian" in self.sys_version:
            # public.ExecShell('apt install -y {} 2>&1 |tee {}/log.txt'.format(soft, self.__path))
            result, err = public.ExecShell('apt install -y {}'.format(soft))
        # result = public.ReadFile(self.__path + '/log.txt')
        for error in error_message:
            if result.find(error) >= 0 or err.find(error) >= 0:
                return 2
        for no in nothing_message:
            if result.find(no) >= 0 or err.find(no) >= 0:
                return 3
        return 1

    def get_repair_bar(self, get):
        '''
        获取修复进度条
        @param get:
        @return: int
        '''
        if not os.path.exists(self.__path + '/repair_bar.txt'): return 0
        data3 = public.ReadFile(self.__path + '/repair_bar.txt')
        if isinstance(data3, str):
            data3 = data3.strip()
            try:
                data = json.loads(data3)
                data["percentage"] = float(data["percentage"])
            except Exception as e:
                # public.print_log(e)
                data = 0
            return data
        return 0

    def get_rpm_version(self, pkg_list):
        """
        @name 获取rpm包列表当前版本
        @param pkg_list 包名
        @return string 包 版本号，<br/>隔开
        """
        output, err = public.ExecShell("rpm -q '%{NAME};%{VERSION}-%{RELEASE}\n' "+ ' '.join(pkg_list))
        output_list = output.strip().split("\n")
        result = '<br/>'.join(output_list)
        return result

    def get_dpkg_version(self, pkg_list):
        """
        @name 获取dpkg包列表当前版本
        @param pkg_list 包名
        @return string 包 版本号，<br/>隔开
        """
        output, err = public.ExecShell("dpkg-query -W -f='${Package} ${Version}\n' " + ' '.join(pkg_list))
        output_list = output.strip().split("\n")
        result = '<br/>'.join(output_list)
        return result
