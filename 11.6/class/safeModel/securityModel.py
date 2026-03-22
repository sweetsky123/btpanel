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
    # 回滚相关路径
    __rollback_dir = __path + '/rollback'
    __backup_dir = __path + '/backup'
    __rollback_file = __rollback_dir + '/last_repair.json'
    # 修复记录文件（新）
    __repair_records_file = __rollback_dir + '/repair_records.json'
    # 最大保留记录数
    MAX_REPAIR_RECORDS = 10

    def __init__(self):
        self.configs = config.config()
        # 确保回滚和备份目录存在
        if not os.path.exists(self.__rollback_dir):
            os.makedirs(self.__rollback_dir, 384)
        if not os.path.exists(self.__backup_dir):
            os.makedirs(self.__backup_dir, 384)

    def _create_backup_for_item(self, m_name):
        """
        为指定检测项创建备份，返回备份信息
        @param m_name: 检测项名称
        @return: dict 备份信息，如果不需要备份返回None
        """
        backup_info = None

        # SSH相关配置项备份（含新增的sw_ssh_banner和sw_ssh_permit_env）
        # 注意：sw_ssh_passmin, sw_ssh_passmax, sw_ssh_passwarn 已移至login.defs备份
        if m_name in ['sw_ssh_clientalive', 'sw_ssh_login_grace', 'sw_ssh_maxauth',
                      'sw_ssh_notpass', 'sw_ssh_security', 'sw_ssh_v2', 'sw_ssh_banner',
                      'sw_ssh_ciphers', 'sw_ssh_loglevel', 'sw_ssh_kexalgorithms',
                      'sw_ssh_ignore_rhosts', 'sw_ssh_permit_env', 'sw_ssh_hostbased',
                      'sw_ssh_forward']:
            config_file = '/etc/ssh/sshd_config'
            if os.path.exists(config_file):
                backup_path = self.__backup_dir + '/sshd_config_{}.bak'.format(int(time.time()))
                public.ExecShell('cp {} {}'.format(config_file, backup_path))
                backup_info = {
                    'backup_type': 'file',
                    'backup_path': backup_path,
                    'original_path': config_file,
                    'restore_cmd': 'cp {} {}'.format(backup_path, config_file)
                }

        # login.defs密码策略相关配置项备份
        elif m_name in ['sw_ssh_passmin', 'sw_ssh_passmax', 'sw_ssh_passwarn']:
            config_file = '/etc/login.defs'
            if os.path.exists(config_file):
                backup_path = self.__backup_dir + '/login.defs_{}.bak'.format(int(time.time()))
                public.ExecShell('cp {} {}'.format(config_file, backup_path))
                backup_info = {
                    'backup_type': 'file',
                    'backup_path': backup_path,
                    'original_path': config_file,
                    'restore_cmd': 'cp {} {}'.format(backup_path, config_file)
                }

        # sysctl参数备份（含新增的IPv4/IPv6网络参数）
        elif m_name in ['sw_kernel_space', 'sw_tcp_syn_cookie', 'sw_protected_hardlinks',
                        'sw_protected_symlinks', 'sw_ipv4_secure_redirects_not_accept',
                        'sw_ipv6_redirects_not_accept', 'sw_ipv4_send_redirects_disabled',
                        'sw_ipv4_log_martians_enabled', 'sw_icmp_echo_ignore_broadcasts',
                        'sw_ipv4_accept_source_route_disabled', 'sw_ipv4_accept_redirects_disabled',
                        'sw_icmp_ignore_bogus', 'sw_ipv6_accept_ra_disabled',
                        'sw_ipv4_redirects_not_accept', 'sw_ipv6_accept_source_route_disabled']:
            config_file = '/etc/sysctl.conf'
            if os.path.exists(config_file):
                backup_path = self.__backup_dir + '/sysctl_{}.bak'.format(int(time.time()))
                public.ExecShell('cp {} {}'.format(config_file, backup_path))
                backup_info = {
                    'backup_type': 'file',
                    'backup_path': backup_path,
                    'original_path': config_file,
                    'restore_cmd': 'cp {} {} && sysctl -p'.format(backup_path, config_file)
                }

        # modprobe配置备份（新增7项协议/文件系统禁用）
        elif m_name in ['sw_dccp_disabled', 'sw_sctp_disabled', 'sw_tipc_disabled',
                        'sw_rds_disabled', 'sw_jffs2_disabled', 'sw_hfs_disabled', 'sw_udf_disabled']:
            config_file = '/etc/modprobe.d/CIS.conf'
            if os.path.exists(config_file):
                backup_path = self.__backup_dir + '/modprobe_cis_{}.bak'.format(int(time.time()))
                public.ExecShell('cp {} {}'.format(config_file, backup_path))
                backup_info = {
                    'backup_type': 'file',
                    'backup_path': backup_path,
                    'original_path': config_file,
                    'restore_cmd': 'cp {} {}'.format(backup_path, config_file)
                }
            else:
                # 文件不存在时也记录，用于回滚时删除
                backup_info = {
                    'backup_type': 'file',
                    'backup_path': '',
                    'original_path': config_file,
                    'restore_cmd': 'rm -f {}'.format(config_file)
                }

        # PHP配置备份
        elif m_name in ['sw_php_expose', 'sw_php_display_errors', 'sw_php_disable_functions',
                        'sw_php_url_include']:
            config_file = '/www/server/php/{}/etc/php.ini'.format(
                public.get_webserver()) if public.get_webserver() else None
            if config_file and os.path.exists(config_file):
                backup_path = self.__backup_dir + '/php_{}.bak'.format(int(time.time()))
                public.ExecShell('cp {} {}'.format(config_file, backup_path))
                backup_info = {
                    'backup_type': 'file',
                    'backup_path': backup_path,
                    'original_path': config_file,
                    'restore_cmd': 'cp {} {}'.format(backup_path, config_file)
                }

        # Nginx配置备份
        elif m_name in ['sw_nginx_server', 'sw_nginx_malware']:
            config_file = '/www/server/nginx/conf/nginx.conf'
            if os.path.exists(config_file):
                backup_path = self.__backup_dir + '/nginx_{}.bak'.format(int(time.time()))
                public.ExecShell('cp {} {}'.format(config_file, backup_path))
                backup_info = {
                    'backup_type': 'file',
                    'backup_path': backup_path,
                    'original_path': config_file,
                    'restore_cmd': 'cp {} {} && nginx -t && nginx -s reload'.format(backup_path, config_file)
                }

        # Apache配置备份
        elif m_name in ['sw_httpd_trace_enable', 'sw_httpd_version_leak']:
            config_file = '/www/server/apache/conf/httpd.conf'
            if os.path.exists(config_file):
                backup_path = self.__backup_dir + '/httpd_{}.bak'.format(int(time.time()))
                public.ExecShell('cp {} {}'.format(config_file, backup_path))
                backup_info = {
                    'backup_type': 'file',
                    'backup_path': backup_path,
                    'original_path': config_file,
                    'restore_cmd': 'cp {} {} && httpd -t && httpd graceful'.format(backup_path, config_file)
                }

        # FTP配置备份
        elif m_name in ['sw_ftp_root', 'sw_ftp_login', 'sw_ftp_umask', 'sw_ftp_pass']:
            config_file = '/etc/pure-ftpd/pure-ftpd.conf'
            if os.path.exists(config_file):
                backup_path = self.__backup_dir + '/pure-ftpd_{}.bak'.format(int(time.time()))
                public.ExecShell('cp {} {}'.format(config_file, backup_path))
                backup_info = {
                    'backup_type': 'file',
                    'backup_path': backup_path,
                    'original_path': config_file,
                    'restore_cmd': 'cp {} {} && systemctl restart pure-ftpd'.format(backup_path, config_file)
                }

        # bootloader配置备份
        elif m_name == 'sw_bootloader_mod':
            config_files = ['/etc/default/grub', '/boot/grub2/grub.cfg', '/boot/grub/grub.conf']
            backup_cmds = []
            for cf in config_files:
                if os.path.exists(cf):
                    backup_path = self.__backup_dir + '/grub_{}_{}.bak'.format(os.path.basename(cf), int(time.time()))
                    public.ExecShell('cp {} {}'.format(cf, backup_path))
                    backup_cmds.append('cp {} {}'.format(backup_path, cf))
            if backup_cmds:
                backup_info = {
                    'backup_type': 'file',
                    'backup_path': 'multiple',
                    'original_path': 'grub_files',
                    'restore_cmd': ' && '.join(backup_cmds)
                }

        # auditd配置备份（新增）
        elif m_name in ['sw_auditd_init', 'sw_audit_modules_events', 'sw_audit_mounts_events',
                        'sw_audit_access_failed_events', 'sw_audit_delete_events',
                        'sw_audit_identity_events', 'sw_audit_logins_events',
                        'sw_audit_mac_policy_events', 'sw_audit_network_env_events',
                        'sw_audit_perm_mod_events', 'sw_audit_session_events',
                        'sw_audit_sudoers_scope_events', 'sw_audit_sudo_log_events',
                        'sw_audit_time_change_events']:
            # 备份auditd.conf和audit.rules
            config_files = ['/etc/audit/auditd.conf', '/etc/audit/rules.d/audit.rules']
            backup_cmds = []
            for cf in config_files:
                if os.path.exists(cf):
                    backup_path = self.__backup_dir + '/audit_{}_{}.bak'.format(os.path.basename(cf), int(time.time()))
                    public.ExecShell('cp {} {}'.format(cf, backup_path))
                    backup_cmds.append('cp {} {}'.format(backup_path, cf))
            if backup_cmds:
                backup_info = {
                    'backup_type': 'file',
                    'backup_path': 'multiple',
                    'original_path': 'audit_files',
                    'restore_cmd': ' && '.join(backup_cmds) + ' && service auditd restart'
                }

        # YUM配置备份（新增 - 仅RedHat系列）
        elif m_name == 'sw_yum_gpgcheck_enabled':
            config_file = '/etc/yum.conf'
            if os.path.exists(config_file):
                backup_path = self.__backup_dir + '/yum_{}.bak'.format(int(time.time()))
                public.ExecShell('cp {} {}'.format(config_file, backup_path))
                backup_info = {
                    'backup_type': 'file',
                    'backup_path': backup_path,
                    'original_path': config_file,
                    'restore_cmd': 'cp {} {}'.format(backup_path, config_file)
                }

        # chrony配置备份（新增 - 仅RedHat系列）
        elif m_name == 'sw_chrony_configured':
            config_files = ['/etc/chrony.conf', '/etc/sysconfig/chronyd']
            backup_cmds = []
            for cf in config_files:
                if os.path.exists(cf):
                    backup_path = self.__backup_dir + '/chrony_{}_{}.bak'.format(os.path.basename(cf), int(time.time()))
                    public.ExecShell('cp {} {}'.format(cf, backup_path))
                    backup_cmds.append('cp {} {}'.format(backup_path, cf))
            if backup_cmds:
                backup_info = {
                    'backup_type': 'file',
                    'backup_path': 'multiple',
                    'original_path': 'chrony_files',
                    'restore_cmd': ' && '.join(backup_cmds) + ' && systemctl restart chronyd'
                }

        # NTP配置备份（新增）
        elif m_name == 'sw_ntp_configured':
            config_files = ['/etc/ntp.conf', '/etc/sysconfig/ntpd']
            backup_cmds = []
            for cf in config_files:
                if os.path.exists(cf):
                    backup_path = self.__backup_dir + '/ntp_{}_{}.bak'.format(os.path.basename(cf), int(time.time()))
                    public.ExecShell('cp {} {}'.format(cf, backup_path))
                    backup_cmds.append('cp {} {}'.format(backup_path, cf))
            if backup_cmds:
                backup_info = {
                    'backup_type': 'file',
                    'backup_path': 'multiple',
                    'original_path': 'ntp_files',
                    'restore_cmd': ' && '.join(backup_cmds) + ' && systemctl restart ntpd'
                }

        # 本地登录标语备份（新增）
        elif m_name == 'sw_local_login_banner':
            config_file = '/etc/issue'
            if os.path.exists(config_file):
                backup_path = self.__backup_dir + '/issue_{}.bak'.format(int(time.time()))
                public.ExecShell('cp {} {}'.format(config_file, backup_path))
                backup_info = {
                    'backup_type': 'file',
                    'backup_path': backup_path,
                    'original_path': config_file,
                    'restore_cmd': 'cp {} {}'.format(backup_path, config_file)
                }

        # 命令行超时配置备份（新增）
        elif m_name == 'sw_time_out':
            config_file = '/etc/profile'
            if os.path.exists(config_file):
                backup_path = self.__backup_dir + '/profile_{}.bak'.format(int(time.time()))
                public.ExecShell('cp {} {}'.format(config_file, backup_path))
                backup_info = {
                    'backup_type': 'file',
                    'backup_path': backup_path,
                    'original_path': config_file,
                    'restore_cmd': 'cp {} {}'.format(backup_path, config_file)
                }

        # IPv6转发配置备份（新增 - 使用sysctl.conf备份）
        elif m_name == 'sw_ipv6_forwarding_disabled':
            # IPv6转发配置在sysctl.conf中，已包含在sysctl备份中
            config_file = '/etc/sysctl.conf'
            if os.path.exists(config_file):
                backup_path = self.__backup_dir + '/sysctl_{}.bak'.format(int(time.time()))
                if not os.path.exists(backup_path):
                    # 如果还没有备份，创建一个
                    public.ExecShell('cp {} {}'.format(config_file, backup_path))
                backup_info = {
                    'backup_type': 'file',
                    'backup_path': backup_path,
                    'original_path': config_file,
                    'restore_cmd': 'cp {} {} && sysctl -p'.format(backup_path, config_file)
                }

        return backup_info

    def _save_rollback_record(self, rollback_items):
        """
        保存回滚记录到文件
        @param rollback_items: 回滚项列表
        """
        if not rollback_items:
            return

        repair_data = {
            'repair_id': 'repair_{}'.format(int(time.time())),
            'repair_time': int(time.time()),
            'items': rollback_items
        }

        # 确保目录存在
        if not os.path.exists(self.__rollback_dir):
            os.makedirs(self.__rollback_dir, 384)

        # 写入回滚记录
        public.WriteFile(self.__rollback_file, json.dumps(repair_data))

    def _read_repair_records(self):
        """
        读取修复记录文件
        @return: list 修复记录列表
        """
        if not os.path.exists(self.__repair_records_file):
            return {"records": []}

        try:
            content = public.ReadFile(self.__repair_records_file)
            if content:
                return json.loads(content)
        except:
            pass

        return {"records": []}

    def _write_repair_records(self, data):
        """
        写入修复记录文件
        @param data: 要写入的数据
        """
        # 确保目录存在
        if not os.path.exists(self.__rollback_dir):
            os.makedirs(self.__rollback_dir, 384)

        public.WriteFile(self.__repair_records_file, json.dumps(data))

    def _cleanup_old_records(self, records):
        """
        清理超过10条的旧记录和对应的备份文件
        @param records: 修复记录列表
        @return: 清理后的记录列表
        """
        if len(records) <= self.MAX_REPAIR_RECORDS:
            return records

        # 获取要删除的旧记录
        old_records = records[self.MAX_REPAIR_RECORDS:]

        # 删除对应的备份文件
        for old_record in old_records:
            for backup in old_record.get('backups', []):
                backup_path = backup.get('backup_path')
                if backup_path and os.path.exists(backup_path):
                    try:
                        os.remove(backup_path)
                        # public.print_log("已删除旧备份文件: {}".format(backup_path))
                    except Exception as e:
                        pass
                        # public.print_log("删除备份文件失败: {} - {}".format(backup_path, e))

        # 返回前10条记录
        return records[:self.MAX_REPAIR_RECORDS]

    def _add_repair_record(self, rollback_items):
        """
        添加新的修复记录，自动清理超过10条的旧记录
        @param rollback_items: 回滚项列表
        """
        if not rollback_items:
            return

        # 读取现有记录
        data = self._read_repair_records()

        # 构建新记录
        new_record = {
            'repair_id': 'repair_{}'.format(int(time.time())),
            'repair_time': int(time.time()),
            'repair_items': [item.get('m_name') for item in rollback_items],
            'status': 'active',
            'backups': rollback_items
        }

        # 插入到开头
        data['records'].insert(0, new_record)

        # 清理超过10条的记录
        data['records'] = self._cleanup_old_records(data['records'])

        # 保存
        self._write_repair_records(data)

    def set_security(self, get):
        '''
        自动修复对应的安全风险项
        @param get: 传 < dict_obj > 里面包含风险名列表 < list > m_name
        @return: 返回 dict_obj
        '''
        public.set_module_logs('panelWarning', 'set_security', 1)
        all_repair_data = []  # 全部修复历史数据
        self.sys_version = self.get_sys_version()  # 初始化获取当前系统版本
        public.WriteFile(self.__path + '/repair_bar.txt',
                         json.dumps({"status": "准备修复", "percentage": 0.0}))  # 修复进度条归零
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
                        # 检查是否开启系统加固
                        if self._is_safe_mode():
                            failed.append({"result": {"status": False,
                                                      "msg": "{}修复失败，请关闭系统加固后再次执行修复".format(cve),
                                                      "type": ["请关闭系统加固后再次修复"]},
                                           "m_name": "{}".format(cve)})
                        else:
                            failed.append({"result": {"status": False, "msg": "{}修复失败，请手动修复".format(cve),
                                                      "type": ["请手动修复"]},
                                           "m_name": "{}".format(cve)})
                    elif tmp == 3:
                        success.append({"result": {"status": True, "msg": "{}修复成功".format(cve),
                                                   "type": [
                                                       "若漏洞依旧存在，则联系堡塔运维https://www.bt.cn/bbs发送漏洞信息"]},
                                        "m_name": "{}".format(cve)})
                except Exception as e:
                    # public.print_log("{}修复出错：{}".format(cve, e))
                    failed.append({"result": {"status": False,
                                              "msg": "{}修复失败，联系堡塔运维https://www.bt.cn/bbs发送错误信息".format(
                                                  cve), "type": [e]},
                                   "m_name": "{}".format(cve)})
                new_version = self.get_dpkg_version(repair_dict[cve])
                self.one_repair_data["describe"] = "修复前版本：<br/>{}<br/>修复后版本：{}".format(old_version,
                                                                                                 new_version)
                self.one_repair_data[
                    "recover"] = "执行命令降级安装：<br/>apt-get install 【软件包】=【修复前版本】<br/>注意降级安装可能需要相关的依赖包也同时降级安装"
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
                        if self._is_safe_mode():
                            failed.append({"result": {"status": False,
                                                      "msg": "修复失败，请关闭系统加固后再次执行修复",
                                                      "type": ["请关闭系统加固后再次修复"]},
                                           "m_name": "{}".format(RHSA)})
                        else:
                            failed.append({"result": {"status": False,
                                                      "msg": "修复失败，请手动修复",
                                                      "type": ["请手动修复"]},
                                           "m_name": "{}".format(RHSA)})
                    elif tmp == 3:
                        success.append({"result": {"status": True,
                                                   "msg": "{}修复成功".format(RHSA),
                                                   "type": [
                                                       "若漏洞依旧存在，则联系堡塔运维https://www.bt.cn/bbs发送漏洞信息"]},
                                        "m_name": "{}".format(RHSA)})
                except Exception as e:
                    # public.print_log("{}修复出错：{}".format(RHSA, e))
                    failed.append({"result": {"status": False,
                                              "msg": "修复失败，联系堡塔运维https://www.bt.cn/bbs发送错误信息",
                                              "type": [e]},
                                   "m_name": "{}".format(RHSA)})
                new_version = self.get_rpm_version(repair_dict[RHSA])
                self.one_repair_data["describe"] = "修复前版本：<br/>{}<br/>修复后版本：{}".format(old_version,
                                                                                                 new_version)
                self.one_repair_data[
                    "recover"] = "执行命令降级安装：<br/>yum downgrade 【软件包】-【修复前版本】<br/>注意降级安装可能需要相关的依赖包也同时降级安装"
                all_repair_data.append(self.one_repair_data)
            try:
                import panelWarning
                panelWarning.panelWarning().new_get_sys_product(flag=True)
            except Exception as e:
                pass
                # public.print_log("修复完漏洞再次扫描失败：{}".format(e))

        # 将开发者模式修复放到最后，防止重载面板导致其他漏洞修复失败
        element_to_move = "sw_debug_mode"
        if element_to_move in m_name_list:
            m_name_list.remove(element_to_move)
            m_name_list.append(element_to_move)

        # 初始化回滚记录列表
        rollback_items = []

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

            # ===== 新增：创建备份 =====
            try:
                backup_info = self._create_backup_for_item(m_name)
                if backup_info:
                    backup_info['m_name'] = m_name
                    rollback_items.append(backup_info)
            except Exception as e:
                pass
                # public.print_log("创建备份失败：{} - {}".format(m_name, e))

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

        # ===== 保存修复记录（最多保留10条）=====
        try:
            self._add_repair_record(rollback_items)
        except Exception as e:
            pass
            # public.print_log("保存修复记录失败：{}".format(e))

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

    # 检查系统加固是否开启
    def _is_safe_mode(self, args=None):
        if not os.path.exists('/www/server/panel/plugin/syssafe/'):
            return False
        data = json.loads(public.readFile('/www/server/panel/plugin/syssafe/config.json'))
        return data['open']

    # 修复pypi供应链投毒
    def sw_pip_poison(self):
        """
        pypi供应链投毒检测
        @return:
        """
        result = {"status": False, "msg": "pypi供应链投毒检测处理失败,请手动设置"}
        try:
            evil_list = public.ExecShell(
                "btpip freeze |grep -E \"istrib|djanga|easyinstall|junkeldat|libpeshka|mumpy|mybiubiubiu|nmap-python|openvc"
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
            self.one_repair_data["describe"] = "修复前权限：<br/>{}<br/>修复后权限：<br/>{}".format(
                '<br/>'.join(old_version),
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
        self.one_repair_data[
            "describe"] = "【/www/server/pure-ftpd/etc/pure-ftpd.conf】<br/>修复前：{}<br/>修复后：MinUID 100".format(
            old_version)
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
        self.one_repair_data["describe"] = "【/etc/profile】设置命令行超时600秒自动退出【export TMOUT=600】"
        self.one_repair_data["recover"] = "恢复备份的/etc/profile文件"
        result = {"status": False, "msg": "设置命令行界面超时退出失败,请手动设置"}
        filename = "/etc/profile"

        # 检查是否已存在TMOUT配置（支持匹配 export TMOUT= 格式）
        conf = public.readFile(filename)
        if conf:
            import re
            # 匹配 TMOUT= 或 export TMOUT= 格式（包括小写 tmout）
            if re.search(r'(?:export\s+)?TMOUT\s*=', conf, re.IGNORECASE | re.MULTILINE):
                # 使用 sed 替换现有配置并去重：
                # 1. 删除所有 TMOUT/tmout 相关行
                # 2. 在文件末尾添加统一的 export TMOUT=600
                w_result = public.ExecShell("sed -i '/^[[:space:]]*export[[:space:]]\\+TMOUT[[:space:]]*=/d; /^[[:space:]]*TMOUT[[:space:]]*=/d; /^[[:space:]]*tmout[[:space:]]*=/d' {}".format(filename))
                if not w_result[1]:
                    # 删除成功后，追加新的配置
                    public.ExecShell("echo \"export TMOUT=600\" >> {}".format(filename))
                    result["status"] = True
                    result["msg"] = "已更新命令行界面超时为600秒退出"
                elif "Permission denied" in w_result[1] or "Operation not permitted" in w_result[1]:
                    result["msg"] = "修复被系统加固拦截，请先关闭系统加固，修复完后再开启"
                    result["type"] = ["修复被系统加固拦截，请先关闭系统加固，修复完后再开启"]
                return result

        # 不存在配置则追加
        w_result = public.ExecShell("echo \"export TMOUT=600\" >> {}".format(filename))
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
        self.one_repair_data["describe"] = "去掉文件的suid或sgid权限：<br/>chmod u-s {}<br/>chmod g-s {}".format(
            ' '.join(suid), ' '.join(sgid))
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
        self.one_repair_data[
            "describe"] = "ftp访问安全配置【/www/server/pure-ftpd/etc/pure-ftpd.conf】<br/>修复前：{}<br/>修复后：Umask                       177:077".format(
            old_result)
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

    def sw_ssh_loglevel(self):
        '''
        设置SSH日志级别为INFO
        @return:
        '''
        result = {"status": False, "msg": "设置SSH日志级别失败,请手动设置"}
        file = "/etc/ssh/sshd_config"
        self.one_repair_data["describe"] = "设置SSH日志级别为INFO【/etc/ssh/sshd_config】<br/>LogLevel INFO"
        self.one_repair_data["recover"] = "打开文件【/etc/ssh/sshd_config】修改LogLevel的值"

        f_data = public.readFile(file)
        try:
            # 先删除已有的LogLevel配置（包括注释行）
            pattern = r'^\s*#?\s*LogLevel\s+.*'
            if re.search(pattern, f_data, re.MULTILINE):
                file_result = re.sub(pattern, "LogLevel INFO", f_data, count=1, flags=re.MULTILINE)
                public.writeFile(file, file_result)
            else:
                # 追加新配置
                public.ExecShell("echo 'LogLevel INFO' >> {}".format(file))

            # 重启sshd
            f_data = public.readFile(file)
            if re.search(r'^\s*LogLevel\s+INFO', f_data, re.MULTILINE):
                c_result = public.ExecShell("systemctl restart sshd")
                if not c_result[1]:
                    result["status"] = True
                    result["msg"] = "设置SSH日志级别为INFO成功"
        except Exception as e:
            pass
            # public.print_log("修复异常：{}".format(e))

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
        if "Protocol 2" in f_data:
            c_result = public.ExecShell("systemctl restart sshd")
            # 检查返回码和错误输出
            if c_result[0] == 0 and not c_result[1]:
                result["status"] = True
                result["msg"] = "设置加密的远程管理ssh成功"
            else:
                result["msg"] = "配置已写入但sshd重启失败: {}".format(c_result[1] or "未知错误")
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
            self.one_repair_data["describe"] = "修复前权限：<br/>{}<br/>修复后权限：<br/>{}".format(
                '<br/>'.join(old_version),
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
        if result["status"]:
            result["msg"] = "已开启禁ping"
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
        self.one_repair_data[
            "describe"] = "修改密码最小间隔时间：<br/>【/etc/login.defs】<br/>{}<br/>执行命令：chage --mindays 7 root".format(
            old_version)
        self.one_repair_data[
            "recover"] = "取消修改密码最小间隔：<br/>打开文件【/etc/login.defs】，修改PASS_MIN_DAYS的值为0<br/>执行命令chage --mindays 0 root"
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
        self.one_repair_data[
            "describe"] = "设置ssh密码过期提前告警：<br/>【/etc/login.defs】<br/>{}<br/>执行命令：chage --warndays 7 root".format(
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
        self.one_repair_data["describe"] = "修复polkit本地提权漏洞：<br/>修复前版本：{}<br/>修复后版本：{}".format(
            old_version, new_version)
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
        self.one_repair_data[
            "describe"] = "开启地址空间布局随机化：<br/>【/proc/sys/kernel/randomize_va_space】<br/>{}".format(old_version)
        self.one_repair_data[
            "recover"] = "关闭方式：<br/>打开文件【/proc/sys/kernel/randomize_va_space】，修改内容为{}<br/>执行命令：sysctl -w kernel.randomize_va_space={}".format(
            old_version, old_version)
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
        self.one_repair_data["describe"] = "关闭Apache版本泄露配置：ServerSignature Off、ServerTokens Prod"
        self.one_repair_data[
            "recover"] = "取消方式：<br/>打开文件【/www/server/apache/conf/httpd.conf】<br/>设置ServerSignature为on<br/>删除ServerTokens Prod<br/>最后重启apache"
        if os.path.exists(conf):
            try:
                info_data = public.ReadFile(conf)
                if not info_data:
                    return result

                has_server_sig = re.search(r'\nServerSignature', info_data)
                has_server_tok = re.search(r'\nServerTokens', info_data)

                # 如果都没有配置，直接添加
                if not has_server_sig and not has_server_tok:
                    info_data = info_data + "\nServerSignature Off\nServerTokens Prod\n"
                    public.writeFile(conf, info_data)
                    result["status"] = True
                    result["msg"] = "Apache 版本泄露修复成功"
                    return result

                # 替换现有配置（匹配任意值，不只是on）
                file_result = info_data

                # ServerSignature: 匹配任意非换行字符的值
                if has_server_sig:
                    file_result = re.sub(r'\n\s*ServerSignature\s+\S+', "\nServerSignature Off", file_result)
                else:
                    file_result = file_result + "\nServerSignature Off"

                # ServerTokens: 匹配任意非换行字符的值
                if has_server_tok:
                    file_result = re.sub(r'\n\s*ServerTokens\s+\S+', "\nServerTokens Prod", file_result)
                else:
                    file_result = file_result + "\nServerTokens Prod"

                public.writeFile(conf, file_result)

                # 重新读取验证修复结果
                new_data = public.ReadFile(conf)
                if new_data and re.search(r'ServerSignature Off', new_data) and re.search(r'ServerTokens Prod', new_data):
                    result["status"] = True
                    result["msg"] = "Apache 版本泄露修复成功"
                    return result
                else:
                    result["type"] = ["修复被系统加固拦截，请先关闭系统加固，修复完后再开启"]
            except Exception as e:
                # public.print_log("修复 Apache 版本泄露失败: {}".format(e))
                return result
        return result

    def sw_nginx_server(self):
        '''
        关闭Nginx版本显示
        @return:
        '''
        file = "/www/server/nginx/conf/nginx.conf"
        result = {"status": False, "msg": "关闭nginx版本显示失败,请手动设置"}
        self.one_repair_data["describe"] = "关闭Nginx版本显示：server_tokens off"
        self.one_repair_data[
            "recover"] = "取消方式：<br/>打开文件【/www/server/nginx/conf/nginx.conf】<br/>修改server_tokens off为on<br/>最后重启nginx"
        if os.path.exists(file):
            try:
                f_data = public.readFile(file)
                if not f_data:
                    return result

                # 检测是否已存在server_tokens配置
                has_server_tokens = re.search(r'\n\s*server_tokens\s+\S+', f_data)

                if has_server_tokens:
                    # 替换现有配置（匹配任意值：on/On/ON/1等）
                    file_result = re.sub(r'\n(\s*)server_tokens\s+\S+', r"\nserver_tokens off;", f_data)
                else:
                    # 在http块中添加配置（通常在文件末尾或http块内）
                    # 检测是否有http块
                    if re.search(r'\nhttp\s*\{', f_data):
                        # 在http块内添加（查找最后一个}之前）
                        file_result = re.sub(r'(\n\s*\}\s*#\s*gzip\s+on)', r'\1\n    server_tokens off;', f_data)
                        if file_result == f_data:
                            # 如果没有找到gzip位置，在http块结束前添加
                            file_result = re.sub(r'(\n\s*\}\s*#\s*include\s+/www/server)', r'\1\n    server_tokens off;', f_data)
                        if file_result == f_data:
                            # 在http块结束前添加
                            file_result = re.sub(r'(\n\})', r'\1\n    server_tokens off;', f_data, count=1)
                    else:
                        # 没有http块，直接追加到文件末尾
                        file_result = f_data + "\nserver_tokens off;\n"

                public.writeFile(file, file_result)

                # 重新读取验证修复结果
                new_data = public.readFile(file)
                if new_data and re.search(r'server_tokens\s+off\s*;', new_data):
                    result["status"] = True
                    result["msg"] = "关闭nginx版本显示成功"
                else:
                    result["type"] = ["修复被系统加固拦截，请先关闭系统加固，修复完后再开启"]
            except Exception as e:
                # public.print_log("修复 Nginx 版本泄露失败: {}".format(e))
                return result
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
        # 检查PHP目录是否存在
        if not os.path.exists(path):
            return {"status": True, "msg": "PHP未安装，无需修复"}

        # 获取目录下的文件夹
        dirs = os.listdir(path)
        fail_list = []
        for dir in dirs:
            # 动态检测是否为有效的PHP版本目录（检查php.ini是否存在）
            file_path = os.path.join(path, dir, "etc", "php.ini")
            if os.path.exists(file_path):
                try:
                    php_ini = public.readFile(file_path)
                    if not php_ini:
                        continue
                    rep = "\ndisplay_errors\\s?=\\s*(\S+)"
                    if re.search(rep, php_ini):
                        status = re.findall(rep, php_ini)[0].strip().lower()
                        # 检测是否为开启状态（支持 On/on/1/yes/true）
                        if status in ['on', '1', 'yes', 'true']:
                            error_list.append(dir)
                            new = re.sub(rep, "\ndisplay_errors = Off", php_ini)
                            public.writeFile(file_path, new)
                            public.phpReload(str(dir))  # 重启指定PHP
                    else:
                        # 不存在配置时追加
                        error_list.append(dir)
                        php_ini = php_ini + "\ndisplay_errors = Off\n"
                        public.writeFile(file_path, php_ini)
                        public.phpReload(str(dir))
                except Exception as e:
                    fail_list.append(dir)
                    # public.print_log("修复 PHP {} display_errors 失败: {}".format(dir, e))
        self.one_repair_data["describe"] = "修复以下PHP版本错误信息泄露：{}".format('、'.join(error_list))
        self.one_repair_data["recover"] = "恢复方式：<br/>打开面板-软件商店-运行环境-对应PHP-配置修改-开启display_errors选项"
        if fail_list:
            return {"status": False, "msg": "【PHP配置文件{}】关闭错误提示失败".format('、'.join(fail_list)),
                    "type": ["修复被系统加固拦截，请先关闭系统加固，修复完后再开启"]}
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
        repair_list = []  # 记录修复历史
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
            return {"status": False, "msg": "【PHP配置文件{}】清除挂马失败".format('、'.join(fail_list)),
                    "type": ["修复被系统加固拦截，请先关闭系统加固，修复完后再开启"]}
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
                    if tmp[0].strip() != "off":
                        httpd_conf = re.sub(rep1, "\nTraceEnable off", output)
                        public.WriteFile(path, httpd_conf)
                else:
                    with open(path, 'a+') as file:
                        file.write("TraceEnable off \n")
            except:
                return {"status": False, "msg": "关闭Apache Trace请求失败",
                        "type": ["修复被系统加固拦截，请先关闭系统加固，修复完后再开启"]}
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
            return {"status": False, "msg": "以下文件清除nginx配置挂马内容失败：".format('、'.join(fail_file)),
                    "type": ["请先关闭系统加固，修复完后再开启"]}
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
        self.one_repair_data[
            "describe"] = "修复内核参数硬链接保护：<br/>【/proc/sys/fs/protected_hardlinks】{}改为1".format(old_version)
        self.one_repair_data[
            "recover"] = "执行命令：【echo {} > /proc/sys/fs/protected_hardlinks】<br/>【sysctl -w fs.protected_hardlinks={}】".format(
            old_version, old_version)
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

    def _disable_kernel_module(self, module_name):
        """
        通用内核模块禁用方法
        @param module_name: 模块名称
        @return: 修复结果字典
        """
        result = {"status": False, "msg": "禁用{}协议失败,请手动设置".format(module_name)}
        config_file = "/etc/modprobe.d/CIS.conf"

        try:
            # 检查模块是否已加载
            lsmod_result = public.ExecShell("lsmod | grep '^{} '\\s*".format(module_name))[0].strip()

            # 检查使用计数
            use_count = 0
            if lsmod_result:
                parts = lsmod_result.split()
                if len(parts) >= 3:
                    try:
                        use_count = int(parts[2])
                    except:
                        pass

            # 创建modprobe配置目录（如果不存在）
            public.ExecShell("mkdir -p /etc/modprobe.d")

            # 检查配置是否已存在
            config_content = public.readFile(config_file) or ''
            if not re.search(r'^\s*install\s+{}\s+/bin/true\s*$'.format(module_name), config_content, re.M):
                # 添加配置
                public.ExecShell("echo 'install {} /bin/true' >> {}".format(module_name, config_file))

            # 如果模块未加载或使用计数为0，尝试卸载
            if not lsmod_result or use_count == 0:
                public.ExecShell("modprobe -r {} 2>/dev/null".format(module_name))

            result["status"] = True
            result["msg"] = "已禁用{}协议".format(module_name)

            # 如果模块正在使用，给出提示
            if use_count > 0:
                result["msg"] += "（模块正在使用，仅添加配置，重启后生效）"

        except Exception as e:
            pass
            # public.print_log("禁用{}协议异常：{}".format(module_name, e))

        return result

    def sw_dccp_disabled(self):
        '''
        @name 禁用DCCP协议
        '''
        config_file = "/etc/modprobe.d/CIS.conf"
        self.one_repair_data["describe"] = "禁用DCCP协议"
        self.one_repair_data["recover"] = "打开文件【{}】删除install dccp /bin/true".format(config_file)
        return self._disable_kernel_module("dccp")

    def sw_sctp_disabled(self):
        '''
        @name 禁用SCTP协议
        '''
        config_file = "/etc/modprobe.d/CIS.conf"
        self.one_repair_data["describe"] = "禁用SCTP协议"
        self.one_repair_data["recover"] = "打开文件【{}】删除install sctp /bin/true".format(config_file)
        return self._disable_kernel_module("sctp")

    def sw_tipc_disabled(self):
        '''
        @name 禁用TIPC协议
        '''
        config_file = "/etc/modprobe.d/CIS.conf"
        self.one_repair_data["describe"] = "禁用TIPC协议"
        self.one_repair_data["recover"] = "打开文件【{}】删除install tipc /bin/true".format(config_file)
        return self._disable_kernel_module("tipc")

    def sw_rds_disabled(self):
        '''
        @name 禁用RDS协议
        '''
        config_file = "/etc/modprobe.d/CIS.conf"
        self.one_repair_data["describe"] = "禁用RDS协议"
        self.one_repair_data["recover"] = "打开文件【{}】删除install rds /bin/true".format(config_file)
        return self._disable_kernel_module("rds")

    def sw_jffs2_disabled(self):
        '''
        @name 禁用JFFS2文件系统
        '''
        config_file = "/etc/modprobe.d/CIS.conf"
        self.one_repair_data["describe"] = "禁用JFFS2文件系统"
        self.one_repair_data["recover"] = "打开文件【{}】删除install jffs2 /bin/true".format(config_file)
        return self._disable_kernel_module("jffs2")

    def sw_hfs_disabled(self):
        '''
        @name 禁用HFS文件系统
        '''
        config_file = "/etc/modprobe.d/CIS.conf"
        self.one_repair_data["describe"] = "禁用HFS文件系统"
        self.one_repair_data["recover"] = "打开文件【{}】删除install hfs /bin/true".format(config_file)
        return self._disable_kernel_module("hfs")

    def sw_udf_disabled(self):
        '''
        @name 禁用UDF文件系统
        '''
        config_file = "/etc/modprobe.d/CIS.conf"
        self.one_repair_data["describe"] = "禁用UDF文件系统"
        self.one_repair_data["recover"] = "打开文件【{}】删除install udf /bin/true".format(config_file)
        return self._disable_kernel_module("udf")

    # ============================================================
    # 新增：IPv4网络参数修复方法（7项）
    # ============================================================

    def sw_ipv4_secure_redirects_not_accept(self):
        '''
        @name 禁止接受安全ICMP重定向
        '''
        result = {"status": False, "msg": "设置IPv4安全重定向失败,请手动设置"}
        config_file = "/etc/sysctl.conf"

        self.one_repair_data["describe"] = "禁止接受安全ICMP重定向<br/>net.ipv4.conf.all.secure_redirects=0"
        self.one_repair_data["recover"] = "打开文件【{}】修改net.ipv4.conf.all.secure_redirects的值，执行sysctl -p".format(
            config_file)

        try:
            # 删除旧配置
            for param in ['net.ipv4.conf.all.secure_redirects', 'net.ipv4.conf.default.secure_redirects']:
                public.ExecShell("sed -i '/^{}/d' {}".format(param, config_file))
                # 添加新配置
                public.ExecShell("echo '{} = 0' >> {}".format(param, config_file))
                # 立即生效
                public.ExecShell("sysctl -w {}=0".format(param))

            # 刷新路由表
            public.ExecShell("sysctl -w net.ipv4.route.flush=1 2>/dev/null")

            result["status"] = True
            result["msg"] = "已禁止接受安全ICMP重定向"

        except Exception as e:
            pass
            # public.print_log("设置IPv4安全重定向异常：{}".format(e))

        return result

    def sw_ipv4_accept_source_route_disabled(self):
        '''
        @name 禁止IPv4源路由
        '''
        result = {"status": False, "msg": "设置IPv4源路由失败,请手动设置"}
        config_file = "/etc/sysctl.conf"

        self.one_repair_data["describe"] = "禁止IPv4源路由<br/>net.ipv4.conf.all.accept_source_route=0"
        self.one_repair_data[
            "recover"] = "打开文件【{}】修改net.ipv4.conf.all.accept_source_route的值，执行sysctl -p".format(config_file)

        try:
            # 删除旧配置并添加新配置
            for param in ['net.ipv4.conf.all.accept_source_route', 'net.ipv4.conf.default.accept_source_route']:
                public.ExecShell("sed -i '/^{}/d' {}".format(param, config_file))
                public.ExecShell("echo '{} = 0' >> {}".format(param, config_file))
                public.ExecShell("sysctl -w {}=0".format(param))

            public.ExecShell("sysctl -w net.ipv4.route.flush=1 2>/dev/null")

            result["status"] = True
            result["msg"] = "已禁止IPv4源路由"

        except Exception as e:
            pass
            # public.print_log("设置IPv4源路由异常：{}".format(e))

        return result

    def sw_ipv4_accept_redirects_disabled(self):
        '''
        @name 禁止IPv4 ICMP重定向
        '''
        result = {"status": False, "msg": "设置IPv4 ICMP重定向失败,请手动设置"}
        config_file = "/etc/sysctl.conf"

        self.one_repair_data["describe"] = "禁止IPv4 ICMP重定向<br/>net.ipv4.conf.all.accept_redirects=0"
        self.one_repair_data["recover"] = "打开文件【{}】修改net.ipv4.conf.all.accept_redirects的值，执行sysctl -p".format(
            config_file)

        try:
            for param in ['net.ipv4.conf.all.accept_redirects', 'net.ipv4.conf.default.accept_redirects']:
                public.ExecShell("sed -i '/^{}/d' {}".format(param, config_file))
                public.ExecShell("echo '{} = 0' >> {}".format(param, config_file))
                public.ExecShell("sysctl -w {}=0".format(param))

            public.ExecShell("sysctl -w net.ipv4.route.flush=1 2>/dev/null")

            result["status"] = True
            result["msg"] = "已禁止IPv4 ICMP重定向"

        except Exception as e:
            # public.print_log("设置IPv4 ICMP重定向异常：{}".format(e))
            pass

        return result

    def sw_ipv4_icmp_ignore_bogus_enabled(self):
        '''
        @name 忽略伪造的ICMP响应
        '''
        result = {"status": False, "msg": "设置忽略伪造ICMP响应失败,请手动设置"}
        config_file = "/etc/sysctl.conf"

        self.one_repair_data["describe"] = "忽略伪造的ICMP响应<br/>net.ipv4.icmp_ignore_bogus_error_responses=1"
        self.one_repair_data[
            "recover"] = "打开文件【{}】修改net.ipv4.icmp_ignore_bogus_error_responses的值，执行sysctl -p".format(
            config_file)

        try:
            param = 'net.ipv4.icmp_ignore_bogus_error_responses'
            public.ExecShell("sed -i '/^{}/d' {}".format(param, config_file))
            public.ExecShell("echo '{} = 1' >> {}".format(param, config_file))
            public.ExecShell("sysctl -w {}=1".format(param))

            result["status"] = True
            result["msg"] = "已设置忽略伪造的ICMP响应"

        except Exception as e:
            # public.print_log("设置忽略伪造ICMP响应异常：{}".format(e))
            pass

        return result

    def sw_ipv4_icmp_echo_ignore_broadcasts(self):
        '''
        @name 忽略广播ping
        '''
        result = {"status": False, "msg": "设置忽略广播ping失败,请手动设置"}
        config_file = "/etc/sysctl.conf"

        self.one_repair_data["describe"] = "忽略广播ping<br/>net.ipv4.icmp_echo_ignore_broadcasts=1"
        self.one_repair_data[
            "recover"] = "打开文件【{}】修改net.ipv4.icmp_echo_ignore_broadcasts的值，执行sysctl -p".format(config_file)

        try:
            param = 'net.ipv4.icmp_echo_ignore_broadcasts'
            public.ExecShell("sed -i '/^{}/d' {}".format(param, config_file))
            public.ExecShell("echo '{} = 1' >> {}".format(param, config_file))
            public.ExecShell("sysctl -w {}=1".format(param))

            result["status"] = True
            result["msg"] = "已设置忽略广播ping"

        except Exception as e:
            # public.print_log("设置忽略广播ping异常：{}".format(e))
            pass

        return result

    def sw_ipv4_log_martians_enabled(self):
        '''
        @name 启用可疑数据包日志
        '''
        result = {"status": False, "msg": "设置可疑数据包日志失败,请手动设置"}
        config_file = "/etc/sysctl.conf"

        self.one_repair_data["describe"] = "启用可疑数据包日志<br/>net.ipv4.conf.all.log_martians=1"
        self.one_repair_data["recover"] = "打开文件【{}】修改net.ipv4.conf.all.log_martians的值，执行sysctl -p".format(
            config_file)

        try:
            for param in ['net.ipv4.conf.all.log_martians', 'net.ipv4.conf.default.log_martians']:
                public.ExecShell("sed -i '/^{}/d' {}".format(param, config_file))
                public.ExecShell("echo '{} = 1' >> {}".format(param, config_file))
                public.ExecShell("sysctl -w {}=1".format(param))

            public.ExecShell("sysctl -w net.ipv4.route.flush=1 2>/dev/null")

            result["status"] = True
            result["msg"] = "已启用可疑数据包日志"

        except Exception as e:
            # public.print_log("设置可疑数据包日志异常：{}".format(e))
            pass

        return result

    def sw_ipv4_send_redirects_disabled(self):
        '''
        @name 禁止发送ICMP重定向
        '''
        result = {"status": False, "msg": "设置禁止发送ICMP重定向失败,请手动设置"}
        config_file = "/etc/sysctl.conf"

        self.one_repair_data["describe"] = "禁止发送ICMP重定向<br/>net.ipv4.conf.all.send_redirects=0"
        self.one_repair_data["recover"] = "打开文件【{}】修改net.ipv4.conf.all.send_redirects的值，执行sysctl -p".format(
            config_file)

        try:
            for param in ['net.ipv4.conf.all.send_redirects', 'net.ipv4.conf.default.send_redirects']:
                public.ExecShell("sed -i '/^{}/d' {}".format(param, config_file))
                public.ExecShell("echo '{} = 0' >> {}".format(param, config_file))
                public.ExecShell("sysctl -w {}=0".format(param))

            public.ExecShell("sysctl -w net.ipv4.route.flush=1 2>/dev/null")

            result["status"] = True
            result["msg"] = "已禁止发送ICMP重定向"

        except Exception as e:
            # public.print_log("设置禁止发送ICMP重定向异常：{}".format(e))
            pass

        return result

    # ============================================================
    # 新增：IPv6网络参数修复方法（2项）
    # ============================================================

    def _is_ipv6_enabled(self):
        """
        检查IPv6是否启用
        @return: bool
        """
        return os.path.exists('/proc/net/if_inet6')

    def sw_ipv6_redirects_not_accept(self):
        '''
        @name 禁止IPv6 ICMP重定向
        '''
        # 首先检查IPv6是否启用
        if not self._is_ipv6_enabled():
            return {"status": True, "msg": "IPv6未启用，无需配置"}

        result = {"status": False, "msg": "设置IPv6 ICMP重定向失败,请手动设置"}
        config_file = "/etc/sysctl.conf"

        self.one_repair_data["describe"] = "禁止IPv6 ICMP重定向<br/>net.ipv6.conf.all.accept_redirects=0"
        self.one_repair_data["recover"] = "打开文件【{}】修改net.ipv6.conf.all.accept_redirects的值，执行sysctl -p".format(
            config_file)

        try:
            for param in ['net.ipv6.conf.all.accept_redirects', 'net.ipv6.conf.default.accept_redirects']:
                public.ExecShell("sed -i '/^{}/d' {}".format(param, config_file))
                public.ExecShell("echo '{} = 0' >> {}".format(param, config_file))
                public.ExecShell("sysctl -w {}=0 2>/dev/null".format(param))

            public.ExecShell("sysctl -w net.ipv6.route.flush=1 2>/dev/null")

            result["status"] = True
            result["msg"] = "已禁止IPv6 ICMP重定向"

        except Exception as e:
            # public.print_log("设置IPv6 ICMP重定向异常：{}".format(e))
            pass

        return result

    def sw_ipv6_accept_ra_disabled(self):
        '''
        @name 禁止IPv6路由器通告
        '''
        # 首先检查IPv6是否启用
        if not self._is_ipv6_enabled():
            return {"status": True, "msg": "IPv6未启用，无需配置"}

        result = {"status": False, "msg": "设置IPv6路由器通告失败,请手动设置"}
        config_file = "/etc/sysctl.conf"

        self.one_repair_data["describe"] = "禁止IPv6路由器通告<br/>net.ipv6.conf.all.accept_ra=0"
        self.one_repair_data["recover"] = "打开文件【{}】修改net.ipv6.conf.all.accept_ra的值，执行sysctl -p".format(
            config_file)

        try:
            for param in ['net.ipv6.conf.all.accept_ra', 'net.ipv6.conf.default.accept_ra']:
                public.ExecShell("sed -i '/^{}/d' {}".format(param, config_file))
                public.ExecShell("echo '{} = 0' >> {}".format(param, config_file))
                public.ExecShell("sysctl -w {}=0 2>/dev/null".format(param))

            public.ExecShell("sysctl -w net.ipv6.route.flush=1 2>/dev/null")

            result["status"] = True
            result["msg"] = "已禁止IPv6路由器通告"

        except Exception as e:
            # public.print_log("设置IPv6路由器通告异常：{}".format(e))
            pass

        return result

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
                        file.write("\nLoginGraceTime 60\n")
                    result, err = public.ExecShell("systemctl restart sshd")
                    if err != "":
                        return {"status": False, "msg": "添加ssh登录超时配置失败",
                                "type": ["请先关闭系统加固，修复完后再开启"]}
                    return {"status": True, "msg": "添加ssh登录超时配置成功"}
            except:
                return {"status": False, "msg": "添加ssh登录超时配置失败", "type": ["请先关闭系统加固，修复完后再开启"]}
        self.one_repair_data["describe"] = "添加ssh登录超时60秒配置"
        self.one_repair_data[
            "recover"] = "打开文件【/etc/ssh/sshd_config】删除LoginGraceTime 60<br/>并执行命令重启ssh服务systemctl restart sshd"
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
            return {"status": False, "msg": "以下文件关闭空密码sudo提权失败：".format('、'.join(fail_file)),
                    "type": ["请先关闭系统加固，修复完后再开启"]}
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
        self.one_repair_data[
            "recover"] = "执行命令：【echo 1 > /proc/sys/fs/suid_dumpable】<br/>【sysctl -w fs.suid_dumpable=1】"
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
        # 检查PHP目录是否存在
        if not os.path.exists(path):
            return {"status": True, "msg": "PHP未安装，无需修复"}

        repair_list = []  # 修复历史
        # 获取目录下的文件夹
        dirs = os.listdir(path)
        fail_list = []
        disa_fun = ["system", "exec", "passthru", "shell_exec", "popen", "proc_open", "putenv"]
        for dir in dirs:
            # 动态检测是否为有效的PHP版本目录（检查php.ini是否存在）
            file_path = os.path.join(path, dir, "etc", "php.ini")
            if os.path.exists(file_path):
                try:
                    php_ini = public.readFile(file_path)
                    if not php_ini:
                        continue
                    rep = "\ndisable_functions\\s?=\\s*(.+)"
                    if re.search(rep, php_ini):
                        # 提取现有禁用函数列表
                        old_value = re.findall(rep, php_ini)[0].strip()
                        # 去除引号和空格，按逗号分割
                        old_value_clean = old_value.strip().strip('"').strip("'")
                        disable_functions = [f.strip() for f in old_value_clean.split(",") if f.strip()]
                        # 添加缺失的危险函数
                        new_disable_functions = disable_functions[:] if disable_functions else []
                        for i2 in disa_fun:
                            if i2 not in disable_functions:
                                new_disable_functions.append(i2)
                                repair_list.append("php版本：{}；禁用函数：{}".format(dir, i2))
                        # 替换整行配置
                        new_value = ",".join(new_disable_functions)
                        new_php = re.sub(rep, "\ndisable_functions = {}".format(new_value), php_ini, count=1)
                        if not public.writeFile(file_path, new_php):
                            fail_list.append(file_path)
                    else:
                        # 不存在配置时追加
                        new_value = ",".join(disa_fun)
                        php_ini = php_ini + "\ndisable_functions = {}\n".format(new_value)
                        if public.writeFile(file_path, php_ini):
                            for i2 in disa_fun:
                                repair_list.append("php版本：{}；禁用函数：{}".format(dir, i2))
                        else:
                            fail_list.append(file_path)
                except Exception as e:
                    fail_list.append(file_path)
                    # public.print_log("修复 PHP {} disable_functions 失败: {}".format(dir, e))
        if len(fail_list) > 0:
            return {"status": False,
                    "msg": "以下PHP文件修复失败，请检查是否被系统加固拦截，并关闭系统加固后再尝试修复：<br/>{}".format(
                        '<br/>'.join(fail_list))}
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
                    c_result = re.sub(tmp[0], tmp[0] + " remember=3", conf)
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
        # 检查PHP目录是否存在
        if not os.path.exists(path):
            return {"status": True, "msg": "PHP未安装，无需修复"}

        # 获取目录下的文件夹
        dirs = os.listdir(path)
        repair_resulit = []
        fail_list = []
        for dir in dirs:
            # 动态检测是否为有效的PHP版本目录（检查php.ini是否存在）
            file_path = os.path.join(path, dir, "etc", "php.ini")
            if os.path.exists(file_path):
                try:
                    php_ini = public.readFile(file_path)
                    if not php_ini:
                        continue
                    rep = "\nallow_url_include\\s*=\\s*(\\S+)"
                    if re.search(rep, php_ini):
                        # 使用 \S+ 匹配非空白字符（支持空值、数字等）
                        new_php = re.sub(rep, "\nallow_url_include = Off", php_ini, count=1)
                        tmp = public.WriteFile(file_path, new_php)
                        repair_resulit.append(dir)
                        if not tmp:
                            fail_list.append(dir)
                    else:
                        # 不存在配置时追加
                        php_ini = php_ini + "\nallow_url_include = Off\n"
                        tmp = public.WriteFile(file_path, php_ini)
                        repair_resulit.append(dir)
                        if not tmp:
                            fail_list.append(dir)
                except Exception as e:
                    fail_list.append(dir)
                    # public.print_log("修复 PHP {} allow_url_include 失败: {}".format(dir, e))
        self.one_repair_data["describe"] = "修复以下php远程包含风险：<br>{}".format('、'.join(repair_resulit))
        self.one_repair_data["recover"] = "打开面板软件商店-运行环境-对应php管理器-配置文件-修改allow_url_include = On"
        if fail_list:
            return {"status": False, "msg": "修复失败，请临时关闭系统加固，等修复完成后再开启"}
        return {"status": True, "msg": "修复远程包含风险成功"}

    def sw_icmp_ignore_bogus(self):
        '''
        @name 忽略伪造的ICMP响应
        '''
        # 调用现有方法
        return self.sw_ipv4_icmp_ignore_bogus_enabled()

    def sw_icmp_echo_ignore_broadcasts(self):
        '''
        @name 忽略广播ping
        '''
        # 调用现有方法
        return self.sw_ipv4_icmp_echo_ignore_broadcasts()

    def sw_telnet_client_not_installed(self):
        '''
        @name 卸载telnet客户端
        '''
        result = {"status": False, "msg": "卸载telnet客户端失败,请手动设置"}
        self.one_repair_data["describe"] = "卸载telnet客户端"
        self.one_repair_data[
            "recover"] = "重新安装telnet客户端：<br/>CentOS/RHEL: yum install telnet<br/>Debian/Ubuntu: apt-get install telnet"

        try:
            # 定义需要卸载的包名列表
            packages = ['telnet', 'inetutils-telnet', 'telnet-server', 'telnetd', 'krb5-telnet']

            if "centos" in self.sys_version or "alicloud" in self.sys_version:
                # CentOS/RHEL 系统
                for pkg in packages:
                    out, err = public.ExecShell('yum remove -y {} 2>&1'.format(pkg))

            elif "ubuntu" in self.sys_version or "debian" in self.sys_version:
                # Debian/Ubuntu 系统
                for pkg in packages:
                    out, err = public.ExecShell('apt-get remove -y {} 2>&1'.format(pkg))

            elif os.path.exists('/usr/bin/apt-get'):
                # 回退：检测到 apt-get，使用 apt
                for pkg in packages:
                    out, err = public.ExecShell('apt-get remove -y {} 2>&1'.format(pkg))

            elif os.path.exists('/usr/bin/yum'):
                # 回退：检测到 yum，使用 yum
                for pkg in packages:
                    out, err = public.ExecShell('yum remove -y {} 2>&1'.format(pkg))

            else:
                # 不支持的系统
                return {"status": False, "msg": "当前系统暂不支持此修复项"}

            # 验证删除结果：检查 telnet 命令是否还存在
            telnet_path, _ = public.ExecShell('which telnet 2>/dev/null')
            telnet_path = telnet_path.strip()

            if not telnet_path or 'not found' in telnet_path.lower():
                result["status"] = True
                result["msg"] = "telnet客户端卸载成功"
            else:
                result["msg"] = "telnet命令仍然存在: {}".format(telnet_path)

        except Exception as e:
            # public.print_log("卸载telnet客户端异常：{}".format(e))
            pass

        return result

    def sw_tcp_wrappers_installed(self):
        '''
        @name 安装TCP Wrappers
        '''
        result = {"status": False, "msg": "安装TCP Wrappers失败,请手动设置"}
        self.one_repair_data["describe"] = "安装TCP Wrappers"
        self.one_repair_data[
            "recover"] = "如需卸载：<br/>CentOS: yum remove tcp_wrappers<br/>Ubuntu/Debian: apt-get remove tcpd"

        try:
            if "centos" in self.sys_version or "alicloud" in self.sys_version:
                out, err = public.ExecShell('yum install -y tcp_wrappers')
                if not err or ('Already installed' in out or 'Complete!' in out or 'Installed:' in out):
                    result["status"] = True
                    result["msg"] = "TCP Wrappers安装成功"

            elif "ubuntu" in self.sys_version or "debian" in self.sys_version:
                out, err = public.ExecShell('apt-get install -y tcpd')
                if not err or ('is already the newest' in out.lower() or 'tcpd is already installed' in out.lower()):
                    result["status"] = True
                    result["msg"] = "TCP Wrappers安装成功"

            elif os.path.exists('/usr/bin/apt-get'):
                # 回退：检测到 apt-get，使用 apt
                out, err = public.ExecShell('apt-get install -y tcpd')
                if not err or ('is already the newest' in out.lower() or 'tcpd is already installed' in out.lower()):
                    result["status"] = True
                    result["msg"] = "TCP Wrappers安装成功"

            elif os.path.exists('/usr/bin/yum'):
                # 回退：检测到 yum，使用 yum
                out, err = public.ExecShell('yum install -y tcp_wrappers')
                if not err or ('Already installed' in out or 'Complete!' in out or 'Installed:' in out):
                    result["status"] = True
                    result["msg"] = "TCP Wrappers安装成功"

            else:
                # 不支持的系统
                return {"status": False, "msg": "当前系统暂不支持此修复项"}

        except Exception as e:
            # public.print_log("安装TCP Wrappers异常：{}".format(e))
            pass

        return result

    def sw_time_sync_used(self):
        '''
        @name 配置时间同步服务
        '''
        result = {"status": False, "msg": "配置时间同步失败,请手动设置"}
        self.one_repair_data["describe"] = "安装并配置chrony时间同步服务"
        self.one_repair_data["recover"] = "如需禁用时间同步：<br/>systemctl stop chronyd && systemctl disable chronyd"

        try:
            # 优先使用chrony
            if "centos" in self.sys_version or "alicloud" in self.sys_version:
                # 安装chrony
                out, err = public.ExecShell('yum install -y chrony')
                if 'Complete!' in out or 'Already installed' in out or not err:
                    # 配置chrony
                    conf_file = '/etc/chrony.conf'
                    conf = public.readFile(conf_file) or ''
                    # 检查是否已有server配置
                    if not conf or 'server ' not in conf:
                        # 添加默认服务器池
                        default_servers = [
                            'server 0.pool.ntp.org iburst',
                            'server 1.pool.ntp.org iburst',
                            'server 2.pool.ntp.org iburst',
                            'server 3.pool.ntp.org iburst'
                        ]
                        new_conf = '\n'.join(default_servers) + '\n'
                        if conf:
                            new_conf = conf + '\n' + new_conf
                        public.WriteFile(conf_file, new_conf)
                    # 启动并启用服务
                    public.ExecShell('systemctl enable chronyd')
                    public.ExecShell('systemctl start chronyd')
                    result["status"] = True
                    result["msg"] = "chrony时间同步服务安装并启动成功"

            elif "ubuntu" in self.sys_version or "debian" in self.sys_version:
                # 安装chrony
                out, err = public.ExecShell('apt-get install -y chrony')
                if 'is already the newest' in out.lower() or 'chrony is already installed' in out.lower() or not err:
                    # 配置chrony
                    conf_file = '/etc/chrony.conf'
                    conf = public.readFile(conf_file) or ''
                    # 检查是否已有server配置
                    if not conf or 'server ' not in conf:
                        # 添加默认服务器池
                        default_servers = [
                            'server 0.pool.ntp.org iburst',
                            'server 1.pool.ntp.org iburst',
                            'server 2.pool.ntp.org iburst',
                            'server 3.pool.ntp.org iburst'
                        ]
                        new_conf = '\n'.join(default_servers) + '\n'
                        if conf:
                            new_conf = conf + '\n' + new_conf
                        public.WriteFile(conf_file, new_conf)
                    # 启动并启用服务
                    public.ExecShell('systemctl enable chrony')
                    public.ExecShell('systemctl start chrony')
                    result["status"] = True
                    result["msg"] = "chrony时间同步服务安装并启动成功"

            elif os.path.exists('/usr/bin/apt-get'):
                # 回退：检测到 apt-get，使用 apt
                out, err = public.ExecShell('apt-get install -y chrony')
                if 'is already the newest' in out.lower() or 'chrony is already installed' in out.lower() or not err:
                    # 配置chrony
                    conf_file = '/etc/chrony.conf'
                    conf = public.readFile(conf_file) or ''
                    if not conf or 'server ' not in conf:
                        default_servers = [
                            'server 0.pool.ntp.org iburst',
                            'server 1.pool.ntp.org iburst',
                            'server 2.pool.ntp.org iburst',
                            'server 3.pool.ntp.org iburst'
                        ]
                        new_conf = '\n'.join(default_servers) + '\n'
                        if conf:
                            new_conf = conf + '\n' + new_conf
                        public.WriteFile(conf_file, new_conf)
                    # 启动并启用服务
                    public.ExecShell('systemctl enable chrony')
                    public.ExecShell('systemctl start chrony')
                    result["status"] = True
                    result["msg"] = "chrony时间同步服务安装并启动成功"

            elif os.path.exists('/usr/bin/yum'):
                # 回退：检测到 yum，使用 yum
                out, err = public.ExecShell('yum install -y chrony')
                if 'Complete!' in out or 'Already installed' in out or not err:
                    # 配置chrony
                    conf_file = '/etc/chrony.conf'
                    conf = public.readFile(conf_file) or ''
                    if not conf or 'server ' not in conf:
                        default_servers = [
                            'server 0.pool.ntp.org iburst',
                            'server 1.pool.ntp.org iburst',
                            'server 2.pool.ntp.org iburst',
                            'server 3.pool.ntp.org iburst'
                        ]
                        new_conf = '\n'.join(default_servers) + '\n'
                        if conf:
                            new_conf = conf + '\n' + new_conf
                        public.WriteFile(conf_file, new_conf)
                    # 启动并启用服务
                    public.ExecShell('systemctl enable chronyd')
                    public.ExecShell('systemctl start chronyd')
                    result["status"] = True
                    result["msg"] = "chrony时间同步服务安装并启动成功"

            else:
                # 不支持的系统
                return {"status": False, "msg": "当前系统暂不支持此修复项"}

        except Exception as e:
            # public.print_log("配置时间同步异常：{}".format(e))
            pass

        return result

    def sw_ssh_banner(self):
        '''
        @name 设置SSH登录警告Banner
        '''
        import ssh_security
        ssh_security = ssh_security.ssh_security()
        ssh_config_file = "/etc/ssh/sshd_config"
        banner_file = "/etc/issue.net"

        result = {"status": False, "msg": "设置SSH Banner失败,请手动设置"}
        self.one_repair_data["describe"] = "设置SSH登录警告Banner：<br/>【{}】Banner {}<br/>创建Banner文件".format(
            ssh_config_file, banner_file)
        self.one_repair_data["recover"] = "打开文件【{}】删除或注释Banner行".format(ssh_config_file)

        try:
            # 创建默认Banner文件（如果不存在）
            if not os.path.exists(banner_file):
                banner_content = """*******************************************************************************
                            *  未经授权，禁止访问此系统。所有访问将被记录和监控。         *
                            *  Unauthorized access is prohibited. All access is logged.     *
                            *******************************************************************************"""
                public.WriteFile(banner_file, banner_content)

            # 修改SSH配置
            f_data = public.readFile(ssh_config_file)
            if not f_data:
                return result

            # 移除已有的Banner配置（包括被注释的）
            lines = []
            for line in f_data.split('\n'):
                if not line.strip().startswith('Banner'):
                    lines.append(line)

            # 添加新的Banner配置
            lines.append('Banner {}'.format(banner_file))
            file_result = '\n'.join(lines)
            public.writeFile(ssh_config_file, file_result)

            # 重启SSH服务
            ssh_security.restart_ssh()

            # 验证
            f_data = public.readFile(ssh_config_file)
            if 'Banner {}'.format(banner_file) in f_data and os.path.exists(banner_file):
                result["status"] = True
                result["msg"] = "已设置SSH登录警告Banner"
        except Exception as e:
            # public.print_log("设置SSH Banner异常：{}".format(e))
            pass

        return result

    def sw_ssh_ignore_rhosts(self):
        '''
        @name 启用SSH IgnoreRhosts
        '''
        import ssh_security
        ssh_security = ssh_security.ssh_security()
        file = "/etc/ssh/sshd_config"

        result = {"status": False, "msg": "启用SSH IgnoreRhosts失败,请手动设置"}
        self.one_repair_data["describe"] = "启用SSH IgnoreRhosts：<br/>【{}】IgnoreRhosts yes".format(file)
        self.one_repair_data["recover"] = "打开文件【{}】删除或修改IgnoreRhosts行".format(file)

        try:
            f_data = public.readFile(file)
            if not f_data:
                return result

            # 移除已有的IgnoreRhosts配置（使用负向前瞻过滤注释）
            lines = []
            for line in f_data.split('\n'):
                if not re.search(r'^\s*(?!#)\s*IgnoreRhosts\s+', line):
                    lines.append(line)

            # 添加新的IgnoreRhosts配置
            lines.append('IgnoreRhosts yes')
            file_result = '\n'.join(lines)
            public.writeFile(file, file_result)

            # 重启SSH服务
            ssh_security.restart_ssh()

            # 验证
            f_data = public.readFile(file)
            if re.search(r'^\s*IgnoreRhosts\s+yes', f_data, re.M):
                result["status"] = True
                result["msg"] = "已启用SSH IgnoreRhosts"
        except Exception as e:
            # public.print_log("启用SSH IgnoreRhosts异常：{}".format(e))
            pass

        return result

    def sw_ssh_permit_env(self):
        '''
        @name 禁用SSH PermitUserEnvironment
        '''
        import ssh_security
        ssh_security = ssh_security.ssh_security()
        file = "/etc/ssh/sshd_config"

        result = {"status": False, "msg": "禁用PermitUserEnvironment失败,请手动设置"}
        self.one_repair_data["describe"] = "禁用SSH PermitUserEnvironment：<br/>【{}】PermitUserEnvironment no".format(
            file)
        self.one_repair_data["recover"] = "打开文件【{}】将PermitUserEnvironment no改为yes".format(file)

        try:
            f_data = public.readFile(file)
            if not f_data:
                return result

            # 移除已有的PermitUserEnvironment配置
            lines = []
            for line in f_data.split('\n'):
                if not line.strip().startswith('PermitUserEnvironment'):
                    lines.append(line)

            # 添加禁用配置
            lines.append('\nPermitUserEnvironment no')
            file_result = '\n'.join(lines)
            public.writeFile(file, file_result)

            # 重启SSH服务
            ssh_security.restart_ssh()

            # 验证
            f_data = public.readFile(file)
            if re.search(r'^\s*PermitUserEnvironment\s+no', f_data, re.M):
                result["status"] = True
                result["msg"] = "已禁用SSH PermitUserEnvironment"
        except Exception as e:
            # public.print_log("禁用SSH PermitUserEnvironment异常：{}".format(e))
            pass

        return result

    def sw_ssh_ciphers(self):
        '''
        @name 设置SSH加密套件为强算法
        '''
        import ssh_security
        ssh_security = ssh_security.ssh_security()
        file = "/etc/ssh/sshd_config"

        result = {"status": False, "msg": "设置SSH加密套件失败,请手动设置"}
        self.one_repair_data["describe"] = "设置SSH加密套件：<br/>【{}】Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr".format(file)
        self.one_repair_data["recover"] = "打开文件【{}】删除或修改Ciphers行".format(file)

        try:
            f_data = public.readFile(file)
            if not f_data:
                return result

            # 移除已有的Ciphers配置
            lines = []
            for line in f_data.split('\n'):
                if not re.search(r'^\s*(?!#)\s*Ciphers\s+', line):
                    lines.append(line)

            # 添加强加密套件配置
            lines.append('\nCiphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr')
            file_result = '\n'.join(lines)
            public.writeFile(file, file_result)

            # 重启SSH服务
            ssh_security.restart_ssh()

            # 验证
            f_data = public.readFile(file)
            if re.search(r'^\s*Ciphers\s+aes256-gcm', f_data, re.M):
                result["status"] = True
                result["msg"] = "设置SSH加密套件成功"
        except Exception as e:
            # public.print_log("修复异常：{}".format(e))
            pass

        return result

    def sw_ssh_kexalgorithms(self):
        '''
        @name 设置SSH密钥交换算法为强算法
        '''
        import ssh_security
        ssh_security = ssh_security.ssh_security()
        file = "/etc/ssh/sshd_config"

        result = {"status": False, "msg": "设置SSH密钥交换算法失败,请手动设置"}
        self.one_repair_data["describe"] = "设置SSH密钥交换算法：<br/>【{}】KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256".format(file)
        self.one_repair_data["recover"] = "打开文件【{}】删除或修改KexAlgorithms行".format(file)

        try:
            # 仅CentOS系统检测（与检测项保持一致）
            if not os.path.exists('/etc/centos-release'):
                result["status"] = True
                result["msg"] = "非CentOS系统，无需修复"
                return result

            f_data = public.readFile(file)
            if not f_data:
                return result

            # 移除已有的KexAlgorithms配置
            lines = []
            for line in f_data.split('\n'):
                if not re.search(r'^\s*(?!#)\s*KexAlgorithms\s+', line):
                    lines.append(line)

            # 添加强密钥交换算法配置
            lines.append('\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256')
            file_result = '\n'.join(lines)
            public.writeFile(file, file_result)

            # 重启SSH服务
            ssh_security.restart_ssh()

            # 验证
            f_data = public.readFile(file)
            if re.search(r'^\s*KexAlgorithms\s+curve25519-sha256', f_data, re.M):
                result["status"] = True
                result["msg"] = "设置SSH密钥交换算法成功"
        except Exception as e:
            # public.print_log("修复异常：{}".format(e))
            pass

        return result

    def sw_ssh_hostbased(self):
        '''
        @name 禁用SSH基于主机的认证
        '''
        import ssh_security
        ssh_security = ssh_security.ssh_security()
        file = "/etc/ssh/sshd_config"

        result = {"status": False, "msg": "禁用HostbasedAuthentication失败,请手动设置"}
        self.one_repair_data["describe"] = "禁用SSH基于主机的认证：<br/>【{}】HostbasedAuthentication no".format(file)
        self.one_repair_data["recover"] = "打开文件【{}】将HostbasedAuthentication no改为yes".format(file)

        try:
            f_data = public.readFile(file)
            if not f_data:
                return result

            # 移除已有的HostbasedAuthentication配置
            lines = []
            for line in f_data.split('\n'):
                if not re.search(r'^\s*(?!#)\s*HostbasedAuthentication\s+', line):
                    lines.append(line)

            # 添加禁用配置
            lines.append('\nHostbasedAuthentication no')
            file_result = '\n'.join(lines)
            public.writeFile(file, file_result)

            # 重启SSH服务
            ssh_security.restart_ssh()

            # 验证
            f_data = public.readFile(file)
            if re.search(r'^\s*HostbasedAuthentication\s+no', f_data, re.M):
                result["status"] = True
                result["msg"] = "禁用HostbasedAuthentication成功"
        except Exception as e:
            # public.print_log("修复异常：{}".format(e))
            pass

        return result

    def sw_ipv4_redirects_not_accept(self):
        '''
        @name 禁止IPv4 ICMP重定向
        '''
        result = {"status": False, "msg": "禁止ICMP重定向失败,请手动设置"}
        config_file = "/etc/sysctl.conf"

        self.one_repair_data[
            "describe"] = "禁止IPv4 ICMP重定向<br/>net.ipv4.conf.all.accept_redirects=0<br/>net.ipv4.conf.default.accept_redirects=0"
        self.one_repair_data["recover"] = "打开文件【{}】修改accept_redirects的值，执行sysctl -p".format(config_file)

        try:
            params = [
                'net.ipv4.conf.all.accept_redirects',
                'net.ipv4.conf.default.accept_redirects'
            ]
            for param in params:
                # 删除旧配置
                public.ExecShell("sed -i '/^{}/d' {}".format(param, config_file))
                # 添加新配置
                public.ExecShell("echo '{} = 0' >> {}".format(param, config_file))
                # 立即生效
                public.ExecShell("sysctl -w {}=0".format(param))

            # 刷新路由表
            public.ExecShell("sysctl -w net.ipv4.route.flush=1")

            result["status"] = True
            result["msg"] = "已禁止IPv4 ICMP重定向"

        except Exception as e:
            # public.print_log("禁止ICMP重定向异常：{}".format(e))
            pass

        return result

    def sw_ipv6_accept_source_route_disabled(self):
        '''
        @name 禁止IPv6源路由
        '''
        result = {"status": False, "msg": "禁止IPv6源路由失败,请手动设置"}
        config_file = "/etc/sysctl.conf"

        self.one_repair_data[
            "describe"] = "禁止IPv6源路由<br/>net.ipv6.conf.all.accept_source_route=0<br/>net.ipv6.conf.default.accept_source_route=0"
        self.one_repair_data["recover"] = "打开文件【{}】修改accept_source_route的值，执行sysctl -p".format(config_file)

        try:
            # 检查IPv6是否启用
            if not os.path.exists('/proc/net/if_inet6'):
                result["status"] = True
                result["msg"] = "IPv6未启用，跳过配置"
                return result

            params = [
                'net.ipv6.conf.all.accept_source_route',
                'net.ipv6.conf.default.accept_source_route'
            ]
            for param in params:
                # 删除旧配置
                public.ExecShell("sed -i '/^{}/d' {}".format(param, config_file))
                # 添加新配置
                public.ExecShell("echo '{} = 0' >> {}".format(param, config_file))
                # 立即生效
                public.ExecShell("sysctl -w {}=0".format(param))

            # 刷新路由表
            public.ExecShell("sysctl -w net.ipv6.route.flush=1")

            result["status"] = True
            result["msg"] = "已禁止IPv6源路由"

        except Exception as e:
            # public.print_log("禁止IPv6源路由异常：{}".format(e))
            pass

        return result

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
            else:
                # Ubuntu 未知版本，返回通用标识
                sys_version = "ubuntu_unknown"
        elif os.path.exists("/etc/debian_version"):
            result = public.ReadFile("/etc/debian_version")
            if "10." in result:
                sys_version = "debian_10"
            elif "11." in result:
                sys_version = "debian_11"
            elif "12." in result:
                sys_version = "debian_12"
            elif "13." in result or "trixie" in result.lower():
                sys_version = "debian_13"
            else:
                # Debian 未知版本，返回通用标识
                sys_version = "debian_unknown"
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
        output, err = public.ExecShell("rpm -q '%{NAME};%{VERSION}-%{RELEASE}\n' " + ' '.join(pkg_list))
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

    # ============================================================
    # 回滚相关方法（从panelWarning.py迁移）
    # ============================================================

    def get_rollback_info(self, get):
        """
        @name 获取可回滚的修复信息
        @param get
        @return dict
        """
        rollback_file = self.__rollback_file

        # 检查回滚记录是否存在
        if not os.path.exists(rollback_file):
            return public.returnMsg(False, '没有可回滚的修复记录')

        try:
            rollback_data = json.loads(public.ReadFile(rollback_file))
            return public.returnMsg(True, rollback_data)
        except:
            return public.returnMsg(False, '回滚记录文件损坏')

    def get_repair_records(self, get):
        """
        @name 获取修复记录列表
        @param get
        @return dict
        """
        try:
            data = self._read_repair_records()
            records = data.get('records', [])

            # 格式化返回数据
            result_list = []
            for record in records:
                # 检查备份文件是否都存在
                can_rollback = True
                for backup in record.get('backups', []):
                    backup_path = backup.get('backup_path')
                    if backup_path and not os.path.exists(backup_path):
                        can_rollback = False
                        break

                result_list.append({
                    'repair_id': record.get('repair_id'),
                    'repair_time': record.get('repair_time'),
                    'repair_items': record.get('repair_items', []),
                    'item_count': len(record.get('repair_items', [])),
                    'can_rollback': can_rollback
                })
            return {
                "status": True,
                "data": result_list
            }
        except Exception as e:
            return public.returnMsg(False, '获取修复记录失败: {}'.format(str(e)))

    def get_repair_detail(self, get):
        """
        @name 获取单条修复记录详情
        @param get.repair_id 修复记录ID
        @return dict
        """
        if not hasattr(get, 'repair_id') or not get.repair_id:
            return public.returnMsg(False, '请提供修复记录ID')

        try:
            data = self._read_repair_records()
            records = data.get('records', [])

            # 查找指定记录
            target_record = None
            for record in records:
                if record.get('repair_id') == get.repair_id:
                    target_record = record
                    break

            if not target_record:
                return public.returnMsg(False, '未找到指定的修复记录')

            # 格式化返回数据
            backups = []
            for backup in target_record.get('backups', []):
                backup_path = backup.get('backup_path')
                backups.append({
                    'm_name': backup.get('m_name'),
                    'backup_path': backup_path,
                    'backup_exists': os.path.exists(backup_path) if backup_path else False,
                    'original_path': backup.get('original_path', ''),
                    'restore_cmd': backup.get('restore_cmd', '')
                })

            result = {
                'repair_id': target_record.get('repair_id'),
                'repair_time': public.format_date(times=target_record.get('repair_time')),
                'repair_items': target_record.get('repair_items', []),
                'backups': backups
            }

            return public.returnMsg(True, result)
        except Exception as e:
            return public.returnMsg(False, '获取修复记录详情失败: {}'.format(str(e)))

    def delete_repair_records(self, get):
        """
        @name 删除修复记录
        @param get.ids 要删除的记录ID，多个用逗号分隔，或"all"表示全部删除
        @return dict
        """
        if not hasattr(get, 'ids') or not get.ids:
            return public.returnMsg(False, '请提供要删除的记录ID')

        try:
            data = self._read_repair_records()
            records = data.get('records', [])

            deleted_ids = []
            deleted_backups = []

            if get.ids.lower() == 'all':
                # 删除所有记录和备份
                for record in records:
                    deleted_ids.append(record.get('repair_id'))
                    for backup in record.get('backups', []):
                        backup_path = backup.get('backup_path')
                        if backup_path and os.path.exists(backup_path):
                            os.remove(backup_path)
                            deleted_backups.append(backup_path)

                records = []
            else:
                # 删除指定记录
                ids_to_delete = get.ids.split(',')
                new_records = []

                for record in records:
                    if record.get('repair_id') in ids_to_delete:
                        deleted_ids.append(record.get('repair_id'))
                        # 删除对应的备份文件
                        for backup in record.get('backups', []):
                            backup_path = backup.get('backup_path')
                            if backup_path and os.path.exists(backup_path):
                                os.remove(backup_path)
                                deleted_backups.append(backup_path)
                    else:
                        new_records.append(record)

                records = new_records

            # 保存更新后的记录
            data['records'] = records
            self._write_repair_records(data)

            msg = '成功删除{}条记录'.format(len(deleted_ids))
            if deleted_backups:
                msg += '，{}个备份文件'.format(len(deleted_backups))

            return public.returnMsg(True, msg)
        except Exception as e:
            return public.returnMsg(False, '删除修复记录失败: {}'.format(str(e)))

    def rollback_repair(self, get):
        """
        @name 执行回滚操作
        @param get.repair_id 可选，指定要回滚的修复记录ID
        @return dict
        """
        # 优先使用新的修复记录文件
        if os.path.exists(self.__repair_records_file):
            return self._rollback_from_records(get)
        # 回退到旧的回滚文件（兼容性）
        else:
            return self._rollback_from_old_file(get)

    def _rollback_from_records(self, get):
        """从新的修复记录文件中回滚"""
        if not hasattr(get, 'repair_id') or not get.repair_id:
            return public.returnMsg(False, '请提供要回滚的修复记录ID')

        try:
            data = self._read_repair_records()
            records = data.get('records', [])

            # 查找指定的记录
            target_record = None
            target_index = -1
            for i, record in enumerate(records):
                if record.get('repair_id') == get.repair_id:
                    target_record = record
                    target_index = i
                    break

            if not target_record:
                return public.returnMsg(False, '未找到指定的修复记录')

            # 执行回滚
            backups = target_record.get('backups', [])
            restored_items = []
            failed_items = []

            # 按相反顺序执行回滚（后修复的先回滚）
            for backup in reversed(backups):
                restore_cmd = backup.get('restore_cmd')
                m_name = backup.get('m_name')

                if not restore_cmd:
                    failed_items.append(m_name or 'unknown')
                    continue

                try:
                    result, err = public.ExecShell(restore_cmd)
                    if err and 'error' in err.lower():
                        failed_items.append(m_name or 'unknown')
                        # public.print_log("回滚失败: {} - {}".format(m_name, err))
                    else:
                        restored_items.append(m_name or 'unknown')
                except Exception as e:
                    failed_items.append(m_name or 'unknown')
                    # public.print_log("回滚异常: {} - {}".format(m_name, e))

            # 只删除备份文件，保留修复记录（用于历史追溯）
            # 记录保留后，can_rollback 会自动变为 False（因为备份文件不存在）
            # records.pop(target_index)
            # data['records'] = records
            # self._write_repair_records(data)

            # 删除备份文件
            for backup in backups:
                backup_path = backup.get('backup_path')
                if backup_path and os.path.exists(backup_path):
                    try:
                        os.remove(backup_path)
                        # public.print_log("已删除备份文件: {}".format(backup_path))
                    except Exception as e:
                        pass
                        # public.print_log("删除备份文件失败: {} - {}".format(backup_path, e))

            # 返回结果
            if failed_items:
                return public.returnMsg(True, '回滚完成')
            else:
                return public.returnMsg(True, '回滚成功')

        except Exception as e:
            return public.returnMsg(False, '回滚失败：{}'.format(str(e)))

    def _rollback_from_old_file(self, get):
        """从旧的回滚文件中回滚（兼容旧版本）"""
        rollback_file = self.__rollback_file
        rollback_history_file = self.__rollback_dir + '/rollback_history.json'

        # 检查回滚记录是否存在
        if not os.path.exists(rollback_file):
            return public.returnMsg(False, '没有可回滚的修复记录')

        try:
            rollback_data = json.loads(public.ReadFile(rollback_file))
            items = rollback_data.get('items', [])

            # 如果指定了回滚项，只回滚指定的
            specified_items = None
            if hasattr(get, 'items') and get.items:
                specified_items = get.items.split(',')

            restored_items = []
            failed_items = []

            # 按相反顺序执行回滚（后修复的先回滚）
            for item in reversed(items):
                # 如果指定了回滚项，跳过不在列表中的
                if specified_items and item.get('m_name') not in specified_items:
                    continue

                backup_type = item.get('backup_type')
                restore_cmd = item.get('restore_cmd')

                if not restore_cmd:
                    failed_items.append(item.get('m_name', 'unknown'))
                    continue

                try:
                    # 执行恢复命令
                    result, err = public.ExecShell(restore_cmd)
                    restored_items.append(item.get('m_name', 'unknown'))
                except:
                    failed_items.append(item.get('m_name', 'unknown'))

            # 记录回滚历史
            history_entry = {
                'rollback_id': 'rollback_{}'.format(int(time.time())),
                'repair_id': rollback_data.get('repair_id'),
                'rollback_time': int(time.time()),
                'restored_items': restored_items,
                'failed_items': failed_items,
                'status': 'success' if not failed_items else 'partial'
            }

            # 读取现有历史并添加新记录
            history = []
            if os.path.exists(rollback_history_file):
                try:
                    history = json.loads(public.ReadFile(rollback_history_file))
                except:
                    history = []

            history.append(history_entry)

            # 只保留最近50条历史记录
            if len(history) > 50:
                history = history[-50:]

            # 确保目录存在
            if not os.path.exists(self.__rollback_dir):
                os.makedirs(self.__rollback_dir, 384)

            # 写入历史记录
            public.WriteFile(rollback_history_file, json.dumps(history))

            # 返回结果
            if failed_items:
                return public.returnMsg(True, '回滚完成，部分项目失败：成功[{}]，失败[{}]'.format(
                    ','.join(restored_items), ','.join(failed_items)))
            else:
                return public.returnMsg(True, '回滚成功')

        except Exception as e:
            return public.returnMsg(False, '回滚失败：{}'.format(str(e)))

    # ========================================================================
    # 新增修复方法：auditd审计规则（12个 + 1个初始化方法）
    # ========================================================================

    def _ensure_auditd_installed(self):
        """确保auditd已安装（自动安装）"""
        if os.path.exists('/usr/sbin/auditd'):
            return True

        # 根据系统类型选择安装命令
        if os.path.exists('/usr/bin/yum') or os.path.exists('/usr/bin/dnf'):
            result, err = public.ExecShell('yum install -y audit')
            if 'Complete!' in result or 'Already installed' in result:
                return True
        elif os.path.exists('/usr/bin/apt-get'):
            result, err = public.ExecShell('apt-get install -y auditd')
            if err == '':
                return True

        return False

    def _ensure_auditd_log_configured(self):
        """确保auditd日志轮转配置生效"""
        auditd_conf = '/etc/audit/auditd.conf'
        if not os.path.exists(auditd_conf):
            return False

        conf_data = public.readFile(auditd_conf)
        if not conf_data:
            return False

        # 检查是否已配置
        need_update = False
        if 'max_log_file' not in conf_data:
            conf_data = conf_data + '\nmax_log_file = 50\n'
            need_update = True
        elif 'max_log_file =' in conf_data and 'max_log_file = 50' not in conf_data:
            conf_data = re.sub(r'max_log_file\s*=.*\n', 'max_log_file = 50\n', conf_data)
            need_update = True

        if 'num_logs' not in conf_data:
            conf_data = conf_data + '\nnum_logs = 5\n'
            need_update = True
        elif 'num_logs =' in conf_data and 'num_logs = 5' not in conf_data:
            conf_data = re.sub(r'num_logs\s*=.*\n', 'num_logs = 5\n', conf_data)
            need_update = True

        if 'max_log_file_action' not in conf_data:
            conf_data = conf_data + '\nmax_log_file_action = ROTATE\n'
            need_update = True
        elif 'max_log_file_action =' in conf_data and 'max_log_file_action = ROTATE' not in conf_data:
            conf_data = re.sub(r'max_log_file_action\s*=.*\n', 'max_log_file_action = ROTATE\n', conf_data)
            need_update = True

        if need_update:
            public.writeFile(auditd_conf, conf_data)
            # 重启auditd使配置生效
            public.ExecShell('service auditd restart')

        return True

    def _add_audit_rules(self, rules, rule_name):
        """通用审计规则添加方法"""
        # 先确保auditd已安装
        if not self._ensure_auditd_installed():
            return {"status": False, "msg": "auditd安装失败"}

        # 确保日志轮转配置生效
        self._ensure_auditd_log_configured()

        audit_file = "/etc/audit/rules.d/audit.rules"
        audit_data = public.readFile(audit_file) or ''

        added_rules = []
        for rule in rules:
            if rule not in audit_data:
                public.ExecShell("echo '{}' >> {}".format(rule, audit_file))
                added_rules.append(rule)

        if added_rules:
            # 重启auditd
            public.ExecShell('service auditd restart')

        return {"status": True, "msg": "已添加{}审计规则".format(rule_name)}

    def sw_auditd_init(self):
        """auditd初始化 + 日志轮转配置"""
        result = {"status": False, "msg": "auditd初始化失败,请手动设置"}

        self.one_repair_data["describe"] = "安装并配置auditd，设置日志轮转策略"
        self.one_repair_data["recover"] = "卸载auditd或手动修改配置"

        try:
            # 检查是否已安装
            if not self._ensure_auditd_installed():
                return {"status": False, "msg": "auditd安装失败"}

            # 配置日志轮转
            self._ensure_auditd_log_configured()

            result["status"] = True
            result["msg"] = "auditd初始化成功"

        except Exception as e:
            pass
            # public.print_log("auditd初始化异常：{}".format(e))

        return result

    def sw_audit_modules_events(self):
        """内核模块加载/卸载审计"""
        self.one_repair_data["describe"] = "添加内核模块审计规则：insmod/rmmod/modprobe/init_module/delete_module"
        self.one_repair_data["recover"] = "删除 /etc/audit/rules.d/audit.rules 中的modules规则"

        rules = [
            '-w /sbin/insmod -p x -k modules',
            '-w /sbin/rmmod -p x -k modules',
            '-w /sbin/modprobe -p x -k modules',
            '-a always,exit -F arch=b64 -S init_module -S delete_module -k modules'
        ]
        return self._add_audit_rules(rules, 'modules')

    def sw_audit_mounts_events(self):
        """文件系统挂载审计"""
        self.one_repair_data["describe"] = "添加文件系统挂载审计规则：mount系统调用"
        self.one_repair_data["recover"] = "删除 /etc/audit/rules.d/audit.rules 中的mounts规则"

        rules = [
            '-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts',
            '-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts'
        ]
        return self._add_audit_rules(rules, 'mounts')

    def sw_audit_access_failed_events(self):
        """未授权文件访问审计"""
        self.one_repair_data["describe"] = "添加未授权文件访问审计规则：EACCES/EPERM失败记录"
        self.one_repair_data["recover"] = "删除 /etc/audit/rules.d/audit.rules 中的access规则"

        rules = [
            '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access',
            '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access',
            '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access',
            '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access'
        ]
        return self._add_audit_rules(rules, 'access')

    def sw_audit_delete_events(self):
        """文件删除审计"""
        self.one_repair_data["describe"] = "添加文件删除审计规则：unlink/unlinkat/rename/renameat"
        self.one_repair_data["recover"] = "删除 /etc/audit/rules.d/audit.rules 中的delete规则"

        rules = [
            '-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete',
            '-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete'
        ]
        return self._add_audit_rules(rules, 'delete')

    def sw_audit_identity_events(self):
        """用户/组信息修改审计"""
        self.one_repair_data["describe"] = "添加用户/组信息修改审计规则：/etc/passwd、/etc/shadow等"
        self.one_repair_data["recover"] = "删除 /etc/audit/rules.d/audit.rules 中的identity规则"

        rules = [
            '-w /etc/group -p wa -k identity',
            '-w /etc/passwd -p wa -k identity',
            '-w /etc/gshadow -p wa -k identity',
            '-w /etc/shadow -p wa -k identity',
            '-w /etc/security/opasswd -p wa -k identity'
        ]
        return self._add_audit_rules(rules, 'identity')

    def sw_audit_logins_events(self):
        """登录/注销审计"""
        self.one_repair_data["describe"] = "添加登录/注销审计规则：/var/log/lastlog、/var/run/faillock/"
        self.one_repair_data["recover"] = "删除 /etc/audit/rules.d/audit.rules 中的logins规则"

        rules = [
            '-w /var/log/lastlog -p wa -k logins'
        ]
        # faillock目录可能不存在，检查后再添加
        if os.path.exists('/var/run/faillock/'):
            rules.append('-w /var/run/faillock/ -p wa -k logins')

        return self._add_audit_rules(rules, 'logins')

    def sw_audit_mac_policy_events(self):
        """MAC策略修改审计"""
        # 动态检测MAC策略类型（SELinux或AppArmor）
        rules = []
        desc_parts = []

        # 检测SELinux
        if os.path.isdir('/etc/selinux'):
            rules.append('-w /etc/selinux/ -p wa -k MAC-policy')
            desc_parts.append('/etc/selinux/')

        # 检测AppArmor
        if os.path.isdir('/etc/apparmor'):
            rules.append('-w /etc/apparmor/ -p wa -k MAC-policy')
            desc_parts.append('/etc/apparmor/')
        if os.path.isdir('/etc/apparmor.d'):
            rules.append('-w /etc/apparmor.d/ -p wa -k MAC-policy')
            desc_parts.append('/etc/apparmor.d/')

        # 如果都没有，默认添加SELinux规则（兼容未启用MAC的系统）
        if not rules:
            rules.append('-w /etc/selinux/ -p wa -k MAC-policy')
            desc_parts.append('/etc/selinux/（默认）')

        self.one_repair_data["describe"] = "添加MAC策略修改审计规则：" + '、'.join(desc_parts)
        self.one_repair_data["recover"] = "删除 /etc/audit/rules.d/audit.rules 中的MAC-policy规则"

        return self._add_audit_rules(rules, 'MAC-policy')

    def sw_audit_network_env_events(self):
        """网络环境修改审计"""
        self.one_repair_data["describe"] = "添加网络环境修改审计规则：sethostname/setdomainname、/etc/hosts等"
        self.one_repair_data["recover"] = "删除 /etc/audit/rules.d/audit.rules 中的system-locale规则"

        rules = [
            '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale',
            '-w /etc/issue -p wa -k system-locale',
            '-w /etc/issue.net -p wa -k system-locale',
            '-w /etc/hosts -p wa -k system-locale'
        ]

        # CentOS/RHEL特有路径
        if os.path.exists('/etc/sysconfig/network'):
            rules.append('-w /etc/sysconfig/network -p wa -k system-locale')
        if os.path.exists('/etc/sysconfig/network-scripts/'):
            rules.append('-w /etc/sysconfig/network-scripts/ -p wa -k system-locale')

        return self._add_audit_rules(rules, 'system-locale')

    def sw_audit_perm_mod_events(self):
        """权限修改审计"""
        self.one_repair_data["describe"] = "添加权限修改审计规则：chmod/chown/setxattr等"
        self.one_repair_data["recover"] = "删除 /etc/audit/rules.d/audit.rules 中的perm_mod规则"

        rules = [
            '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod',
            '-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod',
            '-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod',
            '-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod',
            '-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod',
            '-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod'
        ]
        return self._add_audit_rules(rules, 'perm_mod')

    def sw_audit_session_events(self):
        """会话启动审计"""
        self.one_repair_data["describe"] = "添加会话启动审计规则：/var/run/utmp、/var/log/wtmp、/var/log/btmp"
        self.one_repair_data["recover"] = "删除 /etc/audit/rules.d/audit.rules 中的session/logins规则"

        rules = [
            '-w /var/run/utmp -p wa -k session',
            '-w /var/log/wtmp -p wa -k logins',
            '-w /var/log/btmp -p wa -k logins'
        ]
        return self._add_audit_rules(rules, 'session')

    def sw_audit_sudoers_scope_events(self):
        """sudoers变更审计"""
        self.one_repair_data["describe"] = "添加sudoers变更审计规则：/etc/sudoers、/etc/sudoers.d/"
        self.one_repair_data["recover"] = "删除 /etc/audit/rules.d/audit.rules 中的scope规则"

        rules = [
            '-w /etc/sudoers -p wa -k scope',
            '-w /etc/sudoers.d/ -p wa -k scope'
        ]
        return self._add_audit_rules(rules, 'scope')

    def sw_audit_time_change_events(self):
        """时间修改审计"""
        self.one_repair_data["describe"] = "添加时间修改审计规则：adjtimex/settimeofday/clock_settime、/etc/localtime"
        self.one_repair_data["recover"] = "删除 /etc/audit/rules.d/audit.rules 中的time-change规则"

        rules = [
            '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change',
            '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change',
            '-a always,exit -F arch=b64 -S clock_settime -k time-change',
            '-a always,exit -F arch=b32 -S clock_settime -k time-change',
            '-w /etc/localtime -p wa -k time-change'
        ]
        return self._add_audit_rules(rules, 'time-change')

    def sw_audit_sudo_log_events(self):
        """sudo日志审计"""
        self.one_repair_data["describe"] = "添加sudo日志审计规则：/var/log/sudo.log"
        self.one_repair_data["recover"] = "删除 /etc/audit/rules.d/audit.rules 中的actions规则"

        rules = [
            '-w /var/log/sudo.log -p wa -k actions'
        ]
        return self._add_audit_rules(rules, 'actions')

    # ========================================================================
    # 新增修复方法：基础配置修复（3个）
    # ========================================================================

    def sw_yum_gpgcheck_enabled(self):
        """启用YUM包签名校验（仅RedHat系列）"""
        result = {"status": False, "msg": "启用YUM包签名校验失败,请手动设置"}

        self.one_repair_data["describe"] = "启用YUM包签名校验：<br/>【/etc/yum.conf】gpgcheck=1<br/>【/etc/yum.repos.d/*.repo】gpgcheck=1"
        self.one_repair_data["recover"] = "恢复原配置文件或手动修改gpgcheck值"

        try:
            yum_conf = "/etc/yum.conf"
            repo_dir = "/etc/yum.repos.d/"

            # 修改 /etc/yum.conf
            yum_data = public.readFile(yum_conf)
            if yum_data:
                # 在 [main] 段落设置 gpgcheck=1
                if re.search(r'^\s*\[main\]', yum_data, re.M):
                    # 如果没有gpgcheck行，添加
                    if not re.search(r'^\s*gpgcheck\s*=', yum_data, re.M):
                        yum_data = re.sub(r'^(\s*\[main\].*?$)', r'\1\ngpgcheck=1', yum_data, flags=re.M)
                    else:
                        # 修改现有的gpgcheck值
                        yum_data = re.sub(r'^(\s*gpgcheck\s*=)\s*\d+', r'\1 1', yum_data, flags=re.M)
                    public.writeFile(yum_conf, yum_data)

            # 批量修改 /etc/yum.repos.d/*.repo
            public.ExecShell("sed -ri 's/^[[:space:]]*gpgcheck[[:space:]]*=.*/gpgcheck=1/' {}*.repo".format(repo_dir))

            result["status"] = True
            result["msg"] = "已启用YUM包签名校验"

        except Exception as e:
            # public.print_log("启用YUM包签名校验异常：{}".format(e))
            pass

        return result

    def sw_ipv6_forwarding_disabled(self):
        """禁用IPv6转发（仅限主机）"""
        # 首先检查IPv6是否启用
        if not os.path.exists('/proc/net/if_inet6'):
            return {"status": True, "msg": "IPv6未启用，无需配置"}

        result = {"status": False, "msg": "禁用IPv6转发失败,请手动设置"}
        config_file = "/etc/sysctl.conf"

        self.one_repair_data["describe"] = "禁用IPv6转发<br/>net.ipv6.conf.all.forwarding=0"
        self.one_repair_data["recover"] = "打开文件【{}】修改net.ipv6.conf.all.forwarding的值，执行sysctl -p".format(config_file)

        try:
            param = 'net.ipv6.conf.all.forwarding'
            # 删除旧配置
            public.ExecShell("sed -i '/^{}/d' {}".format(param, config_file))
            # 添加新配置
            public.ExecShell("echo '{} = 0' >> {}".format(param, config_file))
            # 立即生效
            public.ExecShell("sysctl -w {}=0".format(param))
            public.ExecShell("sysctl -w net.ipv6.route.flush=1")

            result["status"] = True
            result["msg"] = "已禁用IPv6转发"

        except Exception as e:
            # public.print_log("禁用IPv6转发异常：{}".format(e))
            pass

        return result

    def sw_local_login_banner(self):
        """配置本地登录警告标语"""
        result = {"status": False, "msg": "配置本地登录警告标语失败,请手动设置"}
        issue_file = "/etc/issue"

        self.one_repair_data["describe"] = "清理本地登录标语中的系统信息变量"
        self.one_repair_data["recover"] = "恢复原 /etc/issue 文件内容"

        try:
            issue_data = public.readFile(issue_file)
            if issue_data:
                # 删除系统信息变量
                issue_data = re.sub(r'\\[mrs SvRvDdTl]', '', issue_data)
                # 添加统一警告内容
                if not issue_data.strip():
                    issue_data = "Authorized uses only. All activity may be monitored and reported."
                public.writeFile(issue_file, issue_data)

            result["status"] = True
            result["msg"] = "已配置本地登录警告标语"

        except Exception as e:
            # public.print_log("配置本地登录警告标语异常：{}".format(e))
            pass

        return result

    # ========================================================================
    # 新增修复方法：时间同步服务（2个）
    # ========================================================================

    def sw_chrony_configured(self):
        """配置chrony以chrony用户运行（仅RedHat系列）"""
        result = {"status": False, "msg": "配置chrony失败,请手动设置"}

        self.one_repair_data["describe"] = "配置chronyd以chrony用户运行"
        self.one_repair_data["recover"] = "恢复原 /etc/sysconfig/chronyd 配置"

        try:
            # 检查chrony是否安装
            if not os.path.exists('/usr/sbin/chronyd'):
                # 尝试安装
                if os.path.exists('/usr/bin/yum') or os.path.exists('/usr/bin/dnf'):
                    install_result = public.ExecShell('yum install -y chrony')
                    if 'Complete!' not in install_result[0] and 'Already installed' not in install_result[0]:
                        return {"status": False, "msg": "chrony安装失败"}
                else:
                    return {"status": False, "msg": "仅支持RedHat系列系统的自动安装"}

            # 修改 /etc/sysconfig/chronyd
            chrony_conf = "/etc/sysconfig/chronyd"
            if os.path.exists(chrony_conf):
                conf_data = public.readFile(chrony_conf) or ''
                if '-u chrony' not in conf_data:
                    # 修改或添加 OPTIONS
                    if re.search(r'^OPTIONS=', conf_data, re.M):
                        conf_data = re.sub(r'^OPTIONS=.*$', 'OPTIONS="-u chrony"', conf_data, flags=re.M)
                    else:
                        conf_data = conf_data + '\nOPTIONS="-u chrony"'
                    public.writeFile(chrony_conf, conf_data)

            # 重启chronyd
            public.ExecShell('systemctl restart chronyd')
            public.ExecShell('systemctl enable chronyd')

            result["status"] = True
            result["msg"] = "已配置chrony"

        except Exception as e:
            # public.print_log("配置chrony异常：{}".format(e))
            pass

        return result

    def sw_ntp_configured(self):
        """配置NTP服务"""
        result = {"status": False, "msg": "配置NTP失败,请手动设置"}
        ntp_conf = "/etc/ntp.conf"
        ntp_sysconfig = "/etc/sysconfig/ntpd"

        self.one_repair_data["describe"] = "配置ntpd以ntp用户运行并添加restrict配置"
        self.one_repair_data["recover"] = "恢复原配置文件"

        try:
            # 检查ntp是否安装（不自动安装）
            if not os.path.exists('/usr/sbin/ntpd'):
                return {"status": False, "msg": "ntp未安装，请先安装ntp"}

            # 修改 /etc/ntp.conf
            ntp_data = public.readFile(ntp_conf)
            if ntp_data:
                # 添加restrict配置
                if 'restrict -4 default kod nomodify notrap nopeer noquery' not in ntp_data:
                    ntp_data = ntp_data + '\nrestrict -4 default kod nomodify notrap nopeer noquery'
                if 'restrict -6 default kod nomodify notrap nopeer noquery' not in ntp_data:
                    ntp_data = ntp_data + '\nrestrict -6 default kod nomodify notrap nopeer noquery'
                public.writeFile(ntp_conf, ntp_data)

            # 修改 /etc/sysconfig/ntpd
            if os.path.exists(ntp_sysconfig):
                sysconfig_data = public.readFile(ntp_sysconfig) or ''
                if '-u ntp:ntp' not in sysconfig_data:
                    if re.search(r'^OPTIONS=', sysconfig_data, re.M):
                        sysconfig_data = re.sub(r'^OPTIONS=.*$', 'OPTIONS="-u ntp:ntp"', sysconfig_data, flags=re.M)
                    else:
                        sysconfig_data = sysconfig_data + '\nOPTIONS="-u ntp:ntp"'
                    public.writeFile(ntp_sysconfig, sysconfig_data)

            # 重启ntpd
            public.ExecShell('systemctl restart ntpd')
            public.ExecShell('systemctl enable ntpd')

            result["status"] = True
            result["msg"] = "已配置NTP"

        except Exception as e:
            # public.print_log("配置NTP异常：{}".format(e))
            pass

        return result
