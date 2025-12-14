import json
import multiprocessing
import os
import time
import traceback
import re
import psutil
import sys

os.chdir('/www/server/panel')
if not 'class/' in sys.path:
    sys.path.insert(0, 'class/')
import public
from monitorModel.base import monitorBase
from pluginAuth import Plugin


class main(monitorBase):
    pids = None
    panel_pid = None
    task_pid = None
    processPs = {
        'bioset': '用于处理块设备上的I/O请求的进程',
        'BT-MonitorAgent': '面板程序的进程',
        'rngd': '一个熵守护的进程',
        'master': '用于管理和协调子进程的活动的进程',
        'irqbalance': '一个IRQ平衡守护的进程',
        'rhsmcertd': '主要用于管理Red Hat订阅证书，并维护系统的订阅状态的进程',
        'auditd': '是Linux审计系统中用户空间的一个组的进程',
        'chronyd': '调整内核中运行的系统时钟和时钟服务器同步的进程',
        'qmgr': 'PBS管理器的进程',
        'oneavd': '面板微步木马检测的进程',
        'postgres': 'PostgreSQL数据库的进程',
        'grep': '一个命令行工具的进程',
        'lsof': '一个命令行工具的进程',
        'containerd-shim-runc-v2': 'Docker容器的一个组件的进程',
        'pickup': '用于监听Unix域套接字的进程',
        'cleanup': '邮件传输代理（MTA）中的一个组件的进程',
        'trivial-rewrite': '邮件传输代理（MTA）中的一个组件的进程',
        'containerd': 'docker依赖服务的进程',
        'redis-server': 'redis服务的进程',
        'rcu_sched': 'linux系统rcu机制服务的进程',
        'jsvc': '面板tomcat服务的进程',
        'oneav': '面板微步木马检测的进程',
        'mysqld': 'MySQL服务的进程',
        'php-fpm': 'PHP的子进程',
        'php-cgi': 'PHP-CGI的进程',
        'nginx': 'Nginx服务的进程',
        'httpd': 'Apache服务的进程',
        'sshd': 'SSH服务的进程',
        'pure-ftpd': 'FTP服务的进程',
        'sftp-server': 'SFTP服务的进程',
        'mysqld_safe': 'MySQL服务的进程',
        'firewalld': '防火墙服务的进程',
        'BT-Panel': '宝塔面板-主的进程',
        'BT-Task': '宝塔面板-后台任务的进程',
        'NetworkManager': '网络管理服务的进程',
        'svlogd': '日志守护的进程',
        'memcached': 'Memcached缓存器的进程',
        'gunicorn': "宝塔面板的进程",
        "BTPanel": '宝塔面板的进程',
        'baota_coll': "堡塔云控-主控端的进程",
        'baota_client': "堡塔云控-被控端的进程",
        'node': 'Node.js程序的进程',
        'supervisord': 'Supervisor的进程',
        'rsyslogd': 'rsyslog日志服务的进程',
        'crond': '计划任务服务的进程',
        'cron': '计划任务服务的进程',
        'rsync': 'rsync文件同步的进程',
        'ntpd': '网络时间同步服务的进程',
        'rpc.mountd': 'NFS网络文件系统挂载服务的进程',
        'sendmail': 'sendmail邮件服务的进程',
        'postfix': 'postfix邮件服务的进程',
        'npm': 'Node.js NPM管理器的进程',
        'PM2': 'Node.js PM2进程管理器的进程',
        'htop': 'htop进程监控软件的进程',
        'btpython': '宝塔面板-独立Python环境的进程',
        'btappmanagerd': '宝塔应用管理器插件的进程',
        'dockerd': 'Docker容器管理器的进程',
        'docker-proxy': 'Docker容器管理器的进程',
        'docker-registry': 'Docker容器管理器的进程',
        'docker-distribution': 'Docker容器管理器的进程',
        'docker-network': 'Docker容器管理器的进程',
        'docker-volume': 'Docker容器管理器的进程',
        'docker-swarm': 'Docker容器管理器的进程',
        'docker-systemd': 'Docker容器管理器的进程',
        'docker-containerd': 'Docker容器管理器的进程',
        'docker-containerd-shim': 'Docker容器管理器的进程',
        'docker-runc': 'Docker容器管理器的进程',
        'docker-init': 'Docker容器管理器的进程',
        'docker-init-systemd': 'Docker容器管理器的进程',
        'docker-init-upstart': 'Docker容器管理器的进程',
        'docker-init-sysvinit': 'Docker容器管理器的进程',
        'docker-init-openrc': 'Docker容器管理器的进程',
        'docker-init-runit': 'Docker容器管理器的进程',
        'docker-init-systemd-resolved': 'Docker容器管理器的进程',
        'rpcbind': 'NFS网络文件系统服务的进程',
        'dbus-daemon': 'D-Bus消息总线守护的进程',
        'systemd-logind': '登录管理器的进程',
        'systemd-journald': 'Systemd日志管理服务的进程',
        'systemd-udevd': '系统设备管理服务的进程',
        'systemd-timedated': '系统时间日期服务的进程',
        'systemd-timesyncd': '系统时间同步服务的进程',
        'systemd-resolved': '系统DNS解析服务的进程',
        'systemd-hostnamed': '系统主机名服务的进程',
        'systemd-networkd': '系统网络管理服务的进程',
        'systemd-resolvconf': '系统DNS解析服务的进程',
        'systemd-local-resolv': '系统DNS解析服务的进程',
        'systemd-sysctl': '系统系统参数服务的进程',
        'systemd-modules-load': '系统模块加载服务的进程',
        'systemd-modules-restore': '系统模块恢复服务的进程',
        'agetty': 'TTY登陆验证程序的进程',
        'sendmail-mta': 'MTA邮件传送代理的进程',
        '(sd-pam)': '可插入认证模块的进程',
        'polkitd': '授权管理服务的进程',
        'mongod': 'MongoDB数据库服务的进程',
        'mongodb': 'MongoDB数据库服务的进程',
        'mongodb-mms-monitor': 'MongoDB数据库服务的进程',
        'mongodb-mms-backup': 'MongoDB数据库服务的进程',
        'mongodb-mms-restore': 'MongoDB数据库服务的进程',
        'mongodb-mms-agent': 'MongoDB数据库服务的进程',
        'mongodb-mms-analytics': 'MongoDB数据库服务的进程',
        'mongodb-mms-tools': 'MongoDB数据库服务的进程',
        'mongodb-mms-backup-agent': 'MongoDB数据库服务的进程',
        'mongodb-mms-backup-tools': 'MongoDB数据库服务的进程',
        'mongodb-mms-restore-agent': 'MongoDB数据库服务的进程',
        'mongodb-mms-restore-tools': 'MongoDB数据库服务的进程',
        'mongodb-mms-analytics-agent': 'MongoDB数据库服务的进程',
        'mongodb-mms-analytics-tools': 'MongoDB数据库服务的进程',
        'dhclient': 'DHCP协议客户端的进程',
        'dhcpcd': 'DHCP协议客户端的进程',
        'dhcpd': 'DHCP服务器的进程',
        'isc-dhcp-server': 'DHCP服务器的进程',
        'isc-dhcp-server6': 'DHCP服务器的进程',
        'dhcp6c': 'DHCP服务器的进程',
        'dhcpcd': 'DHCP服务器的进程',
        'dhcpd': 'DHCP服务器的进程',
        'avahi-daemon': 'Zeroconf守护的进程',
        'login': '登录的进程',
        'systemd': '系统管理服务的进程',
        'systemd-sysv': '系统管理服务的进程',
        'systemd-journal-gateway': '系统管理服务的进程',
        'systemd-journal-remote': '系统管理服务的进程',
        'systemd-journal-upload': '系统管理服务的进程',
        'systemd-networkd': '系统网络管理服务的进程',
        'rpc.idmapd': 'NFS网络文件系统相关服务的进程',
        'cupsd': '打印服务的进程',
        'cups-browsed': '打印服务的进程',
        'sh': 'shell的进程',
        'php': 'PHP CLI模式的进程',
        'blkmapd': 'NFS映射服务的进程',
        'lsyncd': '文件同步服务的进程',
        'sleep': '延迟的进程',
    }

    def __init__(self):
        self.panel_pid = None

    def specific_resource_load_type(self, get):
        try:
            self.get_top_cpu_processes()
            infos = {}
            infos['info'] = {}
            infos['info']['physical_cpu'] = psutil.cpu_count(logical=False)
            infos['info']['logical_cpu'] = psutil.cpu_count(logical=True)
            c_tmp = public.readFile('/proc/cpuinfo')
            d_tmp = re.findall("physical id.+", c_tmp)
            cpuW = len(set(d_tmp))
            load_avg = os.getloadavg()
            infos['info']['cpu_name'] = public.getCpuType() + " * {}".format(cpuW)
            infos['info']['num_phys_cores'] = cpuW
            infos['info']['load_avg'] = {"1": load_avg[0], "5": load_avg[1], "15": load_avg[2]}
            infos['info']['active_processes'] = len(
                [p for p in psutil.process_iter() if p.status() == psutil.STATUS_RUNNING])
            infos['info']['total_processes'] = len(psutil.pids())
            num = psutil.cpu_count(logical=True)
            cpu_list = []
            mem_total = psutil.virtual_memory().total
            pid_list = self.get_top_cpu_processes()
            sorted(pid_list, key=lambda x: x['cpu_percent'], reverse=True)
            cpu_top_list = pid_list[:5]
            mem_top_list = sorted(pid_list, key=lambda x: x['memory'], reverse=True)[:5]
            for data in cpu_top_list:
                process = psutil.Process(int(data['pid']))
                pid = int(data['pid'])
                name = process.name()
                cpu_usage = str(round(data['cpu_percent'] / num, 2)) + '%'
                timestamp = time.time() - process.create_time()
                time_info = {}
                time_info["天"] = int(timestamp // (24 * 3600))
                time_info["小时"] = int((timestamp - time_info['天'] * 24 * 3600) // 3600)
                time_info["分钟"] = int((timestamp - time_info['天'] * 24 * 3600 - time_info['小时'] * 3600) // 60)
                ll = [str(v) + k for k, v in time_info.items() if v != 0]
                proc_survive = ''.join(ll)
                threads = process.num_threads()
                important = 0
                explain = self.processPs.get(process.name(), '未知程序的进程')
                if 'BT-Panel' == process.name() or 'BT-Task' == process.name():
                    important = 1
                exe_path = process.exe()
                cwd_path = process.cwd()
                memory_usage = '%.2f' % (int(process.memory_info().rss) / int(mem_total) * 100) + "%"
                cpu_list.append(
                    {'cpu_percent': cpu_usage, 'memory_usage': memory_usage, 'proc_name': name, 'proc_survive': proc_survive, 'num_threads': threads, 'important': important, 'explain': explain,
                     'exe_path': exe_path, 'cwd_path': cwd_path, 'pid': pid})
            mem_list = []
            for data in mem_top_list:
                process = psutil.Process(int(data['pid']))
                pid = int(data['pid'])
                name = process.name()
                cpu_usage = data['cpu_percent']
                timestamp = time.time() - process.create_time()
                time_info = {}
                time_info["天"] = int(timestamp // (24 * 3600))
                time_info["小时"] = int((timestamp - time_info['天'] * 24 * 3600) // 3600)
                time_info["分钟"] = int((timestamp - time_info['天'] * 24 * 3600 - time_info['小时'] * 3600) // 60)
                ll = [str(v) + k for k, v in time_info.items() if v != 0]
                proc_survive = ''.join(ll)
                threads = process.num_threads()
                important = 0
                explain = self.processPs.get(process.name(), '未知程序的进程')
                if 'BT-Panel' == process.name() or 'BT-Task' == process.name():
                    important = 1
                exe_path = process.exe()
                cwd_path = process.cwd()
                memory_usage = '%.2f' % (int(process.memory_info().rss) / int(mem_total) * 100) + "%"
                mem_list.append(
                    {'cpu_percent': cpu_usage, 'memory_usage': memory_usage, 'proc_name': name, 'proc_survive': proc_survive, 'num_threads': threads, 'important': important, 'explain': explain,
                     'exe_path': exe_path, 'cwd_path': cwd_path, 'pid': pid})
            infos['CPU_high_occupancy_software_list'] = cpu_list
            infos['memory_high_occupancy_software_list'] = mem_list
            return infos
        except:
            return traceback.format_exc()

    def kill_process_all(self, get):
        pid = int(get.pid)
        if pid < 30: return public.returnMsg(False, '不能结束系统关键进程!')
        if pid not in psutil.pids(): return public.returnMsg(False, '指定进程不存在!')
        p = psutil.Process(pid)
        if self.is_panel_process(pid): return public.returnMsg(False, '不能结束面板服务进程')
        p.kill()
        return self.kill_process_tree_all(pid)

    # 结束进程树
    def kill_process_tree_all(self, pid):
        if pid < 30: return public.returnMsg(True, '已结束此进程树!')
        if self.is_panel_process(pid): return public.returnMsg(False, '不能结束面板服务进程')
        try:
            if pid not in psutil.pids(): public.returnMsg(True, '已结束此进程树!')
            p = psutil.Process(pid)
            ppid = p.ppid()
            name = p.name()
            p.kill()
            public.ExecShell('pkill -9 ' + name)
            if name.find('php-') != -1:
                public.ExecShell("rm -f /tmp/php-cgi-*.sock")
            elif name.find('mysql') != -1:
                public.ExecShell("rm -f /tmp/mysql.sock")
            elif name.find('mongod') != -1:
                public.ExecShell("rm -f /tmp/mongod*.sock")
            self.kill_process_lower(pid)
            if ppid: return self.kill_process_all(ppid)
        except:
            pass
        return public.returnMsg(True, '已结束此进程树!')

    def kill_process_lower(self, pid):
        pids = psutil.pids()
        for lpid in pids:
            if lpid < 30: continue
            if self.is_panel_process(lpid): continue
            p = psutil.Process(lpid)
            ppid = p.ppid()
            if ppid == pid:
                p.kill()
                return self.kill_process_lower(lpid)
        return True

    # 判断是否是面板进程
    def is_panel_process(self, pid):
        if not self.panel_pid:
            self.panel_pid = os.getpid()
        if pid == self.panel_pid: return True
        if not self.task_pid:
            try:
                self.task_pid = int(
                    public.ExecShell("ps aux | grep 'python task.py'|grep -v grep|head -n1|awk '{print $2}'")[0])
            except:
                self.task_pid = -1
        if pid == self.task_pid: return True
        return False

    def get_top_cpu_processes(self):
        processes = []

        # 遍历所有进程并获取CPU占用率
        for p in psutil.process_iter(['pid', 'name']):
            try:
                cpu_percent = p.cpu_percent(interval=None)
                pid = p.pid
                name = p.info['name']
                if 'BT-Panel' in name:
                    continue
                memory = p.memory_info().rss
                processes.append({'pid': pid, 'cpu_percent': cpu_percent, 'memory': memory})
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # 按照CPU占用率进行排序
        processes.sort(key=lambda x: x['cpu_percent'], reverse=True)

        return processes  # 返回前五个进程
