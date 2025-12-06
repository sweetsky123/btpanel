# coding: utf-8
import sys, os

os.chdir('/www/server/panel/')
sys.path.insert(0, "class/")
import PluginLoader
import public
import time


def clear_hosts():
    """
    @name 清理hosts文件中的bt.cn记录
    @return:
    """
    remove = 0
    try:
        import requests
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

        url = 'https://www.bt.cn/api/ip/info_json'
        res = requests.post(url, verify=False)

        if res.status_code == 404:
            remove = 1
        elif res.status_code == 200 or res.status_code == 400:
            res = res.json()
            if res != "[]":
                remove = 1
    except:
        result = public.ExecShell("curl -sS --connect-timeout 3 -m 60 -k https://www.bt.cn/api/ip/info_json")[0]
        if result != "[]":
            remove = 1

    hosts_file = '/etc/hosts'
    if remove == 1 and os.path.exists(hosts_file):
        public.ExecShell('sed -i "/www.bt.cn/d" /etc/hosts')

def clear_hosts_bt_sb():
    """
    @name 清理hosts文件中的bt.sb记录
    @return: 无返回值

    功能描述：这个函数检查是否需要从 /etc/hosts 文件中移除与 bt.sb 相关的记录。
    它首先尝试通过发送HTTP请求到 'https://api.bt.sb/api/ip/info_json' 来判断。
    如果请求返回404状态码，或者返回的内容不为空，那么就决定移除相关记录。
    如果HTTP请求失败，它将尝试使用curl命令行工具来获取相同的信息。
    最后，如果判断需要移除记录，则执行相应的shell命令来更新 /etc/hosts 文件。
    """
    remove = 0  # 初始化移除标志为0（不移除）

    try:
        # 尝试通过HTTP请求获取信息
        import requests
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

        url = 'https://api.bt.sb/api/ip/info_json'
        res = requests.post(url, verify=False)

        # 根据响应状态码决定是否需要移除记录
        if res.status_code == 404:
            remove = 1
        elif res.status_code == 200 or res.status_code == 400:
            res = res.json()
            if res != "[]":
                remove = 1
    except:
        # 如果HTTP请求失败，使用curl命令行尝试获取信息
        result = public.ExecShell("curl -sS --connect-timeout 3 -m 60 -k https://api.bt.sb/api/ip/info_json")[0]
        if result != "[]":
            remove = 1

    # 检查是否需要移除记录，并执行移除操作
    hosts_file = '/etc/hosts'
    if remove == 1 and os.path.exists(hosts_file):
        public.ExecShell('sed -i "/\.bt\.sb/d" /etc/hosts')

def flush_cache():
    '''
        @name 更新缓存
        @author hwliang
        @return void
    '''
    try:
        # start_time = time.time()
        res = PluginLoader.get_plugin_list(1)
        spath = '{}/data/pay_type.json'.format(public.get_panel_path())
        public.downloadFile('https://api.bt.sb/install/lib/pay_type.json',spath)
        import plugin_deployment
        plugin_deployment.plugin_deployment().GetCloudList(None)

        # timeout = time.time() - start_time
        if 'ip' in res and res['ip']:
            pass
        else:
            if isinstance(res, dict) and not 'msg' in res: res['msg'] = '连接服务器失败!'
    except:
        pass


def flush_php_order_cache():
    """
    更新软件商店php顺序缓存
    @return:
    """
    spath = '{}/data/php_order.json'.format(public.get_panel_path())
    public.downloadFile('https://api.bt.sb/install/lib/php_order.json', spath)


def flush_msg_json():
    """
    @name 更新消息json
    """
    try:
        spath = '{}/data/msg.json'.format(public.get_panel_path())
        public.downloadFile(public.get_url() + '/linux/panel/msg/msg.json', spath)
    except:
        pass


if __name__ == '__main__':
    tip_date_tie = '/tmp/.fluah_time'
    if os.path.exists(tip_date_tie):
        last_time = int(public.readFile(tip_date_tie))
        timeout = time.time() - last_time
        if timeout < 600:
            print("执行间隔过短，退出 - {}!".format(timeout))
            sys.exit()
    clear_hosts()
    clear_hosts_bt_sb()
    flush_cache()
    flush_php_order_cache()
    flush_msg_json()

    public.writeFile(tip_date_tie, str(int(time.time())))
