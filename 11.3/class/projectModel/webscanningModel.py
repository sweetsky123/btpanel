#!/usr/bin/python
# coding: utf-8
# Date 2022/4/1
# -------------------------------------------------------------------
# 宝塔Linux面板
# -------------------------------------------------------------------
# Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
# -------------------------------------------------------------------
# Author: lkq <lkq@bt.cn>
# 网站安全扫描
# -------------------------------------------------------------------
import re
from curses import panel
from projectModel.base import projectBase
import sys, json, os, public, hashlib, requests, time
from BTPanel import cache
import PluginLoader


class main(projectBase):
    # __scanning=scanningModel.main()
    __count = 0
    __shell = "/www/server/panel/data/webshell_check_shell.txt"
    session = requests.Session()
    send_time = ""  # 记录上一次发送ws时间
    web_name = ""  # 当前检测的网站名
    public.set_module_logs('webscanning', 'ScanSingleSite', 1)
    scan_type = "vulscan"
    web_scan_num = 0
    # 添加计数器
    risk_count = {
        "warning": 0, # 告警（0）
        "low": 0,  # 低危 (1)
        "middle": 0,  # 中危 (2)
        "high": 0  # 高危 (3)
    }

    web_count_list = []

    def GetWebInfo(self, get):
        '''
        @name 获取网站信息
        @author lkq<2022-4-12>
        @param name  网站名称
        @return
        '''
        webinfo = public.M('sites').where('project_type=? and name=?', ('PHP', get.name)).count()
        if not webinfo: return False
        webinfo = public.M('sites').where('project_type=? and name=?', ('PHP', get.name)).select()
        return webinfo[0]

    def ScanWeb(self, get):
        '''
        @name 获取当前站点漏洞扫描信息
        @author lkq<2022-4-12>
        @param name  网站名称
        @return
        '''
        if '_ws' in get: get._ws.send(public.getJson(
            {"end": False, "ws_callback": get.ws_callback, "info": "正在扫描 %s 网站漏洞" % get.name,
             "type": "vulscan"}))

        # args = public.dict_obj()
        # args.module_get_object = 1
        # from projectModel import scanningModel

        scanInfo = PluginLoader.module_run("scanning", "startScanWeb", get)

        # scanInfo=self.__scanning.startScanWeb(get)
        if scanInfo['msg'][0]['is_vufix']:
            for scan in scanInfo['msg'][0]['cms']:
                if '_ws' in get: get._ws.send(public.getJson(
                    {"dangerous": int(scan['dangerous']), "end": False, "ws_callback": get.ws_callback,
                     "info": "网站 %s 存在漏洞" % get.name, "type": "vulscan",
                     "is_error": True, "repair": scan["repair"]}))
                try:
                    scan['dangerous'] = int(scan['dangerous'])
                    del (scan['determine'])
                    del (scan['ps'])
                    del (scan['repair_file'])
                    del (scan['version'])
                    del (scan['cms_list'])
                    del (scan['cms_name'])
                except:
                    continue
            return scanInfo['msg'][0]['cms']
        return {}

    def WebSSlSecurity(self, webinfo, get):
        '''
        @name SSL证书安全性，是否开启SSL
        @author lkq<2022-4-12>
        @param name  网站名称
        @return Tls1.0 检测 TLS1.1
        '''
        if public.get_webserver() == 'nginx':
            conf_file = '/www/server/panel/vhost/nginx/{}.conf'.format(webinfo['name'])
            if os.path.exists(conf_file):
                conf_info = public.ReadFile(conf_file)
                keyText = 'SSLCertificateFile'
                if public.get_webserver() == 'nginx':
                    keyText = 'ssl_certificate'
                if conf_info.find(keyText) == -1:
                    if '_ws' in get: get._ws.send(public.getJson(
                        {"end": False, "ws_callback": get.ws_callback,
                         "info": "【%s】 网站未启用SSL" % webinfo['name'],
                         "type": "webscan", "is_error": True, "dangerous": 2}))
                    webinfo['result']['webscan'].append({"name": "【%s】 网站未启用SSL" % webinfo['name'],
                                                         "repair": "修复方案：在网站设置-SSL开启强制https", "dangerous": 1})
                if 'TLSv1 ' in conf_info:
                    if '_ws' in get: get._ws.send(public.getJson(
                        {"end": False, "ws_callback": get.ws_callback,
                         "info": "【%s】 网站启用了不安全的TLS1协议" % webinfo['name'],
                         "type": "webscan", "is_error": True, "dangerous": 2}))
                    webinfo['result']['webscan'].append({"name": "【%s】 网站启用了不安全的TLS1协议" % webinfo['name'],
                                                         "repair": "修复方案：打开配置文件去掉TLS1", "dangerous": 2})

    def WebInfoDisclosure(self, get):
        '''
        @name php/nginx/apache版本泄露，检测防火墙是否开启
        @author lkq<2022-4-12>
        @param name  网站名称
        @return
        '''
        if '_ws' in get: get._ws.send(
            public.getJson({"end": False, "callback": get.ws_callback, "info": "正在扫描 %s 网站配置安全性" % get.name,
                            "type": "webscan"}))
        result = []
        if public.get_webserver() == 'nginx':
            nginx_path = '/www/server/nginx/conf/nginx.conf'
            if os.path.exists(nginx_path):
                nginx_info = public.ReadFile(nginx_path)
                if not 'server_tokens off' in nginx_info:
                    result.append({"name": "Nginx存在版本信息泄露",
                                   "repair": "打开nginx.conf配置文件，在http { }里加上： server_tokens off;",
                                   "dangerous": 1, "type": "webscan"})
        phpversion = public.get_site_php_version(get.name)
        phpini = '/www/server/php/%s/etc/php.ini' % phpversion
        if os.path.exists(phpini):
            php_info = public.ReadFile(phpini)
            if not 'expose_php = Off' in php_info:
                result.append({"name": "PHP %s 存在版本信息泄露" % phpversion,
                               "repair": "修复方案：打开php.ini配置文件，设置expose_php = Off", "dangerous": 1, "type": "webscan"})

        # 是否开启防火墙
        if not os.path.exists("/www/server/btwaf/"):
            if '_ws' in get: get._ws.send(public.getJson(
                {"end": False, "ws_callback": get.ws_callback,
                 "info": "未安装防火墙",
                 "type": "webscan", "is_error": True, "dangerous": 1}))
            result.append({"name": "未安装防火墙",
                           "repair": "修复方案：安装nginx防火墙", "dangerous": 1, "type": "webscan"})
        # else:
        #     waf_list = self.get_waf_status_all()
        #     if get.name in waf_list:
        #         if not waf_list[get.name]['status']:
        #             if '_ws' in get: get._ws.send(public.getJson(
        #                 {"end": False, "ws_callback": get.ws_callback,
        #                  "info": "【{}】网站未开启防火墙".format(get.name),
        #                  "type": "webscan", "is_error": True, "dangerous": 1}))
        #             result.append({"name": "【{}】网站未开启防火墙".format(get.name),
        #                            "repair": "修复方案：在WAF-站点设置开启网站防火墙状态", "dangerous": 1, "type": "webscan"})

        # 检查是否开启防跨站
        web_infos = public.M('sites').where("name=?", (get.name, )).select()
        for web in web_infos:
            run_path = self.GetSiteRunPath(web["name"], web["path"])
            if not run_path:
                continue
            path = web["path"] + run_path
            user_ini_file = path + '/.user.ini'
            # 文件不存在也代表没开
            if not os.path.exists(user_ini_file):
                # if '_ws' in get: get._ws.send(public.getJson(
                #     {"end": False, "ws_callback": get.ws_callback,
                #      "info": "【{}】网站未开启防跨站".format(get.name), "repair": "网站目录-开启防跨站攻击(open_basedir)",
                #      "type": "webscan", "is_error": True, "dangerous": 0}))
                # result.append({"name": "【{}】网站未开启防跨站".format(get.name),
                #                "repair": "修复方案：网站目录-启用防跨站攻击(open_basedir)，防止黑客通过跨越目录读取敏感数据",
                #                "dangerous": 0, "type": "webscan"})
                continue
            user_ini_conf = public.readFile(user_ini_file)
            if "open_basedir" not in user_ini_conf:
                if '_ws' in get: get._ws.send(public.getJson(
                    {"end": False, "ws_callback": get.ws_callback,
                     "info": "【{}】网站未开启防跨站".format(get.name), "repair": "网站目录-开启防跨站攻击(open_basedir)",
                     "type": "webscan", "is_error": True, "dangerous": 0}))
                result.append({"name": "【{}】网站未开启防火墙".format(get.name),
                               "repair": "修复方案：网站目录-启用防跨站攻击(open_basedir)，防止黑客通过跨越目录读取敏感数据",
                               "dangerous": 0, "type": "webscan"})
        # 结束
        if '_ws' in get: get._ws.send(
            public.getJson({"end": False, "callback": get.ws_callback, "info": "扫描 %s 网站配置安全性完成" % get.name,
                            "type": "webscan"}))

        return result

    def GetSiteRunPath(self, siteName, sitePath):
        """
        @name 获取网站运行目录
        @author lwh
        @param string siteName 网站名
        @param string sitePath 网站路径
        """
        if not siteName or os.path.isfile(sitePath):
            return "/"
        path = sitePath
        if public.get_webserver() == 'nginx':
            filename = '/www/server/panel/vhost/nginx/' + siteName + '.conf'
            if os.path.exists(filename):
                conf = public.readFile(filename)
                rep = '\s*root\s+(.+);'
                tmp1 = re.search(rep, conf)
                if tmp1: path = tmp1.groups()[0]
        elif public.get_webserver() == 'apache':
            filename = '/www/server/panel/vhost/apache/' + siteName + '.conf'
            if os.path.exists(filename):
                conf = public.readFile(filename)
                rep = '\s*DocumentRoot\s*"(.+)"\s*\n'
                tmp1 = re.search(rep, conf)
                if tmp1: path = tmp1.groups()[0]
        else:
            filename = '/www/server/vhost/openlitespeed/' + siteName + '.conf'
            if os.path.exists(filename):
                conf = public.readFile(filename)
                rep = "vhRoot\s*(.*)"
                path = re.search(rep, conf)
                if not path:
                    return False
                path = path.groups()[0]
        data = {}
        if sitePath == path:
            return '/'
        else:
            return path.replace(sitePath, '')

    def _send_task(self, url):
        '''
        @name 拨测发送请求
        @author lkq<2022-4-12>
        @param url  URL
        @return
        '''
        import panelAuth
        pdata = panelAuth.panelAuth().create_serverid(None)
        pdata['url'] = url
        try:
            result = public.httpPost("http://www.bt.cn/api/local/boce", pdata, 10)
            result = json.loads(result)
            return result
        except:
            return False

    def WebBtBoce(self, get, webinfo):
        '''
        @name 拨测
        @author lkq<2022-4-12>
        @param name  网站名称
        @return
        '''
        webinfo['result']['boce'] = []
        for url in get.url:
            if url.find('http://') == -1 and url.find('https://') == -1: continue
            if '_ws' in get: get._ws.send(public.getJson(
                {"end": False, "ws_callback": get.ws_callback, "info": "正在对URL %s 进行拨测" % url, "type": "boce"}))
            result = self._send_task(get.url)
            if '_ws' in get: get._ws.send(public.getJson(
                {"end": False, "ws_callback": get.ws_callback, "info": result, "type": "boce"}))
            if result:
                webinfo['result']['boce'].append(result)

    def WebFilePermission(self, webinfo, get):
        '''
       @name 网站权限
       @author lkq<2022-4-12>
       @param name  网站名称
       @return
       '''
        import pwd
        return_data = []
        for i in os.listdir(webinfo['path']):
            is_name = os.path.join(webinfo['path'], i)
            if os.path.isdir(is_name):
                return_data.append(is_name)
                for i2 in os.listdir(is_name):
                    is_name2 = is_name + '/' + i2
                    if os.path.isdir(is_name2):
                        return_data.append(is_name2)
        if len(return_data) >= 1:
            for file in return_data:
                if not os.path.exists(file): continue
                stat = os.stat(file)
                if int(oct(stat.st_mode)[-3:]) == 777:
                    if '_ws' in get: get._ws.send(public.getJson(
                        {"end": False, "ws_callback": get.ws_callback, "info": "  【%s】 目录权限错误" % file,
                         "repair": "设置 【%s】 目录为755" % file,
                         "type": "webscan", "is_error": True, "dangerous": 1}))
                    webinfo['result']['webscan'].append(
                        {"name": "  【%s】 目录权限错误" % file, "repair": "修复方案：设置 【%s】 目录为755" % file,
                         "dangerous": 1})
                if pwd.getpwuid(stat.st_uid).pw_name != 'www':
                    if '_ws' in get: get._ws.send(public.getJson(
                        {"end": False, "ws_callback": get.ws_callback, "info": "  【%s】 目录权限错误" % file,
                         "repair": "修复方案：设置 【%s】 目录的用户权限为www" % file,
                         "type": "webscan", "is_error": True, "dangerous": 1}))
                    webinfo['result']['webscan'].append(
                        {"name": "  【%s】 目录用户权限错误" % file, "repair": "设置 【%s】 目录的用户权限为www" % file,
                         "dangerous": 1})

    def Getdir(self, path):
        '''
        @name 获取目录下的所有php文件
        @author lkq<2022-4-12>
        @param path 文件目录
        @return list
        '''
        return_data = []
        data2 = []
        [[return_data.append(os.path.join(root, file)) for file in files] for root, dirs, files in os.walk(path)]
        for i in return_data:
            if str(i.lower())[-4:] == '.php':
                data2.append(i)
        return data2

    def ReadFile(self, filename, mode='r'):
        '''
        @name 读取文件内容
        @author lkq<2022-4-12>
        @param filename 文件路径
        @return 文件内容
        '''
        import os
        if not os.path.exists(filename): return False
        try:
            fp = open(filename, mode)
            f_body = fp.read()
            fp.close()
        except Exception as ex:
            if sys.version_info[0] != 2:
                try:
                    fp = open(filename, mode, encoding="utf-8")
                    f_body = fp.read()
                    fp.close()
                except Exception as ex2:
                    return False
            else:
                return False
        return f_body

    def FileMd5(self, filename):
        '''
        @name 获取文件的md5值
        @author lkq<2022-4-12>
        @param filename 文件路径
        @return MD5
        '''
        if os.path.exists(filename):
            with open(filename, 'rb') as fp:
                data = fp.read()
            file_md5 = hashlib.md5(data).hexdigest()
            return file_md5
        else:
            return False

    def WebshellChop(self, filename, url, get):
        '''
        @name 上传到云端判断是否是webshell
        @author lkq<2022-4-12>
        @param filename 文件路径
        @param url 云端URL
        @return bool
        '''
        try:
            upload_url = url
            size = os.path.getsize(filename)
            if size > 1024000: return False
            upload_data = {'inputfile': self.ReadFile(filename), "md5": self.FileMd5(filename)}
            upload_res = requests.post(upload_url, upload_data, timeout=20).json()
            if upload_res['msg'] == 'ok':
                if (upload_res['data']['data']['level'] == 5):
                    return True
                return False
        except:
            return False

    def GetCheckUrl(self):
        '''
        @name 获取云端URL地址
        @author lkq<2022-4-12>
        @return URL
        '''
        try:
            ret = requests.get('http://www.bt.cn/checkWebShell.php').json()
            if ret['status']:
                return ret['url']
            return False
        except:
            return False

    def UploadShell(self, data, get, webinfo):
        '''
        @name 上传文件
        @author lkq<2022-4-12>
        @param data 文件路径集合
        @return 返回webshell 路径
        '''
        if len(data) == 0: return []
        url = self.GetCheckUrl()
        if not url: return []
        count = 0
        wubao = 0
        shell_data = []
        if os.path.exists(self.__shell):
            wubao = 1
            try:
                shell_data = json.loads(public.ReadFile(self.__shell))
            except:
                public.WriteFile(self.__shell, [])
                wubao = 0
        for i in data:
            count += 1
            if '_ws' in get: get._ws.send(
                public.getJson({"end": False, "callback": get.ws_callback, "info": "正在扫描文件是否是木马%s" % i,
                                "type": "webshell", "count": self.__count, "is_count": count}))
            # 判断是否是哪个误报的文件
            if wubao:
                if i in shell_data: continue
            if self.WebshellChop(i, url, get):
                if '_ws' in get: get._ws.send(
                    public.getJson({"end": False, "callback": get.ws_callback,
                                    "info": "%s 网站木马扫描发现当前文件为木马文件%s" % (
                                        get.name, len(webinfo['result']['webshell'])),
                                    "type": "webshell", "count": self.__count, "is_count": count, "is_error": True}))
                webinfo['result']['webshell'].append(i)
        if '_ws' in get: get._ws.send(
            public.getJson({"end": False, "callback": get.ws_callback,
                            "info": "%s 网站木马扫描完成共发现 %s 个木马文件" % (
                                get.name, len(webinfo['result']['webshell'])),
                            "type": "webshell", "count": self.__count,
                            "is_count": count}))

    def GetDirList(self, path_data):
        '''
        @name 获取当前目录下所有PHP文件
        @author lkq<2022-4-12>
        '''
        if os.path.exists(str(path_data)):
            return self.Getdir(path_data)
        else:
            return False

    def SanDir(self, webinfo, get):
        '''
        @name 扫描webshell入口函数
        @author lkq<2022-4-12>
        @param path 需要扫描的路径
        @return  webshell 路径集合
        '''
        self.__count = 0
        file = self.GetDirList(webinfo['path'])
        if not file:
            return []
        ##进度条
        self.__count = len(file)
        return_data = self.UploadShell(file, get, webinfo)
        return return_data

    def UpdateWubao(self, filename):
        '''
        @name 更新误报文件
        @author lkq<2022-4-12>
        @param filename 误报文件
        '''
        if not os.path.exists(self.__shell):
            public.WriteFile(self.__shell, [filename.strip()])
        else:
            try:
                shell_data = json.loads(public.ReadFile(self.__shell))
                if not filename in shell_data:
                    shell_data.append(filename)
                    public.WriteFile(self.__shell, json.dumps(shell_data))
            except:
                pass

    # 提交误报
    def SendWubao(self, get):
        '''
        @name 提交误报
        @author lkq<2022-4-12>
        @param get.filename 误报文件
        '''
        userInfo = json.loads(public.ReadFile('/www/server/panel/data/userInfo.json'))
        cloudUrl = 'http://www.bt.cn/api/bt_waf/reportTrojanError'
        self.UpdateWubao(filename=get.filename)
        pdata = {'name': get.filename, 'inputfile': self.ReadFile(get.filename), "md5": self.FileMd5(get.filename),
                 "access_key": userInfo['access_key'], "uid": userInfo['uid']}
        ret = public.httpPost(cloudUrl, pdata)
        return public.returnMsg(True, "提交误报完成")

    def WebShellKill(self, get, webinfo):
        '''
       @name 木马查杀
       @author lkq<2022-4-12>
       @param name  网站名称
       @return
       '''
        webinfo['result']['webshell'] = []
        self.SanDir(webinfo, get)

    def WebFileDisclosure(self, webinfo, get):
        '''
       @name 网站信息泄露，.svn、.git泄露
       @author lkq<2022-4-12>
       @param name  网站名称
       @return
       '''
        webinfo['result']['filescan'] = []
        for i in os.listdir(webinfo['path']):
            is_name = os.path.join(webinfo['path'], i)
            if os.path.isfile(is_name):
                if is_name.endswith(".sql"):
                    webinfo['result']['filescan'].append(
                        {"name": "  【%s】 网站根目录存在sql备份文件%s" % (webinfo['name'], is_name),
                         "repair": "修复方案：转移到其他目录或者下载到本地",
                         "dangerous": 2})
                elif is_name.endswith(".zip") or is_name.endswith(".gz") or is_name.endswith(
                        ".tar") or is_name.endswith(
                    ".7z") or is_name.endswith(".bak"):
                    if webinfo['name'] in is_name:
                        if '_ws' in get: get._ws.send(public.getJson(
                            {"end": False, "ws_callback": get.ws_callback,
                             "info": "  【%s】 网站根目录存在备份文件 %s" % (webinfo['name'], is_name),
                             "type": "filescan", "is_error": True, "dangerous": 2}))
                        webinfo['result']['filescan'].append(
                            {"name": "  【%s】 网站根目录存在备份文件 %s" % (webinfo['name'], is_name),
                             "repair": "修复方案：转移到其他目录或者下载到本地", "dangerous": 2})
            if os.path.isdir(is_name):
                # .git、.svn泄露
                if is_name.endswith(".svn") or is_name.endswith(".git") or is_name.endswith(".cvs"):
                    if '_ws' in get: get._ws.send(public.getJson(
                        {"end": False, "ws_callback": get.ws_callback,
                         "info": "  【%s】 网站根目录存在版本控制文件 %s，可能导致网站源代码泄露" % (webinfo['name'], is_name),
                         "type": "filescan", "is_error": True, "dangerous": 2}))
                    webinfo['result']['filescan'].append(
                        {"name": "  【%s】 网站根目录存在版本控制文件 %s，可能导致网站源代码泄露" % (webinfo['name'], is_name),
                         "repair": "修复方案：将该目录转移到其他地方或者设置禁止访问", "dangerous": 2})

    def IsBackupSite(self, webname):
        """
        @name 判断是否存在备份
        @author lkq<2022-4-12>
        @return
        """
        import crontab
        crontab_data = crontab.crontab()
        data = crontab_data.GetCrontab(None)
        for i in data:
            if i['sType'] == 'site':
                if i['sName'] == 'ALL':
                    return True
                if i['sName'] == webname:
                    return True
        return False

    def WebBackup(self, webinfo, get):
        '''
       @name 是否备份重要数据
       @author lkq<2022-4-12>
       @param name  网站名称
       @return
       '''
        webinfo['result']['backup'] = []
        if not self.IsBackupSite(webinfo['name']):
            if '_ws' in get: get._ws.send(public.getJson({"end": False, "ws_callback": get.ws_callback,
                                                          "info": "修复方案：【%s】 在计划任务中创建备份网站任务" %
                                                                  webinfo['name'], "type": "backup", "is_error": True,
                                                          "dangerous": 0}))
            webinfo['result']['backup'].append({"name": "  【%s】 缺少计划任务备份" % (webinfo['name']),
                                                "repair": "修复方案：【%s】 在计划任务中创建备份网站任务" % webinfo[
                                                    'name'], "dangerous": 0})

    def GetLevelRule(self, get):
        result = []
        data2 = ['364c2b553559697066445638', '364c2b55354c326a66445638',
                 '3537364f3561577a66444577664f694a7375614468513d3d', '365a79793649533466444977664f694a7375614468513d3d',
                 '36594b41364b2b3366444d7766413d3d', '353436773659655266444d77664f574e6d75573971513d3d',
                 '63444a7766444d77664f6976694f6d716c773d3d',
                 '354c6974357061483561325835626d5666444d77664f694a7375614468513d3d',
                 '356232703536576f66445577664f574e6d75573971513d3d', '364c53743562327066445577664f574e6d75573971513d3d',
                 '356f715635724f6f66445577664f574e6d75573971513d3d', '354c71613559326166445577664f574e6d75573971513d3d',
                 '354c71613570435066445577664f574e6d75573971513d3d', '357065673536434266445977664f694a7375614468513d3d',
                 '3570794a3536434266445977664f694a7375614468513d3d', '35594733356f754e66445977664f694a7375614468513d3d',
                 '35705376354c755966445977664f57626d2b615775656155722b53376d413d3d',
                 '356f6951354c713635623278364b654766446377664f694a7375614468513d3d',
                 '356f6951354c7136353553313562327866446377664f694a7375614468513d3d',
                 '3662754536496d79353732523536755a66446377664f694a7375614468513d3d',
                 '3571796e3537364f3562656f354c6d7a66446377664f694a7375614468513d3d',
                 '35367973354c6941354c7961356f6d4166446377664f694a7375614468513d3d',
                 '36496d79356f4f4666446377664f694a7375614468513d3d', '355a7539354c716e51585a384e7a423836496d79356f4f46',
                 '354c71613572537951585a384e7a423836496d79356f4f46', '3570656c3570797359585a384e7a423836496d79356f4f46',
                 '354c6941357079733659475466446377664f694a7375614468513d3d',
                 '357065683536434266446377664f694a7375614468513d3d', '354c6d463649324a66446377664f694a7375614468513d3d',
                 '356f32563662473866446377664f574e6d75573971513d3d',
                 '36494342364a6d4f3570793666446377664f574e6d75573971513d3d',
                 '35714f4c35346d4d66446377664f574e6d75573971513d3d', '36492b6736492b6366446377664f574e6d75573971513d3d',
                 '3572367a365a656f66446377664f574e6d75573971513d3d', '356f2b513534367766446377664f574e6d75573971513d3d',
                 '35615371365a697a355a2b4f66446377664f574e6d75573971513d3d',
                 '354c716b35706954356f6d4166446377664f6d376b656542734f533670773d3d',
                 '354c756c35615371355a324b6644637766413d3d',
                 '3559574e3536322b3537716d66446777664f57626d2b615775656155722b53376d413d3d',
                 '3537712f364c657635714f413572574c6644677766413d3d', '355932613562327066446777664f574e6d75573971513d3d',
                 '364c574d365a4b7866446777664f574e6d75573971513d3d',
                 '35616978354c6d51355a793666446777664f574e6d75573971513d3d', '624739755a7a68384f4442383559326135623270',
                 '3572367a365a656f35615371365a697a355a2b4f66446777664f574e6d75573971513d3d',
                 '364a4768354c717366446731664f574e6d75573971513d3d', '3659655235724b5a66446731664f574e6d75573971513d3d',
                 '365a4f3235724b7a66446731664f574e6d75573971513d3d',
                 '3537712f354c694b354c694c35724f6f66446731664f574e6d75573971513d3d',
                 '35616978354c6d51355a2b4f66446b77664f574e6d75573971513d3d',
                 '3571796e354c7161355a7539365a6d4666446b77664f574e6d75573971513d3d',
                 '354c715335593261355a7539365a6d4666446b77664f574e6d75573971513d3d',
                 '354c6948364c4771355a7539365a6d4666446b77664f574e6d75573971513d3d',
                 '354c6948354c6977355a7539365a6d4666446b77664f574e6d75573971513d3d',
                 '354c716135593261355a7539365a6d4666446b77664f574e6d75573971513d3d',
                 '355a75623570613535705376354c755966446b77664f57626d2b615775656155722b53376d413d3d',
                 '35616942356243383570617666446b31664f574e6d75573971513d3d',
                 '35706177364a4768354c717366446b35664f574e6d75573971513d3d',
                 '364c574d355a793666446b35664f574e6d75573971513d3d', '364c574d3559326166446b35664f574e6d75573971513d3d',
                 '35706532357065323562327066446b77664f574e6d75573971513d3d',
                 '35595774355a43493562327066446b35664f574e6d75573971513d3d',
                 '35616962357169433561433066446777664f574e6d75573971513d3d',
                 '3559574e3536322b35705376354c755966446777664f57626d2b615775656155722b53376d413d3d',
                 '364c53333571792b66446377664f6976694f6d716c773d3d',
                 '35726958365943503572574c364b2b5666445577664f6d376b656542734f533670773d3d',
                 '35705337365a697966445577664f6d376b656542734f533670773d3d',
                 '35356d39356269393561325166445577664f6d376b656542734f533670773d3d',
                 '36627552356269393561325166446377664f6d376b656542734f533670773d3d',
                 '35377169356269393561325166445977664f6d376b656542734f533670773d3d',
                 '3559614635373252357269583659435066445977664f6d376b656542734f533670773d3d',
                 '3559574e3570324166446777664f6d376b656542734f533670773d3d',
                 '35727950357253653562656c3559573366446777664f6d376b656542734f533670773d3d',
                 '56325669357269583659435066446777664f6d376b656542734f533670773d3d',
                 '36594347355a435266446777664f6d376b656542734f533670773d3d',
                 '366275523561366966445977664f6d376b656542734f533670773d3d',
                 '357036423561366966445177664f6d376b656542734f533670773d3d',
                 '35705777356f3275355a53753559325766446377664f6d376b656542734f533670773d3d',
                 '353665523561326d354c694b3537325266446b7766465a5154673d3d', '35372b3735614b5a66446b7766465a5154673d3d',
                 '353732523537756335597167365943666644597766465a5154673d3d', '566c424f66446b7766465a5154673d3d',
                 '55314e5366446b7766465a5154673d3d', '35714b763561325166446b7766465a5154673d3d',
                 '646a4a7959586c384f544238566c424f', '3559716736594366355a6d6f6644637766465a5154673d3d',
                 '3659573436595734354c6d7a66446b7766465a5154673d3d',
                 '626d56306432397961794277636d3934655877334d4878575545343d',
                 '3559364c355971623572574c364b2b5666446b77664f6d376b656542734f533670773d3d',
                 '3572574c3559364c66445177664f6d376b656542734f533670773d3d',
                 '35627941356f692f364b36773562325666445977664f6d376b656542734f533670773d3d',
                 '35613661354c324e354c2b68356f477666445977664f6d376b656542734f533670773d3d',
                 '364b36773562325635702b6c364b2b6966445177664f6d376b656542734f533670773d3d',
                 '3659575335627158364b36773562325666446777664f6d376b656542734f533670773d3d',
                 '355a794c365a716266444d77664f6976694f6d716c773d3d', '356f7156364c4f4866445177664f6976694f6d716c773d3d',
                 '356f6951354c713666445977664f694a7375614468513d3d',
                 '353665423570794e66446377664f6d376b656542734f533670773d3d',
                 '35373252364c533366446377664f6976694f6d716c773d3d', '364c326d364c533366446377664f6976694f6d716c773d3d',
                 '355943663571792b66446377664f6976694f6d716c773d3d', '355969473570796666446377664f6976694f6d716c773d3d',
                 '35364342355a574766445531664f57626d2b615775656155722b53376d413d3d',
                 '35705376354c755935626d7a35592b7766446b77664f57626d2b615775656155722b53376d413d3d',
                 '35705376354c7559356f366c35592b6a66446b77664f57626d2b615775656155722b53376d413d3d',
                 '51584277356271553535536f3559694735592b526644597766413d3d',
                 '364b69383559693466445177664f6976694f6d716c773d3d', '3649324a3571613066446377664f694a7375614468513d3d',
                 '35712b5535346d353562694266445977664f6d376b656542734f533670773d3d',
                 '56564e45564877324d487a707535486e6762446b7571633d',
                 '3535577135592b333537325266445977664f694a7375614468513d3d',
                 '3535577135592b333561536e3559576f66445977664f694a7375614468513d3d',
                 '3535577135592b333562715466445977664f694a7375614468513d3d',
                 '3535577135592b33357043633537536966445977664f694a7375614468513d3d',
                 '5156626c7062506c763664384e6a423836496d79356f4f46',
                 '356136463535533335366150355969703536532b66445977664f694a7375614468513d3d']
        for i in data2:
            result.append(public.en_hexb(i).split('|'))
        # public.print_log("页内风险内容：{}".format(result))
        return result

    def WebIndexSecurity(self, get):
        '''
        @name 首页内容风险
        @author lkq<2022-4-12>
        @param urllist  网站名称
        @return
        '''
        return_result = []
        if 'urllist' in get:
            GetLevelRule = self.GetLevelRule(None)
            for i in get.urllist:
                try:
                    if not i.find('http://') == -1 and i.find('https://') == -1:
                        if '_ws' in get: get._ws.send(public.getJson({"end": False, "ws_callback": get.ws_callback,
                                                                      "info": "正在对URL %s 进行内容风险检测" % get.url,
                                                                      "type": "index"}))
                        data = requests.get(url=i, verify=False)
                        info_data = data.text
                        count = 0
                        result = []
                        for i2 in GetLevelRule:
                            if i2[0] in info_data:
                                count += int(i2[1])
                                result.append(i2[0])
                        if count >= 50:
                            if '_ws' in get: get._ws.send(public.getJson(
                                {"end": False, "ws_callback": get.ws_callback, "info": "URL %s 存在内容风险" % i,
                                 "type": "index", "is_error": True}))
                            return_result.append(
                                {"name": "url %s 存在内容风险 内容风险的关键词如下:【 %s 】" % (i, ' , '.join(result)),
                                 "type": "index", "repair": "修复方案：检查该页面是否被篡改或清理掉此关键词"})
                except:
                    continue
            return return_result
        else:
            return []

    def WebHorse(self, get, webinfo):
        '''
        @name 挂马，暗链检测
        @author lwh<2023-12-15>
        @return
        '''
        # 查找网站域名
        site_domain = public.M('domain').where("pid=?", (webinfo['id'])).select()
        if not site_domain:
            return
        result_list = []
        url_dict = {}  # key:协议+ip+端口；value:域名
        for domain in site_domain:
            url_dict["http://127.0.0.1:{}".format(str(domain['port']))] = domain['name']
            url_dict["https://127.0.0.1:{}".format(str(domain['port']))] = domain['name']
        # 敏感词
        sensitive_words = ['棋牌玩法','投注网站','AG体育平台','信誉开户','百家乐导航','久赢彩','网上赌场','线上赌城','急速百家乐','急速六合彩','线上赌场','性感荷官','线上下注','真人赌博','老虎机','实时彩','网上赌城','实时竞猜平台','炸金花','万丰国际','亚博体育','ttc福利彩票','太阳城集团','互博国际','永利娱乐','皇马娱乐','太阳城','万豪国际','亚博国际','bob体育','188金宝博','凯发娱乐','永利游戏','新葡京','亚洲城','银河娱乐','澳门新葡京','皇冠体育','云鼎娱乐','欧亚国际','beplay','乐动体育','betway','ope体育','意甲全球赞助商','沙巴体育','凯时娱乐','欧宝体育','宝马会','威尼斯人','金沙娱乐','伟德体育','新皇冠体育','大發快3','江苏快三','本站彩票','香港六合彩','幸运彩票','北京赛车','北京28','QG刮刮乐','加拿大28','欢乐生肖','福利3D','北京PK拾','KG彩票','VR彩票','VR真人彩票','开元棋牌','大唐棋牌','幸运棋牌','BG棋牌','百胜棋牌','KY棋牌','FG棋牌','天美棋牌','VG棋牌','王者棋牌','TP棋牌','传奇棋牌','棋乐游','金博棋牌','欢乐棋牌','幸运飞艇','抢庄牛牛','澳门六合彩','极速赛车','冰球突破','水牛闪电战','极速六合彩','极速时时彩','北京PK10','BG大仙捕鱼','FG捕鸟达人','TP劈鱼来了','FG欢乐捕鱼','AG捕鱼王','FG美人捕鱼','TP钱龙捕鱼','BB捕鱼达人','FG雷霆战警','TP炸鱼来了','TP二爷捕鱼','JDB龙王捕鱼','BG西游捕鱼','BG捕鱼大师','GD锦绣厅','AG视讯','AE视讯','LEBO视讯','BG视讯','AG女优厅','DG视讯','WM真人','DS贵宾厅','皇家视讯','eBET如意厅','BG畅游厅','BB视讯','PP王者厅','AB聚龙厅','WG视讯','OG视讯','OG东方厅','EA尊爵厅','欧博视讯','BB富贵厅','电竞牛','BC体育','YSB体育','易胜博体育','沙巴电竞','UG体育','IM体育','TF电竞','泛亚体育','泛亚电竞','三昇体育','国际娱乐中心','移动娱乐平台','娱乐城','深海捕鱼','MG电子','真人娱乐','BBIN旗舰厅','庄闲场','棋牌游戏','快乐彩','LEBO真人厅','欧博视讯厅','千炮捕鱼','彩票投注','四人牛牛','时时反水','PT电子','JDB电子','FG电子','AMEBA电子','BB电子','CQ9电子','PG电子','pp电子','TP电子','NT电子','BG电子','HABA电子','SG电子','PNG电子','AG电子','皇朝电子','DT电子','ICG电子','MW电子','JOKER电子','jbo官网','long8','manbetx','18luck','bet365','yabo','华体会体育','ob真人','成人色站','亚洲va','亚洲av','成在人线','国产av','色影院','日本va','看v片','日本有码','一本道','本地偷拍','日本av','成年人视频','久草小说','成人小说','无码成人','成人影视','色吧图片','成人电影','夜夜撸','在线人成','成人旡码','免费A片','黄色视频','成人在线','国产va','直播裸聊','东京热','成人社区','第一会所','狼人社区','香蕉国产','抖音成年短视频','榴草社区','毛片基地','麻豆视频','狼友社区','猫咪成人','草榴社区','伊人影院','UU直播','柚柚AV','avporn','国产精品','成人高清','日韩视频','欧美日韩','欧美在线','亚洲欧美','日韩欧美','亚洲高清','亚洲有声','高跟丝袜','人妖人兽','变态另类','强暴虐待','美女诱惑','欧美色图','潮吹合集','重口色情','不伦恋情','成人动漫','暴力虐待','推女郎图','美腿丝袜','经典三级','少妇偷情','国产自拍','激情口交','无码专区','巨乳诱惑','日韩精品','人妖直播','露出偷窥','高潮喷吹','人妻熟女','SM重口味','高清无码','人妻系列','强奸乱伦','巨乳美乳','丝袜长腿','校园春色','欧美精品','人兽性交','欧美性爱','熟女人妻','亚洲无码','打飞机区','欧美巨乳','亚洲色图','亚洲情色','亚洲性爱','乱伦熟女','家庭乱伦','精品三级','制服诱惑','露出激情','自慰系列','欧美激情','91porn','ThePorn','抖音成人版','柚子直播','桃色直播','青青视频','小草青青在线视频','久青草','九九堂','国产小青蛙','人妻交换','色情小说']
        # 导入BeautifulSoup
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            public.ExecShell("btpip install beautifulsoup4")
            time.sleep(1)
            try:
                from bs4 import BeautifulSoup
            except:
                # public.print_log("导入BeautifulSoup失败")
                webinfo["result"]['webhorse'] = result_list.copy()
                return

        headers = {
            'User-Agent': 'Mozilla/5.0 (Linux; Android 10; MI 9 Build/QKQ1.190825.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/67.0.3396.87 XWEB/1171 MMWEBSDK/200201 Mobile Safari/537.36 MMWEBID/2568 MicroMessenger/7.0.12.1620(0x27000C37) Process/tools NetType/4G Language/zh_CN ABI/arm64',
            'Referer': 'https://www.baidu.com/'
        }
        for url, domain in url_dict.items():
            try:
                headers['Host'] = domain
                response = self.session.get(url, headers=headers, timeout=2, verify=False)
                response.raise_for_status()  # 如果请求返回了不成功的状态代码，将会抛出一个HTTPError异常。
                # 暗链检测
                dark_line = self.DarkChain(response.text)
                if dark_line != "":
                    if '_ws' in get:
                        get._ws.send(public.getJson(
                            {"info": "【{}】 网站疑似存在暗链 【{}】".format(url, dark_line),
                             "repair": "排查被篡改的文件或恢复网站备份，清除暗链内容，修复网站漏洞，防止再次被入侵。",
                             "type": "webhorse", "dangerous": 1, "is_error": True}))
                    result_list.append(
                        {"name": "【{}】 网站疑似存在暗链 【{}】".format(url, dark_line),
                         "repair": "排查被篡改的文件或恢复网站备份，清除暗链内容，修复网站漏洞，防止再次被入侵。",
                         "type": "webhorse", "dangerous": 1})
                # 使用正则表达式匹配 keywords 和 description 标签内容
                title_pattern = re.compile(r'<title>(.*?)</title>')
                keywords_pattern = re.compile(r'<meta\s+name="keywords"\s+content="([^"]*)"')
                description_pattern = re.compile(r'<meta\s+name="description"\s+content="([^"]*)"')
                # 匹配 titles
                title_match = title_pattern.search(response.content.decode())
                if title_match:
                    title = title_match.group(1)
                else:
                    title = ""
                # 匹配 keywords
                keywords_match = keywords_pattern.search(response.content.decode())
                if keywords_match:
                    keywords = keywords_match.group(1)
                else:
                    keywords = ""
                # 匹配 description
                description_match = description_pattern.search(response.content.decode())
                if description_match:
                    description = description_match.group(1)
                else:
                    description = ""
                # 检测是否存在敏感词
                for sw in sensitive_words:
                    for tw in [title, keywords, description]:
                        if sw in tw:
                            if len(sw) > 2:  # 确保字符串至少有两个字符
                                sw = '*' + sw[1:-1] + '*'  # 将第一个和最后一个字符替换为*
                            elif len(sw) == 2:
                                sw = '*' + sw[1]  # 去除第一个字符
                            if '_ws' in get:
                                get._ws.send(public.getJson(
                                    {"info": "检测到【{}】网站存在挂马字段【{}】".format(domain, sw),
                                     "repair": "手机访问时会出现挂马内容，排查被篡改的文件或恢复网站备份，并修复网站漏洞，防止再次被入侵。",
                                     "type": "webhorse", "dangerous": 2, "is_error": True}))
                            result_list.append(
                                {"name": "检测到【{}】网站存在挂马字段【{}】".format(domain, sw),
                                 "repair": "手机访问时会出现挂马内容，排查网站被篡改的文件或恢复网站备份，并修复网站漏洞，防止再次被入侵。",
                                 "type": "webhorse", "dangerous": 3})
                break  # 任意一个域名可访问则退出循环
            except Exception as e:
                continue
        webinfo["result"]['webhorse'] = result_list.copy()

    def DarkChain(self, content):
        """
        @name 暗链检测
        @author lwh<2024-01-31>
        @param content string 网页内容
        """
        rcontent = ""
        CheckRegs = [
            '<marquee\s+height=[0-9]\s+width=[0-9][^>]*?>([\S\s]*?)</marquee>',
            '<div\s*?id=.?\w{1,20}?.?>([\S\s]*?)</div>\s*?<script>document\.getElementById\(.*?\)\.style\.display=.?none.?[;]?</script>',
            # '<div\s*style=.{0,1}position\s*:\s*absolute.*?(?:top|left):\s*-[\d]{3,4}px.*?>.*?</div>',
            '<div\s*style=.{0,1}position\s*:\s*absolute.*?(?:top|left|right):\s*-[6-9][\d]{2,3}px\s*;(?:top|left|right):\s*-[6-9][\d]{2,3}px\s*;.*?>.*?</div>',
            # '<div\s*?style=.?\s*?position([\S\s]*?)(?:top|left):\s*?-[\d]{3,4}px([\S\s]*?)>([\S\s]*?)</div>',
            # '<MARQUEE\s.*?scrollAmount=.?[\d]{4,5}.?.*?(?:width|height)=.?[0-5].?.*?>.*?</marquee>',
            '<div\s*style=.?text-indent:\s*-[\d]{3,5}px.?>([\S\s]*?)</div>',
            '<div\s*style=[^>]*?position:\s*absolute\s*;\s*(?:top|left)\s*:\s*expression\(.*?\).*?>.*?</div>',
            '<MARQUEE[^>]*?width=["\']?[0-9]?\s+height=["\']?[0-9]["\']?[^>]*?>([\s\S]*?)</MARQUEE>',
            '<div\s+style\s*=\s*["\']*\s*overflow\s*:\s*hidden\s*;\s*height\s*:\d\d?px\s*;\s*width\s*:\s*\d\d?.*?>([\S\s]*?)</div>',
            '<div\s+(?!.*?class.*?)(?!.*?\bid\b.*?).*?style=display:none.*?>([\S\s]*?)</div>'
        ]
        for check in CheckRegs:
            try:
                pattern = re.compile(check, re.DOTALL)
                tokens = pattern.findall(content)
                if len(tokens) != 0:
                    for token in tokens:
                        rcontent = token.strip()
                        return rcontent
            except Exception as e:
                continue
        return rcontent

    def DeadChain(self, get, webinfo):
        """
        @name 检查网站是否存在死链
        """
        # 查找网站域名
        site_domain = public.M('domain').where("pid=?", (webinfo['id'])).select()
        if not site_domain:
            return
        result_list = []
        url_list = []  # 待检测的url
        url_head = ["http://", "https://"]  # 携带的协议头
        real_site_domain = ""  # 网站真实域名
        real_site_port = "80"  # 网站端口
        real_site_head = "http://"  # 网站协议

        # 导入BeautifulSoup
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            public.ExecShell("btpip install beautifulsoup4")
            time.sleep(1)
            try:
                from bs4 import BeautifulSoup
            except:
                # public.print_log("导入BeautifulSoup失败")
                webinfo["result"]['deadchain'] = result_list.copy()
                return
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        # 检查哪一个域名可访问
        for domain in site_domain:
            # http和https
            for head in url_head:
                try:
                    head_url = "{}{}".format(head, domain["name"])  # 本网站
                    headers["Host"] = domain["name"]
                    response = self.session.get("{}127.0.0.1:{}".format(head, domain["port"]), timeout=(2, 5),
                                                headers=headers)
                    response.raise_for_status()  # 如果请求返回了不成功的状态代码，将会抛出一个HTTPError异常。
                    soup = BeautifulSoup(response.content, 'html.parser')
                    # 获取a标签
                    title = soup.select('a')
                    for i in title:
                        url = str(i.get('href'))
                        # 分隔参数
                        if '?' in url:
                            url = url.split('?')[0]
                        elif '#' in url:
                            url = url.split('#')[0]
                        if not url: continue
                        # 去除特殊头
                        if url == "/": continue
                        if url.startswith('tel:'): continue
                        if url.startswith('mailto:'): continue
                        if url == "None":
                            continue
                        static_list = ["png", "jpg", "pdf", "gif", "mp3", "mp4", "js", "css", "bmp", "svg", "ttf",
                                       "woff", "txt", "zip", "7z", "gz", "rar", "jar", ".swap", "exe", "tar"]
                        # 判断是否是静态文件
                        static = url.split(".")[-1]
                        if static in static_list:
                            continue
                        if url.startswith('http://') or url.startswith('https://'):
                            # 判断是否是我们需要爬取的网站
                            if url.startswith(head_url):
                                if url == head_url: continue
                            if url not in url_list:
                                url_list.append(url)
                            # # 如果他是域名填写的是baidu.com 内容中有www.baidu.com
                            # elif url.startswith(head + "www." + domain["name"]):
                            #     if url not in url_list:
                            #         url_list.append(url)
                            # # 如果他是域名填写的是www.baidu.com 内容中有baidu.com
                            # elif url.startswith(head + domain["name"].replace("www.", "")):
                            #     if url not in url_list:
                            #         url_list.append(url)
                        else:
                            if url.startswith("#"): continue
                            if url.lower().startswith('javascript'):
                                continue
                            if url.startswith("#"): continue
                            # 如果url为./ 或者/ 开头
                            if url.startswith('/') or url.startswith('./'):
                                http_domain = head + domain["name"]
                                head_s = head_url.replace(http_domain, "")
                                if url == head_s: continue
                                if url == head_url: continue
                                if url.startswith(head_s + "#"): continue
                                if url.startswith('./'):
                                    url = url.replace('./', '/', 1)
                                # 如果他是/开头的 那么就是在当前域名下的  最终的url为 域名+/1.html
                                if url.startswith("//" + domain["name"]):
                                    url = url.replace("//" + domain["name"], "")
                                url = head + domain["name"] + url
                                url_list.append(url)
                                # list_href += 1
                            else:
                                # 如果为/ 结尾
                                if head_url.endswith('/'):
                                    if url.startswith('/'):
                                        url = url[:-1]
                                    url = head_url + url
                                    url_list.append(url)
                                else:
                                    urls = head_url.split('/')[-1]
                                    if urls == domain["name"]:
                                        url = head_url + '/' + url
                                        url_list.append(url)
                                        # list_href += 1
                                    else:
                                        # 如果有点的情况下。需要判断是否是最后一个点·
                                        if '.' in urls:
                                            url = head_url.replace(urls, "") + url
                                            url_list.append(url)
                                        else:
                                            if head_url.endswith('/'):
                                                url = head_url + url
                                            else:
                                                url = head_url + "/" + url
                                            url_list.append(url)
                                            # list_href += 1
                    real_site_domain = domain["name"]
                    real_site_port = domain["port"]
                    real_site_head = head
                except Exception as e:
                    # public.print_log("坏链检测错误：{}".format(e))
                    continue
                # 已扫描了一个域名则跳出
                break
            # 若已获取到链接，则跳出
            if len(url_list) > 0:
                break
        # 检测首页所有链接是否为死链
        dead_code = [400, 403, 410, 404]
        for url in url_list:
            get._ws.send(public.getJson(
                {"end": False, "callback": get.ws_callback, "info": "正在检测链接【{}】".format(url),
                 "type": "deadchain"}))
            try:
                if real_site_domain:
                    # 若为本网站则用
                    if real_site_domain in url:
                        headers = {
                            'Host': real_site_domain
                        }
                        transfer_url = "{}127.0.0.1:{}{}".format(real_site_head, real_site_port, url.replace("{}{}".format(real_site_head,real_site_domain), ""))
                        response = self.session.get(transfer_url, headers=headers)
                    else:
                        response = self.session.get(url, timeout=(2, 5))
                else:
                    response = self.session.get(url, timeout=(2, 5))
                # response.raise_for_status()  # 如果请求返回了不成功的状态代码，将会抛出一个HTTPError异常。
                # 若状态码是4xx则为死链
                if response.status_code in dead_code:
                    if '_ws' in get:
                        get._ws.send(public.getJson(
                            {"info": "【{}】网站首页疑似存在坏链【{}】".format(get.name, url),
                             "repair": "建议修复或删除不可访问的坏链，防止因坏链过多影响搜索引擎对网站的排行",
                             "type": "deadchain", "dangerous": 1, "is_error": True}))
                    result_list.append(
                        {"name": "【{}】网站首页疑似存在坏链【{}】".format(get.name, url),
                         "repair": "建议修复或删除不可访问的坏链，防止因坏链过多影响搜索引擎对网站的排行",
                         "type": "deadchain", "dangerous": 1})
            except:
                continue
        webinfo["result"]['deadchain'] = result_list.copy()

    def DatabaseSecurity(self, get, webinfo):
        '''
        @name 检查网站数据库配置
        '''
        result_list = []
        # 获取网站id
        web_id = webinfo['id']
        # 查询网站使用的数据库信息
        database = public.M('databases').where("pid=?", (web_id,)).select()
        if not isinstance(database, list):
            return
        for dbinfo in database:
            self.DatabaseWeekPass(get, result_list, dbinfo)
            self.DatabaseAccess(get, result_list, dbinfo)
        webinfo["result"]['database'] = result_list.copy()

    def DatabaseWeekPass(self, get, result_list, dbinfo):
        """
        @name 检查数据库弱口令
        @author lwh<2024-02-01>
        """
        if not os.path.exists("/www/server/panel/config/weak_pass.txt"):
            # public.print_log("弱口令字典不存在")
            return
        pass_info = public.ReadFile("/www/server/panel/config/weak_pass.txt")
        pass_list = pass_info.split('\n')
        if 'password' not in dbinfo:
            return
        if dbinfo['password'] in pass_list:
            if 'name' in dbinfo:
                dbname = dbinfo['name']
            else:
                dbname = ''
            if '_ws' in get:
                get._ws.send(public.getJson(
                    {"info": "【{}】 网站数据库【{}】 存在弱口令【{}】".format(get.name, dbname,
                                                                         self.short_passwd(dbinfo['password'])),
                     "repair": "建议修改弱口令，防止被黑客爆破密码窃取数据",
                     "type": "database", "dangerous": 2, "is_error": True}))
            result_list.append({"name": "【{}】 网站数据库【{}】 存在弱口令【{}】".format(get.name, dbname, self.short_passwd(
                dbinfo['password'])),
                                "repair": "建议修改弱口令，防止被黑客爆破密码窃取数据",
                                "type": "database", "dangerous": 2})

    def DatabaseAccess(self, get, result_list, dbinfo):
        """
        @name 检查数据库访问权限
        @author lwh
        """
        if "name" not in dbinfo or "username" not in dbinfo:
            return
        # 获取数据库对象
        import database
        db_obj = database.database()
        get = public.dict_obj()
        get["name"] = dbinfo["username"]
        # 获取数据库访问权限
        result = db_obj.GetDatabaseAccess(get=get)
        # 判断返回格式
        if "status" not in result or "msg" not in result:
            return
        if result["status"]:
            if result["msg"] == "%":
                if '_ws' in get:
                    get._ws.send(public.getJson(
                        {"info": "【{}】 网站数据库【{}】 访问权限为所有人（不安全）".format(get.name, dbinfo["name"]),
                         "repair": "建议在数据库-权限，将数据库访问权限设置为本地服务器或是指定IP，防止被黑客入侵数据库",
                         "type": "database", "dangerous": 1, "is_error": True}))
                result_list.append(
                    {"name": "【{}】 网站数据库【{}】 访问权限为所有人（不安全）".format(get.name, dbinfo["name"]),
                     "repair": "建议在数据库-权限，将数据库访问权限设置为本地服务器或是指定IP，防止被黑客入侵数据库",
                     "type": "database", "dangerous": 1})

    def FtpWeekPass(self, get, webinfo):
        """
        @name Ftp弱口令检测
        @author lwh
        """
        weekpassfile = "/www/server/panel/config/weak_pass.txt"
        if not os.path.exists(weekpassfile):
            # public.print_log("弱口令字典不存在")
            return
        pass_info = public.ReadFile(weekpassfile)
        pass_list = pass_info.split('\n')
        result_list = []
        if "id" not in webinfo:
            return
        ftps = public.M('ftps').where("pid=?", (webinfo["id"],)).select()
        if not isinstance(ftps, list):
            return
        for ftpinfo in ftps:
            if ftpinfo["password"] in pass_list:
                if '_ws' in get:
                    get._ws.send(public.getJson(
                        {"info": "【{}】 网站ftp用户【{}】 存在弱口令【{}】".format(get.name, ftpinfo["name"],
                                                                              self.short_passwd(ftpinfo["password"])),
                         "repair": "建议修改弱口令，防止被黑客爆破ftp密码篡改网站文件", "type": "ftps", "dangerous": 2,
                         "is_error": True}))
                result_list.append({"name": "【{}】 网站ftp用户【{}】 存在弱口令【{}】"
                                   .format(get.name, ftpinfo["name"], self.short_passwd(ftpinfo["password"])),
                                    "repair": "建议修改弱口令，防止被黑客爆破ftp密码篡改网站文件",
                                    "type": "ftps", "dangerous": 2})
        webinfo["result"]['ftps'] = result_list.copy()

    def WebsiteBackend(self, get, webinfo):
        '''
        @name 网站后台路径检测
        @author lwh<2023-12-15>
        @return
        '''
        result_list = []
        url_head = ["http://", "https://"]  # 携带的协议头
        site_domain = public.M('domain').where("pid=?", (webinfo['id'])).select()
        # 扫描的字典{框架名：{"determine":[根据文件匹配框架], "background":"后台地址", "repair": "修复方案"}}
        cms_dict = {
            "Z-BlogPHP": {"determine": ["zb_system/function/c_system_version.php"], "backend": "/zb_system/login.php"},
            "Wordpress": {"determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                                        "wp-includes/class-wp-hook.php"], "backend": "/wp-login.php"}, "Discuz": {
                "determine": ["uc_client/client.php", "uc_server/lib/uccode.class.php", "uc_server/model/version.php",
                              "source/discuz_version.php"], "backend": "/admin.php"}, "Dedecms": {
                "determine": ["data/admin/ver.txt", "data/common.inc.php", "dede/shops_operations_userinfo.php",
                              "member/edit_space_info.php"], "backend": "/dede/login.php"},
            "Ecshop": {"determine": ["upload/includes/cls_ecshop.php", "upload/admin/check_file_priv.php"],
                       "backend": "/admin/"}, "Empirecms": {
                "determine": ["e/class/EmpireCMS_version.php", "e/search/index.php", "e/member/EditInfo/index.php",
                              "e/ViewImg/index.html"], "backend": "/e/admin/"}, "Eyoucms": {
                "determine": ["data/conf/version.txt", "application/api/controller/Uploadify.php",
                              "application/extra/extra_cache_key.php", "application/admin/controller/Uploadify.php"],
                "backend": "/login.php"}, "Jieqicms": {
                "determine": ["configs/article/guideblocks.php", "lib/text/textconvert.php", "class/pposts.php",
                              "admin/managemodules.php"], "backend": "/admin/"}, "Maccms": {
                "determine": ["thinkphp/base.php", "thinkphp/library/think/App.php",
                              "thinkphp/library/think/Request.php"], "backend": "/admin.php"}}
        # 使用字典,进行去重
        unique_ports = {}
        for domain in site_domain:
            port = domain['port']
            if port not in unique_ports:
                unique_ports[port] = domain

        # 将结果转换回列表
        site_domain = list(unique_ports.values())
        
        # 识别框架类型
        site_path = webinfo["path"]
        for key, value in cms_dict.items():
            flag = True  # 默认是命中
            for file in value["determine"]:
                path = site_path + "/" + file
                if not os.path.exists(path):
                    flag = False
            # 命中框架
            if flag:
                # 导入BeautifulSoup
                try:
                    from bs4 import BeautifulSoup
                except ImportError:
                    public.ExecShell("btpip install beautifulsoup4")
                    time.sleep(1)
                    try:
                        from bs4 import BeautifulSoup
                    except:
                        # public.print_log("导入BeautifulSoup失败")
                        webinfo["result"]['backend'] = result_list.copy()
                        return
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Referer': 'https://www.baidu.com/'
                }
                # 检查哪一个域名可访问
                for domain in site_domain:
                    # http和https
                    for head in url_head:
                        headers["Host"] = domain["name"]
                        try:
                            # 通过端口判断是否可访问
                            head_url = "{}127.0.0.1:{}".format(head, domain["port"])
                            response = self.session.get(head_url, timeout=(2, 5), headers=headers)
                            response.raise_for_status()  # 如果请求返回了不成功的状态代码，将会抛出一个HTTPError异常。
                            # 检查后台是否可以访问
                            response = self.session.get(head_url + value["backend"], timeout=(2, 5), headers=headers)
                            response.raise_for_status()
                            if '_ws' in get:
                                get._ws.send(public.getJson(
                                    {"info": "【{}】 疑似网站后台地址【{}】".format(get.name, value["backend"]),
                                     "repair": "建议在网站访问限制页面将后台地址添加加密访问，或者修改默认后台地址，防止被黑客入侵后台",
                                     "type": "backend",
                                     "dangerous": 1, "is_error": True}))
                            result_list.append(
                                {"name": "【{}】 疑似网站后台地址【{}】未做防护".format(get.name, value["backend"]),
                                 "repair": "建议在网站访问限制页面将后台地址添加加密访问，或者修改默认后台地址，防止被黑客入侵后台接管网站",
                                 "type": "backend",
                                 "dangerous": 1})
                        except requests.exceptions.RequestException as error:
                            continue
        webinfo["result"]['backend'] = result_list.copy()

    def GetDoamin(self, get):
        '''
        @name 获取网站的域名信息
        @author lkq<2022-4-12>
        @param name 网站名称
        @return 网站信息列表 [list]
        '''
        webinfo = self.GetWebInfo(get)
        if not webinfo: return public.returnMsg(False, '当前网站不存在')
        if public.M('domain').where("pid=?", (webinfo['id'])).count() == 0:
            if not webinfo: return public.returnMsg(False, '当前网站不存在')
        return public.returnMsg(True, public.M('domain').where("pid=?", (webinfo['id'])).select())

    def __check_auth(self):
        try:
            from pluginAuth import Plugin
            plugin_obj = Plugin(False)
            plugin_list = plugin_obj.get_plugin_list()
            if int(plugin_list['ltd']) > time.time():
                return True
            return False
        except:
            return False

    """
    @name 获取站点扫描结果的路径
    """

    def get_result_path(self, name):

        result_path = '{}/data/site_scan/'.format(public.get_panel_path())
        if not os.path.exists(result_path):
            os.makedirs(result_path)
        return result_path + name + '.json'

    """
    @name 获取站点扫描结果
    @param name 站点名称
    """

    def get_site_result(self, get):

        if not os.path.exists(self.get_result_path(get.name)):
            return public.returnMsg(False, '当前网站未扫描过')
        try:
            return json.loads(public.ReadFile(self.get_result_path(get.name)))
        except:
            return public.returnMsg(False, '获取失败，请重新扫描')

    def ScanSingleSite(self, get):
        """
        @name 扫描单个网站
        @author lkq<2022-4-12>
        @param name  网站名称
        @param vulscan  漏洞扫描
        webscan   网站配置安全性  SSL证书安全性  php/nginx/apache版本泄露   目录和文件权限
        filescan 文件泄漏
        backuo 是否备份重要数据
        webshell 木马
        拨测 boce
        index 首页内容风险
        @param scan_list=[""]
        @return
        """
        webinfo = self.GetWebInfo(get)
        if not webinfo: return public.returnMsg(False, '当前网站不存在')
        webinfo['result'] = {}
        if '_ws' in get:
            # websocket
            for i in get.scan_list:
                if i == 'vulscan':
                    get._ws.send(public.getJson(
                        {"end": False, "ws_callback": get.ws_callback, "info": "正在扫描漏洞", "type": "vulscan"}))
                    webinfo['result']['vulscan'] = self.ScanWeb(get)
                    get._ws.send(public.getJson(
                        {"end": False, "ws_callback": get.ws_callback, "info": "漏洞扫描完成", "type": "vulscan"}))
                if i == 'webscan':
                    get._ws.send(public.getJson(
                        {"end": False, "callback": get.ws_callback, "info": "正在扫描网站配置安全性",
                         "type": "webscan"}))
                    webinfo['result']['webscan'] = self.WebInfoDisclosure(get)
                    get._ws.send(public.getJson(
                        {"end": False, "callback": get.ws_callback, "info": "正在扫描网站权限配置", "type": "webscan"}))
                    # self.WebFilePermission(webinfo, get)
                    get._ws.send(public.getJson(
                        {"end": False, "callback": get.ws_callback, "info": "网站权限配置扫描完成", "type": "webscan"}))
                    get._ws.send(public.getJson(
                        {"end": False, "callback": get.ws_callback, "info": "正在扫描SSL安全", "type": "webscan"}))
                    # 存在大量扫描记录
                    # self.WebSSlSecurity(webinfo, get)
                    get._ws.send(public.getJson(
                        {"end": False, "callback": get.ws_callback, "info": "网站SSL扫描完成", "type": "webscan"}))
                if i == 'filescan':
                    get._ws.send(public.getJson(
                        {"end": False, "callback": get.ws_callback, "info": "正在扫描文件泄漏", "type": "filescan"}))
                    self.WebFileDisclosure(webinfo, get)
                    get._ws.send(public.getJson(
                        {"end": False, "callback": get.ws_callback, "info": "文件泄漏扫描完成", "type": "filescan"}))
                if i == 'backup':
                    get._ws.send(public.getJson(
                        {"end": False, "callback": get.ws_callback, "info": "正在扫描备份文件", "type": "backup"}))
                    self.WebBackup(webinfo, get)
                    get._ws.send(public.getJson(
                        {"end": False, "callback": get.ws_callback, "info": "备份文件扫描完成", "type": "backup"}))
                if i == 'webshell':
                    get._ws.send(public.getJson(
                        {"end": False, "callback": get.ws_callback, "info": "正在扫描webshell", "type": "webshell"}))
                    self.WebShellKill(get, webinfo)
                    get._ws.send(public.getJson(
                        {"end": False, "callback": get.ws_callback, "info": "webshell扫描完成", "type": "webshell"}))
                if i == 'boce':
                    get._ws.send(public.getJson(
                        {"end": False, "callback": get.ws_callback, "info": "正在进行拨测", "type": "boce"}))
                    if 'url' in get:
                        self.WebBtBoce(get, webinfo)
                    get._ws.send(
                        public.getJson({"end": False, "callback": get.ws_callback, "info": "拨测完成", "type": "boce"}))
                if i == 'index':
                    get._ws.send(public.getJson(
                        {"end": False, "callback": get.ws_callback, "info": "正在进行页内内容风险检测",
                         "type": "index"}))
                    webinfo['result']['index'] = self.WebIndexSecurity(get)
                    get._ws.send(public.getJson(
                        {"end": False, "callback": get.ws_callback, "info": "页内容风险检测完成", "type": "index"}))
                if i == 'webhorse':
                    get._ws.send(public.getJson(
                        {"end": False, "callback": get.ws_callback, "info": "正在进行网站挂马检测",
                         "type": "webhorse"}))
                    self.WebHorse(get, webinfo)
                    get._ws.send(public.getJson(
                        {"end": False, "callback": get.ws_callback, "info": "网站挂马检测完成", "type": "webhorse"}))
                if i == 'deadchain':
                    get._ws.send(public.getJson({"end": False, "callback": get.ws_callback, "info": "正在进行网站死链检测",
                                                 "type": "deadchain"}))
                    self.DeadChain(get, webinfo)
                    get._ws.send(public.getJson({"end": False, "callback": get.ws_callback, "info": "网站死链检测完成",
                                                 "type": "deadchain"}))
                if i == 'database':
                    get._ws.send(public.getJson(
                        {"end": False, "callback": get.ws_callback, "info": "正在进行网站数据库风险检测", "type": "database"}))
                    self.DatabaseSecurity(get, webinfo)
                    get._ws.send(public.getJson(
                        {"end": False, "callback": get.ws_callback, "info": "网站数据库风险检测完成", "type": "database"}))
                if i == 'ftps':
                    get._ws.send(public.getJson(
                        {"end": False, "callback": get.ws_callback, "info": "正在进行网站Ftp风险检测",
                         "type": "ftps"}))
                    self.FtpWeekPass(get, webinfo)
                    get._ws.send(public.getJson(
                        {"end": False, "callback": get.ws_callback, "info": "网站Ftp风险检测完成", "type": "ftps"}))
                if i == 'backend':
                    get._ws.send(public.getJson(
                        {"end": False, "callback": get.ws_callback, "info": "正在进行网站后台检测",
                         "type": "backend"}))
                    self.WebsiteBackend(get, webinfo)
                    get._ws.send(public.getJson(
                        {"end": False, "callback": get.ws_callback, "info": "网站后台检测完成", "type": "ftps"}))

                # 如果不是企业版，删除一些漏洞修复的字段
                pay = self.__check_auth()
                if not pay:
                    for issue in webinfo["result"]:
                        for dict_itera in webinfo["result"][issue]:
                            dict_itera.pop("name", None)
                            dict_itera.pop("ps", None)
                            dict_itera.pop("repair", None)

                get._ws.send(public.getJson(
                    {"end": True, "ws_callback": get.ws_callback, "info": "扫描完成", "type": i, "webinfo": webinfo}))

                data = {}
                try:
                    data = json.loads(public.readFile(self.get_result_path(get.name)))
                except:
                    pass
                data[i] = webinfo['result'][i]

                public.writeFile(self.get_result_path(get.name), json.dumps(data))
            time_info = int(time.time())
            public.WriteFile("/www/server/panel/config/webscaning_time", str(time_info))
        else:
            if os.path.exists("/www/server/panel/config/webscaning_time"):
                try:
                    time_info = int(public.ReadFile("/www/server/panel/config/webscaning_time"))
                    return public.returnMsg(True, time_info)
                except:
                    return public.returnMsg(True, 0)
            else:
                return public.returnMsg(True, 0)
        # else:
        #     for i in get.scan_list:
        #         if i=='vulscan':
        #             webinfo['result']['vulscan']=self.ScanWeb(get)
        #         if i=='webscan':
        #             webinfo['result']['webscan']=self.WebInfoDisclosure(get)
        #             self.WebFilePermission(webinfo)
        #             self.WebSSlSecurity(webinfo)
        #         if i=='filescan':
        #             self.WebFileDisclosure(webinfo)
        #         if i=='backup':
        #             self.WebBackup(webinfo)
        #         if i=='webshell':
        #             self.WebShellKill(get,webinfo)
        #         if i=='boce':
        #             if  'url' in get:
        #                 self.WebBtBoce(get,webinfo)
        #         if i=='index':
        #             pass
        #     return webinfo
    def repair(self, get):
        """
        一键修复
        @author lwh<2024-03-20>
        """
        public.set_module_logs('webscanning', 'repair', 1)

    def GetAllSite(self, get):
        """
        获取所有网站列表
        @author lwh<2024-03-14>
        """
        if not hasattr(get, "_ws"):
            return public.returnMsg(False, 'not ws')
        # public.print_log(image_list)
        site_list = public.M('sites').where('project_type=?', ('PHP',)).field("name").select()
        get._ws.send(public.GetJson({"end": True, "site_list": site_list}))

    def ScanAllSite(self, get):
        """
        @name 扫全站
        @author lwh<2024-03-14>
        """
        self.risk_count = {
            "warning": 0,  # 告警 (0)
            "low": 0,  # 低 (1)
            "middle": 0,  # 中 (2)
            "high": 0  # 高 (3)
        }
        if not hasattr(get, "_ws"):
            return public.returnMsg(False, 'not ws')
        # 初始化时间
        self.send_time = time.time()
        # 初始化进度条
        self.bar = 0
        if not hasattr(get, "site_list"):
            return public.returnMsg(False, 'not site_list')
        if not isinstance(get.site_list, list):
            return public.returnMsg(False, 'site_list not a list')
        # 获取所有php网站信息
        site_list = []
        self.web_count_list = []
        all_site_list = public.M('sites').where('project_type=?', ('PHP',)).select()
        for site in all_site_list:
            if site["name"] in get.site_list:
                site_list.append(site)
                self.web_count_list.append(site["name"])
                
        # all_result = {"spend_time": "", "start_time": "", "risk": [], "score": 100, "risk_count": 0, "web_count": 0}
        # 扫描网站漏洞-------------------------------+
        # self.scan_type = "vulscan"  # 设置扫描类型
        # self.send_web_ws(get, msg="正在排查PHP网站漏洞")
        # for site in site_list:
        #     get.name = site["name"]
        #     scanInfo = PluginLoader.module_run("scanning", "startScanWeb", get)
        #     for info in scanInfo["msg"]:
        #         if info['is_vufix']:
        #             vul_type = []
        #             vul_repair = []
        #             for i in info['cms']:
        #                 vul_type.append(i["name"])
        #                 vul_repair.append(i["repair"].replace("\\n", "<br>"))
        #             self.send_web_ws(get=get, msg="发现({})网站漏洞".format(info['name']), detail="({})网站存在漏洞：<br>漏洞类型：{}"
        #                              .format(info['name'], '<br>'.join(vul_type)),
        #                              repair="{}".format('<br>'.join(vul_repair)), dangerous=3)
        self.bar = 10
        # 扫描网站配置-------------------------------+
        self.scan_type = "webscan"
        self.send_web_ws(get, msg="正在检查网站配置")
        # nginx版本泄露
        if public.get_webserver() == 'nginx':
            nginx_path = '/www/server/nginx/conf/nginx.conf'
            if os.path.exists(nginx_path):
                nginx_info = public.ReadFile(nginx_path)
                if not 'server_tokens off' in nginx_info:
                    self.send_web_ws(get=get, msg="nginx版本信息泄露", detail="nginx配置文件未关闭server_tokens，存在被黑客利用漏洞攻击的风险",
                                     repair="打开面板软件商店-nginx管理-配置修改，在http { }中加上：server_tokens off;",dangerous=1)
        # php版本泄露
        php_directory = "/www/server/php"
        php_list = []
        for site in site_list:
            phpversion = public.get_site_php_version(site["name"])
            phpini = '/www/server/php/%s/etc/php.ini' % phpversion
            # phpini = php_directory+"/"+phpver+"/etc/php.ini"
            # 已经检查过就不检查
            if phpversion in php_list:
                continue
            if os.path.exists(phpini):
                php_list.append(phpversion)
                php_info = public.ReadFile(phpini)
                if not 'expose_php = Off' in php_info:
                    self.send_web_ws(get=get, msg="PHP {} 存在版本信息泄露".format(phpversion), detail="PHP {} 存在版本信息泄露".format(phpversion), repair="打开面板软件商店-PHP{}管理".format(phpversion),dangerous=1)
                if re.search("\nallow_url_include\\s*=\\s*(\\w+)", php_info):
                    include_php = re.search("\nallow_url_include\\s*=\\s*(\\w+)", php_info).groups()[0]
                    if include_php.lower() == "off":
                        pass
                    else:
                        self.send_web_ws(get=get, msg="PHP {} 远程包含".format(phpversion),
                                         detail="PHP {} 远程包含allow_url_include参数为开启状态，可能存在被黑客远程控制的风险".format(phpversion),
                                         repair="打开面板软件商店-PHP{}管理-将参数(allow_url_include)设置为Off，并重载配置".format(phpversion),dangerous=2)
        self.bar = 20
        # 是否开启防火墙
        if not os.path.exists("/www/server/btwaf/"):
            self.send_web_ws(get=get, msg="未安装防火墙", detail="未安装防火墙，网站存在入侵风险", repair="安装防火墙",dangerous=1)
        # else:
        #     waf_list = self.get_waf_status_all()
        #     for waf_info in waf_list:
        #         if not waf_list[get.name]['status']:
        #             self.send_web_ws(get=get, msg="()网站未开启防火墙".format())
        #             if '_ws' in get: get._ws.send(public.getJson(
        #                 {"end": False, "ws_callback": get.ws_callback,
        #                  "info": "【{}】网站未开启防火墙".format(get.name),
        #                  "type": "webscan", "is_error": True, "dangerous": 1}))
        #             result.append({"name": "【{}】网站未开启防火墙".format(get.name),
        #                            "repair": "修复方案：在WAF-站点设置开启网站防火墙状态", "dangerous": 1,
        #                            "type": "webscan"})
        # 检查是否开启防跨站
        for web in site_list:
            run_path = self.GetSiteRunPath(web["name"], web["path"])
            if not run_path:
                continue
            path = web["path"] + run_path
            user_ini_file = path + ".user.ini"
            # 文件不存在也代表没开
            # if not os.path.exists(user_ini_file):
            #     if '_ws' in get: get._ws.send(public.getJson(
            #         {"end": False, "ws_callback": get.ws_callback,
            #          "info": "【{}】网站未开启防跨站".format(get.name), "repair": "网站目录-开启防跨站攻击(open_basedir)",
            #          "type": "webscan", "is_error": True, "dangerous": 1}))
            #     result.append({"name": "【{}】网站未开启防跨站".format(get.name),
            #                    "repair": "修复方案：网站目录-启用防跨站攻击(open_basedir)，防止黑客通过跨越目录读取敏感数据",
            #                    "dangerous": 1, "type": "webscan"})
            #     continue
            # 文件不存在
            if not os.path.exists(user_ini_file):
                self.send_web_ws(get=get, msg="({})网站存在跨站风险".format(web["name"]),
                                 detail="({})网站未开启防跨站攻击开关".format(web["name"]),
                                 repair="打开({})网站设置-网站目录-开启防跨站攻击开关".format(web["name"]), dangerous=0)
                continue
            user_ini_conf = public.ReadFile(user_ini_file)
            if "open_basedir" not in user_ini_conf:
                self.send_web_ws(get=get, msg="({})网站存在跨站风险".format(web["name"]),
                                 detail="({})网站未开启防跨站攻击开关".format(web["name"]),
                                 repair="打开({})网站设置-网站目录-开启防跨站攻击开关".format(web["name"]),dangerous=0)
        # 扫描网站文件权限------------------------------------------+
        # web['result']['webscan'] = []
        # atime = time.time()
        # self.WebFilePermission(web, get)
        # public.print_log("WebFilePermission耗时：{}".format(time.time() - atime))
        # 扫描网站SSL配置------------------------------------------+
        if public.get_webserver() == 'nginx':
            keyText = 'ssl_certificate'
            for site in site_list:
                conf_file = '/www/server/panel/vhost/nginx/{}.conf'.format(site['name'])
                if os.path.exists(conf_file):
                    conf_info = public.ReadFile(conf_file)
                    if conf_info.find(keyText) == -1:
                        self.send_web_ws(get=get, msg="网站({})未启用SSL".format(site['name']), detail="网站没有部署SSL证书，数据传输不加密，容易收到中间人攻击，影响搜索引擎排名",
                                         repair="打开网站设置-SSL部署证书", dangerous=0)
        self.bar = 30
        # 扫描文件泄露--------------------------------------------+
        self.scan_type = "filescan"
        self.send_web_ws(get, msg="正在排查文件安全")
        for site in site_list:
            web_path = site["path"]
            # 网站路径不存在，跳过检测
            if not os.path.exists(web_path):
                continue
            for i in os.listdir(web_path):
                is_name = os.path.join(web_path, i)
                if os.path.isfile(is_name):
                    is_name = is_name.replace('<', '&lt;').replace('>', '&gt;')
                    if is_name.endswith(".sql"):
                        self.send_web_ws(get=get, msg="({})网站存在sql数据库文件".format(site["name"]),
                                         detail="({})网站根目录疑似存在sql数据库文件{}，可能会被下载利用".format(site["name"], is_name),
                                         repair="将.sql文件转移到其他地方", dangerous=2)
                    elif is_name.endswith(".zip") or is_name.endswith(".gz") or is_name.endswith(
                            ".tar") or is_name.endswith(".7z") or is_name.endswith(".bak"):
                        self.send_web_ws(get=get, msg="({})网站存在网站备份文件".format(site["name"]),
                                         detail="({})网站根目录疑似存在网站备份文件{}，可能会被下载利用".format(
                                             web_path, is_name), repair="将文件转移到其他地方", dangerous=2)
                if os.path.isdir(is_name):
                    # .git、.svn泄露
                    if is_name.endswith(".svn") or is_name.endswith(".git") or is_name.endswith(".cvs"):
                        self.send_web_ws(get=get, msg="({})网站存在版本控制文件".format(web_path),
                                         detail="({})网站根目录存在版本控制文件{}，可能导致网站源代码泄露".format(
                                             web_path, is_name), repair="将该目录转移到其他地方或者设置禁止访问", dangerous=1)
        self.bar = 40
        # 扫描网站备份-----------------------------------------------+
        self.scan_type = "backup"
        self.send_web_ws(get, msg="正在检测网站备份情况")
        import crontab
        cron_obj = crontab.crontab()
        cron_data = cron_obj.GetCrontab(None)
        isBak = False
        isBakList = []
        for cron in cron_data:
            if cron['sType'] == 'site':
                if cron['sName'] == 'All':
                    isBak = True
                    break
                else:
                    isBakList.append(cron['sName'])
        if not isBak:
            for site in site_list:
                if site["name"] not in isBakList:
                    self.send_web_ws(get=get, msg="网站({})缺少定期备份".format(site["name"]),
                                     detail="网站({})缺少计划任务备份，可能导致发生丢失时无法恢复".format(site["name"]),
                                     repair="在计划任务中创建备份网站任务", dangerous=0)
        self.bar = 50
        # 扫描首页内容------------------------------------------------+
        self.scan_type = "index"
        self.send_web_ws(get, msg="正在检查网站首页内容")
        time.sleep(0.05)
        # 扫描网站挂马-------------------------------------------------+
        self.scan_type = "webhorse"
        self.send_web_ws(get, msg="正在进行网站挂马检测")
        self.session.max_redirects = 3
        # 使用正则表达式匹配 keywords 和 description 标签内容
        title_pattern = re.compile(r'<title>(.*?)</title>')
        keywords_pattern = re.compile(r'<meta\s+name="keywords"\s+content="([^"]*)"')
        description_pattern = re.compile(r'<meta\s+name="description"\s+content="([^"]*)"')
        for site in site_list:
            site_domain = public.M('domain').where("pid=?", (site['id'])).select()
            if not site_domain:
                continue
            url_dict = {}  # key:协议+ip+端口；value:域名
            for domain in site_domain:
                url_dict["http://127.0.0.1:{}".format(str(domain['port']))] = domain['name']
                url_dict["https://127.0.0.1:{}".format(str(domain['port']))] = domain['name']
            # 敏感词
            sensitive_words = ['棋牌玩法', '投注网站', 'AG体育平台', '信誉开户', '百家乐导航', '久赢彩', '网上赌场',
                               '线上赌城', '急速百家乐', '急速六合彩', '线上赌场', '性感荷官', '线上下注', '真人赌博',
                               '老虎机', '实时彩', '网上赌城', '实时竞猜平台', '炸金花', '万丰国际', '亚博体育',
                               'ttc福利彩票', '太阳城集团', '互博国际', '永利娱乐', '皇马娱乐', '太阳城', '万豪国际',
                               '亚博国际', 'bob体育', '188金宝博', '凯发娱乐', '永利游戏', '新葡京', '亚洲城',
                               '银河娱乐', '澳门新葡京', '皇冠体育', '云鼎娱乐', '欧亚国际', 'beplay', '乐动体育', 'betway',
                               'ope体育', '意甲全球赞助商', '沙巴体育', '凯时娱乐', '欧宝体育', '宝马会', '威尼斯人', '金沙娱乐',
                               '伟德体育', '新皇冠体育', '大發快3', '江苏快三', '本站彩票', '香港六合彩', '幸运彩票',
                               '北京赛车', '北京28', 'QG刮刮乐', '加拿大28', '欢乐生肖', '福利3D', '北京PK拾', 'KG彩票',
                               'VR彩票', 'VR真人彩票', '开元棋牌', '大唐棋牌', '幸运棋牌', 'BG棋牌', '百胜棋牌',
                               'KY棋牌', 'FG棋牌', '天美棋牌', 'VG棋牌', '王者棋牌', 'TP棋牌', '传奇棋牌', '棋乐游', '金博棋牌',
                               '欢乐棋牌', '幸运飞艇', '抢庄牛牛', '澳门六合彩', '极速赛车', '冰球突破', '水牛闪电战',
                               '极速六合彩', '极速时时彩', '北京PK10', 'BG大仙捕鱼', 'FG捕鸟达人', 'TP劈鱼来了',
                               'FG欢乐捕鱼', 'AG捕鱼王', 'FG美人捕鱼', 'TP钱龙捕鱼', 'BB捕鱼达人', 'FG雷霆战警',
                               'TP炸鱼来了', 'TP二爷捕鱼', 'JDB龙王捕鱼', 'BG西游捕鱼', 'BG捕鱼大师', 'GD锦绣厅',
                               'AG视讯', 'AE视讯', 'LEBO视讯', 'BG视讯', 'AG女优厅', 'DG视讯', 'WM真人', 'DS贵宾厅', '皇家视讯',
                               'eBET如意厅', 'BG畅游厅', 'BB视讯', 'PP王者厅', 'AB聚龙厅', 'WG视讯', 'OG视讯',
                               'OG东方厅', 'EA尊爵厅', '欧博视讯', 'BB富贵厅', '电竞牛', 'BC体育', 'YSB体育', '易胜博体育',
                               '沙巴电竞', 'UG体育', 'IM体育', 'TF电竞', '泛亚体育', '泛亚电竞', '三昇体育', '国际娱乐中心',
                               '移动娱乐平台', '娱乐城', '深海捕鱼', 'MG电子', '真人娱乐', 'BBIN旗舰厅', '庄闲场',
                               '棋牌游戏', '快乐彩', 'LEBO真人厅', '欧博视讯厅', '千炮捕鱼', '彩票投注', '四人牛牛',
                               '时时反水', 'PT电子', 'JDB电子', 'FG电子', 'AMEBA电子', 'BB电子', 'CQ9电子', 'PG电子',
                               'pp电子', 'TP电子', 'NT电子', 'BG电子', 'HABA电子', 'SG电子', 'PNG电子', 'AG电子',
                               '皇朝电子', 'DT电子', 'ICG电子', 'MW电子', 'JOKER电子', 'jbo官网', 'long8', 'manbetx',
                               '18luck', 'bet365', 'yabo', '华体会体育', 'ob真人', '成人色站', '亚洲va', '亚洲av',
                               '成在人线', '国产av', '色影院', '日本va', '看v片', '日本有码', '一本道', '本地偷拍',
                               '日本av', '成年人视频', '久草小说', '成人小说', '无码成人', '成人影视', '色吧图片',
                               '成人电影', '夜夜撸', '在线人成', '成人旡码', '免费A片', '黄色视频', '成人在线',
                               '国产va', '直播裸聊', '东京热', '成人社区', '第一会所', '狼人社区', '香蕉国产', '抖音成年短视频',
                               '榴草社区', '毛片基地', '麻豆视频', '狼友社区', '猫咪成人', '草榴社区', '伊人影院',
                               'UU直播', '柚柚AV', 'avporn', '国产精品', '成人高清', '日韩视频', '欧美日韩', '欧美在线',
                               '亚洲欧美', '日韩欧美', '亚洲高清', '亚洲有声', '高跟丝袜', '人妖人兽', '变态另类', '强暴虐待',
                               '美女诱惑', '欧美色图', '潮吹合集', '重口色情', '不伦恋情', '成人动漫', '暴力虐待',
                               '推女郎图', '美腿丝袜', '经典三级', '少妇偷情', '国产自拍', '激情口交', '无码专区',
                               '巨乳诱惑', '日韩精品', '人妖直播', '露出偷窥', '高潮喷吹', '人妻熟女', 'SM重口味',
                               '高清无码', '人妻系列', '强奸乱伦', '巨乳美乳', '丝袜长腿', '校园春色', '欧美精品',
                               '人兽性交', '欧美性爱', '熟女人妻', '亚洲无码', '打飞机区', '欧美巨乳', '亚洲色图',
                               '亚洲情色', '亚洲性爱', '乱伦熟女', '家庭乱伦', '精品三级', '制服诱惑', '露出激情',
                               '自慰系列', '欧美激情', '91porn', 'ThePorn', '抖音成人版', '柚子直播', '桃色直播',
                               '青青视频', '小草青青在线视频', '久青草', '九九堂', '国产小青蛙', '人妻交换', '色情小说']

            headers = {
                'User-Agent': 'Mozilla/5.0 (Linux; Android 10; MI 9 Build/QKQ1.190825.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/67.0.3396.87 XWEB/1171 MMWEBSDK/200201 Mobile Safari/537.36 MMWEBID/2568 MicroMessenger/7.0.12.1620(0x27000C37) Process/tools NetType/4G Language/zh_CN ABI/arm64',
                'Referer': 'https://www.baidu.com/'
            }
            for url, domain in url_dict.items():
                try:
                    self.send_web_ws(get=get, msg="排查网站({})挂马".format(domain))
                    headers['Host'] = domain
                    response = self.session.get(url, headers=headers, timeout=(2, 5), verify=False)
                    response.raise_for_status()  # 如果请求返回了不成功的状态代码，将会抛出一个HTTPError异常。
                    # 暗链检测
                    # dark_line = self.DarkChain(response.text)
                    # if dark_line != "":
                    #     if '_ws' in get:
                    #         get._ws.send(public.getJson(
                    #             {"name": "【{}】 网站疑似存在暗链 【{}】".format(url, dark_line),
                    #              "repair": "排查被篡改的文件或恢复网站备份，清除暗链内容，修复网站漏洞，防止再次被入侵。",
                    #              "type": "webhorse", "dangerous": 1}))
                    #     result_list.append(
                    #         {"name": "【{}】 网站疑似存在暗链 【{}】".format(url, dark_line),
                    #          "repair": "排查被篡改的文件或恢复网站备份，清除暗链内容，修复网站漏洞，防止再次被入侵。",
                    #          "type": "webhorse", "dangerous": 1})
                    # 匹配 titles
                    title_match = title_pattern.search(response.content.decode())
                    if title_match:
                        title = title_match.group(1)
                    else:
                        title = ""
                    # 匹配 keywords
                    keywords_match = keywords_pattern.search(response.content.decode())
                    if keywords_match:
                        keywords = keywords_match.group(1)
                    else:
                        keywords = ""
                    # 匹配 description
                    description_match = description_pattern.search(response.content.decode())
                    if description_match:
                        description = description_match.group(1)
                    else:
                        description = ""
                    # 检测是否存在敏感词
                    for sw in sensitive_words:
                        for tw in [title, keywords, description]:
                            if sw in tw:
                                if len(sw) > 2:  # 确保字符串至少有两个字符
                                    sw = '*' + sw[1:-1] + '*'  # 将第一个和最后一个字符替换为*
                                elif len(sw) == 2:
                                    sw = '*' + sw[1]  # 去除第一个字符
                                self.send_web_ws(get=get, msg="检测到({})网站首页存在挂马".format(domain, sw),
                                detail="检测到网站({})首页存在挂马字段({})，使用手机访问网站首页时会跳转至非法页面。".format(domain, sw), repair="排查被篡改的文件或恢复网站备份，并修复网站漏洞，防止再次被入侵",dangerous=2)
                    time.sleep(0.08)  # 减低速度
                    break  # 任意一个域名可访问则退出循环
                except:
                    continue
        self.bar = 70
        # 扫描坏链------------------------------------------------+
        self.scan_type = "deadchain"
        self.send_web_ws(get, msg="正在进行坏链扫描")
        time.sleep(0.05)
        # 扫描数据库安全--------------------------------------+
        self.scan_type = "database"
        self.send_web_ws(get, msg="正在检查网站数据库")
        for site in site_list:
            web_id = site['id']
            database = public.M('databases').where("pid=?", (web_id, )).select()
            if not isinstance(database, list):
                continue
            # 弱口令
            if os.path.exists("/www/server/panel/config/weak_pass.txt"):
                pass_info = public.ReadFile("/www/server/panel/config/weak_pass.txt")
                pass_list = pass_info.split('\n')
                for dbinfo in database:
                    if 'password' not in dbinfo:
                        continue
                    if dbinfo["password"] in pass_list:
                        if 'name' in dbinfo:
                            dbname = dbinfo['name']
                        else:
                            dbname = ''
                        self.send_web_ws(get=get, msg="({})网站数据库存在弱口令".format(site["name"]), detail="({})网站数据库({})存在弱口令：{}".format(site["name"], dbname, self.short_passwd(dbinfo['password'])), repair="建议在面板数据库修改该用户密码，防止被黑客爆破密码窃取数据",dangerous=1)

                # self.DatabaseAccess(get, result_list, dbinfo)
        self.bar = 80
        # 扫描FTP安全----------------------------------+
        self.scan_type = "ftps"
        self.send_web_ws(get, msg="正在检查网站Ftp风险")
        weekpassfile = "/www/server/panel/config/weak_pass.txt"
        if os.path.exists(weekpassfile):
            pass_info = public.ReadFile(weekpassfile)
            pass_list = pass_info.split('\n')
            for site in site_list:
                web_id = site['id']
                ftps = public.M('ftps').where("pid=?", (web_id,)).select()
                if not isinstance(ftps, list):
                    continue
                for ftpinfo in ftps:
                    if ftpinfo["password"] in pass_list:
                        self.send_web_ws(get=get, msg="({})网站ftp用户存在弱口令".format(site["name"]),
                                         detail="({})网站ftp用户({})存在弱口令({})".format(site["name"], ftpinfo["name"],self.short_passwd(ftpinfo["password"])),
                                         repair="建议修改弱口令，防止被黑客爆破ftp密码篡改网站文件", dangerous=2)
        # 扫描网站后台安全--------------------------------------+
        self.scan_type = "backend"
        self.send_web_ws(get, msg="正在检查网站后台风险")
        self.bar = 100
        time.sleep(0.05)
        cache.set("web_scaning_times", self.web_scan_num, 1600)
        # 保存当前检测结果
        self.save_risk_count()
        self.send_web_ws(get=get, msg="扫描完成", end=True)
        # public.print_log("总耗时：{}".format(time.time() - stime))

    def get_risk_count(self, get):
        """获取安全扫描统计结果
        @return: dict {
            'scan_time': str 扫描时间,
            'risk_count': {
                'warning': int 告警数量,
                'low': int 低危数量,
                'middle': int 中危数量,
                'high': int 高危数量
            }
            'web_count': int 扫描网站总数量
        }
        """

        def get_web_count():
            # 【内置】获取网站数量
            try:
                web_count = public.M('sites').where('project_type=?', ('PHP',)).count()
                return web_count
            except:
                return 0

        # 默认返回结果
        default_result = {
            'scan_time': public.format_date(),
            'risk_count': {
                'warning': 0,
                'low': 0,
                'middle': 0,
                'high': 0
            },
            'web_count': get_web_count()
        }
        
        try:
            result_file = '/www/server/panel/data/safeCloud/web_scan_result.json'
            
            # 检查文件是否存在
            if not os.path.exists(result_file):
                return default_result
                
            # 读取文件内容
            result_data = public.readFile(result_file)
            if not result_data:
                return default_result
                
            # 解析JSON数据
            result = json.loads(result_data)
            
            # 验证数据格式
            if not isinstance(result, dict):
                return default_result
                
            if 'scan_time' not in result or 'risk_count' not in result:
                return default_result
                
            # 验证risk_count中的字段
            risk_count = result.get('risk_count', {})
            if not isinstance(risk_count, dict):
                return default_result
                
            required_fields = ['warning', 'low', 'middle', 'high']
            for field in required_fields:
                if field not in risk_count:
                    return default_result
                if not isinstance(risk_count[field], (int, float)):
                    risk_count[field] = 0
                    
            # 确保scan_time是字符串
            if not isinstance(result['scan_time'], str):
                result['scan_time'] = public.format_date()
            return result
            
        except Exception as e:
            public.WriteLog('webscan', '获取安全扫描统计结果失败: {}'.format(str(e)))
            return default_result
    
    def send_web_ws(self, get, msg, detail="", repair="", dangerous=0, end=False):
        """
        @name 发送ws信息
        @author lwh<2024-01-23>
        @param msg string 扫描内容
        @param status int 风险情况：1低危，2中危，3高危
        @param repair string 修复方案
        @param end bool 是否结束
        """
        now_time = time.time()
        # 判断间隔时间是否小于100ms
        if (now_time - self.send_time <= 0.1) and end != True and dangerous == 0:
            # 判断是否是每个扫描项开头
            if not msg.startswith("正在"):
                return
        self.send_time = now_time
        if dangerous != 0:
            self.web_scan_num += 1
            # 统计数量
            self.count_risk(dangerous)

        if not self.__check_auth():
            repair = ""
        get._ws.send(public.GetJson({
            "end": end, 
            "ws_callback": get.ws_callback, 
            "dangerous": dangerous, 
            "detail": detail,
            "type": self.scan_type, 
            "info": msg, 
            "repair": repair, 
            "bar": self.bar
        }))
        
    def count_risk(self,dangerous):
        """统计风险等级
        @param dangerous: int 风险等级(0-3)
        """
        if dangerous == 0:
            self.risk_count["warning"] += 1
        elif dangerous == 1:
            self.risk_count["low"] += 1
        elif dangerous == 2:
            self.risk_count["middle"] += 1
        elif dangerous == 3:
            self.risk_count["high"] += 1

    def save_risk_count(self):
        """保存安全扫描统计结果
        @return: bool
        """
        try:
            # 准备保存目录
            save_path = '/www/server/panel/data/safeCloud'
            if not os.path.exists(save_path):
                os.makedirs(save_path)
                
            # 准备保存数据
            result_data = {
                'scan_time': public.format_date(),
                'risk_count': {
                    'warning': self.risk_count.get('warning', 0),      # 告警
                    'low': self.risk_count.get('low', 0),      # 低危
                    'middle': self.risk_count.get('middle', 0), # 中危
                    'high': self.risk_count.get('high', 0)     # 高危
                },
                'web_count': len(self.web_count_list) if hasattr(self, 'web_count_list') else 0  # 扫描网站总数
            }
            
            # 保存到文件
            save_file = os.path.join(save_path, 'web_scan_result.json')
            public.writeFile(save_file, json.dumps(result_data))
            
            # 记录日志
            # public.WriteLog('webscan', '保存安全扫描统计结果成功: {}'.format(str(result_data)))
            return True
            
        except Exception as e:
            # public.WriteLog('webscan', '保存安全扫描统计结果失败: {}'.format(str(e)))
            return False

    def test2(self, get):
        get._ws.send(get.ws_callback)
        get._ws.send("11111")
        return '111'

    def get_waf_status_all(self):
        """
        @name 获取waf状态
        """
        data = {}
        try:
            path = '/www/server/btwaf/site.json'
            res = json.loads(public.readFile(path))

            for site in res:
                data[site] = {}
                data[site]['status'] = True
                if 'open' in res[site]:
                    data[site]['status'] = res[site]['open']
        except:
            pass

        return data

    def short_passwd(self, text):
        """
        @name 密码脱敏
        @author lwh
        """
        text_len = len(text)
        if text_len > 4:
            return text[:2] + "**" + text[text_len - 2:]
        else:
            if 1 < text_len <= 4:
                return text[:1] + "****" + text[text_len - 1]
            else:
                return "******"


if __name__ == "__main__":
    pass
    # obj = main()
    # webinfo = public.M('sites').where('project_type=?', ('PHP',)).select()
    # get = public.dict_obj()
    # for web in webinfo:
    #     get.name = web["name"]
    #     print("正在扫描{}".format(web["name"]))
    #     obj.ScanWeb(get)
    #     obj.WebInfoDisclosure(get)
    #     obj.WebFilePermission(web, get)
    #     obj.WebSSlSecurity(web, get)
