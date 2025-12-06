#!/usr/bin/python
# coding: utf-8
# Date 2022/3/29
# -------------------------------------------------------------------
# 宝塔Linux面板
# -------------------------------------------------------------------
# Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
# -------------------------------------------------------------------
# Author: lkq <lkq@bt.cn>
# 漏洞扫描
# -------------------------------------------------------------------
import json
from projectModel.base import projectBase
import os, re, time
import public
from BTPanel import cache
from projectModel import wordpress_scan
wordpress_site={}

class main(projectBase):
    __cachekey = public.Md5('vulnerability_scanning' + time.strftime('%Y-%m-%d'))
    __config_file = '/www/server/panel/config/vulnerability_scanning.json'
    __auth_msg = public.to_string(
        [27492, 21151, 33021, 20026, 20225, 19994, 29256, 19987, 20139, 21151, 33021, 65292, 35831, 20808, 36141, 20080,
         20225, 19994, 29256])
    __wordpress_scan=wordpress_scan.wordpress_scan()

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

    def write_config(self, config=False):
        '''
        @name 写入配置文件
        @author lkq<2022-3-30>
        @param config 配置文件
        @return
        '''
        if config:
            public.WriteFile(self.__config_file, json.dumps(config))
        else:
            public.WriteFile(self.__config_file, json.dumps(self.getDefaultCms()))

    def get_config(self):
        '''
        @name 获取配置文件
        @author lkq<2022-3-23>
        @return
        '''
        if not os.path.exists(self.__config_file):
            self.write_config()
            return self.getDefaultCms()
        else:
            #  存在配置文件，则读取
            try:
                config = json.loads(public.ReadFile(self.__config_file))
                # 判断config中的cms_name为maccms，determine是否包含thinkphp/library/think/Route.php，如果包含，去掉
                if config['cms_name'] == 'maccms':
                    if 'thinkphp/library/think/Route.php' in config['determine']:
                        config['determine'].remove('thinkphp/library/think/Route.php')
                    self.write_config()
            except:
                self.write_config()
                return self.getDefaultCms()
        # 是否存在缓存
        if not cache.get(self.__cachekey):
            try:
                import requests
                config = requests.get("https://www.bt.cn/api/bt_waf/scanRules").json()
                cache.set(self.__cachekey, '1', 3600)
                self.write_config(config)
            except:
                return self.getDefaultCms()
            return config
        else:
            return config

    def getDefaultCms(self):
        '''
        @name 获取默认CMS
        @author lkq<2022-3-30>
        '''
        result = [
            {"cms_list": [], "dangerous": "2", "cms_name": "迅睿CMS",
             "ps": "迅睿CMS 版本过低",
             "name": "迅睿CMS 版本过低",
             "determine": ["dayrui/My/Config/Version.php"],
             "version": {"type": "file", "file": "dayrui/My/Config/Version.php",
                         "regular": "version.+'(\d+.\d+.\d+)'", "regular_len": 0,
                         "vul_version": "3.2.0~4.5.4", "ver_type": "range"},
             "repair_file": {"type": "file",
                             "file": [{"file": "dayrui/My/Config/Version.php",
                                       "regular": ''' if (preg_match('/(php|jsp|asp|exe|sh|cmd|vb|vbs|phtml)/i', $value)) {'''}]},
             "repair": "参考https://www.xunruicms.com/bug/ \n升级到最新版"
             },
            {"cms_list": [], "dangerous": "3", "cms_name": "pbootcms",
             "ps": "pbootcms 3.0.0~3.0.4 存在多个高危漏洞CNVD-2020-48981,CNVD-2020-48677,CNVD-2020-48469,CNVD-2020-57593,CNVD-2020-56006,CNVD-2021-00794,CNVD-2021-30081,CNVD-2021-30113,CNVD-2021-32163",
             "name": "pbootcms 2.0.0~2.0.8 存在多个高危漏洞CNVD-2020-48981,CNVD-2020-48677,CNVD-2020-48469,CNVD-2020-57593,CNVD-2020-56006,CNVD-2021-00794,CNVD-2021-30081,CNVD-2021-30113,CNVD-2021-32163",
             "determine": ["apps/common/version.php", "core/basic/Config.php",
                           "apps/admin/view/default/js/mylayui.js",
                           "apps/api/controller/ContentController.php"],
             "version": {"type": "file", "file": "apps/common/version.php",
                         "regular": "app_version.+'(\d+.\d+.\d+)'", "regular_len": 0,
                         "vul_version": "3.0.0~3.0.4", "ver_type": "range"},
             "repair_file": {"type": "file",
                             "file": [{"file": "apps/admin/controller/system/ConfigController.php",
                                       "regular": ''' if (preg_match('/(php|jsp|asp|exe|sh|cmd|vb|vbs|phtml)/i', $value)) {'''}]},
             "repair": "参考https://www.pbootcms.com/changelog/ \n升级到最新版"
            },
            {"cms_list": [], "dangerous": "3", "cms_name": "pbootcms",
               "ps": "pbootcms 2.0.0~2.0.8 存在多个高危漏洞CNVD-2020-04104,CNVD-2020-13536,CNVD-2020-24744,CNVD-2020-32198,CNVD-2020-32180,CNVD-2020-32177,CNVD-2020-31495,CNVD-2019-43060",
               "name": "pbootcms 2.0.0~2.0.8 存在多个高危漏洞CNVD-2020-04104,CNVD-2020-13536,CNVD-2020-24744,CNVD-2020-32198,CNVD-2020-32180,CNVD-2020-32177,CNVD-2020-31495,CNVD-2019-43060",
               "determine": ["apps/common/version.php", "core/basic/Config.php",
                             "apps/admin/view/default/js/mylayui.js",
                             "apps/api/controller/ContentController.php"],
               "version": {"type": "file", "file": "apps/common/version.php",
                           "regular": "app_version.+'(\d+.\d+.\d+)'", "regular_len": 0,
                           "vul_version": "2.0.0~2.0.8", "ver_type": "range"},
               "repair_file": {"type": "file",
                               "file": [{"file": "apps/home/controller/ParserController.php",
                                         "regular": ''' if (preg_match('/(\$_GET\[)|(\$_POST\[)|(\$_REQUEST\[)|(\$_COOKIE\[)|(\$_SESSION\[)|(file_put_contents)|(file_get_contents)|(fwrite)|(phpinfo)|(base64)|(`)|(shell_exec)|(eval)|(assert)|(system)|(exec)|(passthru)|(print_r)|(urldecode)|(chr)|(include)|(request)|(__FILE__)|(__DIR__)|(copy)/i', $matches[1][$i]))'''}]},
               "repair": "参考https://www.pbootcms.com/changelog/ \n升级到最新版"
            },
            {"cms_list": [], "dangerous": "3", "cms_name": "pbootcms",
             "ps": "pbootcms 1.3.0~1.3.8 存在多个高危漏洞CNVD-2018-26355,CNVD-2018-24253,CNVD-2018-26938,CNVD-2019-14855,CNVD-2019-27743,CNVD-2020-23841",
             "name": "pbootcms 1.3.0~1.3.8 存在多个高危漏洞CNVD-2018-26355,CNVD-2018-24253,CNVD-2018-26938,CNVD-2019-14855,CNVD-2019-27743,CNVD-2020-23841",
             "determine": ["apps/common/version.php", "core/basic/Config.php",
                           "apps/admin/view/default/js/mylayui.js",
                           "apps/api/controller/ContentController.php"],
             "version": {"type": "file", "file": "apps/common/version.php",
                         "regular": "app_version.+'(\d+.\d+.\d+)'", "regular_len": 0,
                         "vul_version": "1.3.0~1.3.8", "ver_type": "range"},
             "repair_file": {"type": "file",
                             "file": [{"file": "apps/admin/controller/system/ConfigController.php",
                                       "regular": '''$config = preg_replace('/(\'' . $key . '\'([\s]+)?=>([\s]+)?)[\w\'\"\s,]+,/', '${1}\'' . $value . '\',', $config);'''}]},
             "repair": "参考https://www.pbootcms.com/changelog/ \n升级到最新版"
            },
            {"cms_list": [], "dangerous": "3", "cms_name": "pbootcms",
               "ps": "pbootcms 1.2.0~1.2.2 存在多个高危漏洞CNVD-2018-21503,CNVD-2018-19945,CNVD-2018-22854,CNVD-2018-22142,CNVD-2018-26780,CNVD-2018-24845",
               "name": "pbootcms 1.0.1~1.2.2 存在多个高危漏洞CNVD-2018-21503,CNVD-2018-19945,CNVD-2018-22854,CNVD-2018-22142,CNVD-2018-26780,CNVD-2018-24845",
               "determine": ["apps/common/version.php", "core/basic/Config.php",
                             "apps/admin/view/default/js/mylayui.js",
                             "apps/api/controller/ContentController.php"],
               "version": {"type": "file", "file": "apps/common/version.php",
                           "regular": "app_version.+'(\d+.\d+.\d+)'", "regular_len": 0,
                           "vul_version": ["1.2.0", "1.2.1", "1.2.2"], "ver_type": "list"},
               "repair_file": {"type": "file",
                               "file": [{"file": "apps/admin/controller/system/DatabaseController.php",
                                         "regular": '''if ($value && ! preg_match('/(^|[\s]+)(drop|truncate|set)[\s]+/i', $value)) {'''}]},
               "repair": "参考https://www.pbootcms.com/changelog/ \n升级到最新版"
               },
            {"cms_list": [], "dangerous": "3", "cms_name": "pbootcms",
             "ps": "pbootcms 1.1.9 存在SQL注入漏洞CNVD-2018-18069",
             "name": "pbootcms 1.1.9 存在SQL注入漏洞CNVD-2018-18069",
             "determine": ["apps/common/version.php", "core/basic/Config.php",
                           "apps/admin/view/default/js/mylayui.js",
                           "apps/api/controller/ContentController.php"],
             "version": {"type": "file", "file": "apps/common/version.php",
                         "regular": "app_version.+'(\d+.\d+.\d+)'", "regular_len": 0,
                         "vul_version": ["1.1.9"], "ver_type": "list"},
             "repair_file": {"type": "file",
                             "file": [{"file": "core/function/handle.php",
                                       "regular": '''if (Config::get('url_type') == 2 && strrpos($indexfile, 'index.php') !== false)'''}]},
             "repair": "参考https://www.pbootcms.com/changelog/ \n升级到最新版"
             },
            {"cms_list": [], "dangerous": "4", "cms_name": "pbootcms",
             "ps": "pbootcms 1.1.6~1.1.8 存在前台代码执行漏洞、存在多个SQL注入漏洞 CNVD-2018-17412,CNVD-2018-17741,CNVD-2018-17747,CNVD-2018-17750,CNVD-2018-17751,CNVD-2018-17752,CNVD-2018-17753,CNVD-2018-17754",
             "name": "pbootcms 1.1.6~1.1.8  存在前台代码执行漏洞、存在多个SQL注入漏洞 CNVD-2018-17412,CNVD-2018-17741,CNVD-2018-17747,CNVD-2018-17750,CNVD-2018-17751,CNVD-2018-17752,CNVD-2018-17753,CNVD-2018-17754",
             "determine": ["apps/common/version.php", "core/basic/Config.php",
                           "apps/admin/view/default/js/mylayui.js",
                           "apps/api/controller/ContentController.php"],
             "version": {"type": "file", "file": "apps/common/version.php",
                         "regular": "app_version.+'(\d+.\d+.\d+)'", "regular_len": 0,
                         "vul_version": ["1.1.6", "1.1.7", "1.1.8"], "ver_type": "list"},
             "repair_file": {"type": "file",
                             "file": [{"file": "core/function/handle.php",
                                       "regular": '''if (is_array($string)) { // 数组处理
    foreach ($string as $key => $value) {
        $string[$key] = decode_slashes($value);
    }'''}]},
             "repair": "参考https://www.pbootcms.com/changelog/ \n升级到最新版"
             },
            {"cms_list": [], "dangerous": "3", "cms_name": "pbootcms",
             "ps": "pbootcms 1.1.4 存在SQL注入漏洞CNVD-2018-13335,CNVD-2018-13336",
             "name": "pbootcms 1.1.4 存在SQL注入漏洞CNVD-2018-13335,CNVD-2018-13336",
             "determine": ["apps/common/version.php", "core/basic/Config.php",
                           "apps/admin/view/default/js/mylayui.js",
                           "apps/api/controller/ContentController.php"],
             "version": {"type": "file", "file": "apps/common/version.php",
                         "regular": "app_version.+'(\d+.\d+.\d+)'", "regular_len": 0,
                         "vul_version": ["1.1.4"], "ver_type": "list"},
             "repair_file": {"type": "file",
                             "file": [{"file": "core/extend/ueditor/php/controller.php",
                                       "regular": '''if (! ini_get('session.auto_start') && ! isset($_SESSION)'''}]},
             "repair": "参考https://www.pbootcms.com/changelog/ \n升级到最新版"
             },
            {"cms_list": [], "dangerous": "3", "cms_name": "maccms10",
             "ps": "maccms10 <=2022.1000.3025 存在ssrf漏洞、存在XSS漏洞",
             "name": "maccms10 <=2022.1000.3025 存在ssrf漏洞、存在XSS漏洞",
             "determine": ["application/extra/version.php", "application/api/controller/Wechat.php",
                           "application/admin/controller/Upload.php"],
             "version": {"type": "file", "file": "application/extra/version.php",
                         "regular": "code.+'(\d+.\d+.\d+)'", "regular_len": 0,
                         "vul_version": ["2022.1000.3025", "2022.1000.3005", "2022.1000.3024", "2022.1000.3020",
                                         "2022.1000.3023",
                                         "2022.1000.3002", "2022.1000.1099", "2021.1000.1081"], "ver_type": "list"},
             "repair_file": {"type": "file",
                             "file": [{"file": "application/common/model/Actor.php",
                                       "regular": '''$data[$filter_field] = mac_filter_xss($data[$filter_field]);'''}]},
             "repair": "参考https://github.com/magicblack/maccms10/releases \n升级到最新版"},
            {"cms_list": [], "dangerous": "3", "cms_name": "maccms10",
             "ps": "maccms10 <=2022.1000.3024 存在前台任意用户登陆、后台会话验证绕过、后台任意文件写入、任意文件删除漏洞",
             "name": "maccms10 <=2022.1000.3024 存在前台任意用户登陆、后台会话验证绕过、后台任意文件写入、任意文件删除漏洞",
             "determine": ["application/extra/version.php", "application/api/controller/Wechat.php",
                           "application/admin/controller/Upload.php"],
             "version": {"type": "file", "file": "application/extra/version.php",
                         "regular": "code.+'(\d+.\d+.\d+)'", "regular_len": 0,
                         "vul_version": ["2022.1000.3005", "2022.1000.3024", "2022.1000.3020", 
                                        "2022.1000.3023","2022.1000.3002", "2022.1000.1099", 
                                        "2021.1000.1081"], 
                         "ver_type": "list"},
             "repair_file": {"type": "file",
                             "file": [{"file": "application/common/model/Annex.php", "regular": '''if (stripos($v['annex_file'], '../') !== false)'''}]},
             "repair": "参考https://github.com/magicblack/maccms10/releases \n升级到最新版"
             },
            {"cms_list": [], "dangerous": "3", "cms_name": "eyoucms",
             "ps": "eyoucms 1.5.5~1.5.7 存在多个安全漏洞",
             "name": "eyoucms 1.5.1~1.5.4 存在多个安全漏洞",
             "determine": ["data/conf/version.txt", "application/api/controller/Uploadify.php",
                           "application/extra/extra_cache_key.php",
                           "application/admin/controller/Uploadify.php"],
             "version": {"type": "file", "file": "data/conf/version.txt",
                         "regular": "(\d+.\d+.\d+)", "regular_len": 0,
                         "vul_version": "1.5.5~1.5.7", "ver_type": "range"},
             "repair_file": {"type": "file",
                             "file": [{"file": "application/common.php",
                                       "regular": '''$login_errnum_key = 'adminlogin_'.md5('login_errnum_'.$admin_info['user_name']);'''}]},
             "repair": "参考https://www.eyoucms.com/rizhi/ \n升级eyoucms到最新版"
             },
            {"cms_list": [], "dangerous": "4", "cms_name": "eyoucms",
             "ps": "eyoucms 1.5.1~1.5.4 存在多个高危安全漏洞,CNVD-2021-82431,CNVD-2021-82429,CNVD-2021-72772,CNVD-2021-51838,CNVD-2021-51836,CNVD-2021-41520,CNVD-2021-24745,,CNVD-2021-26007,CNVD-2021-26099,CNVD-2021-41520",
             "name": "eyoucms 1.5.1~1.5.4 存在多个高危安全漏洞,CNVD-2021-82431,CNVD-2021-82429,CNVD-2021-72772,CNVD-2021-51838,CNVD-2021-51836,CNVD-2021-41520,CNVD-2021-24745,,CNVD-2021-26007,CNVD-2021-26099,CNVD-2021-41520",
             "determine": ["data/conf/version.txt", "application/api/controller/Uploadify.php",
                           "application/extra/extra_cache_key.php",
                           "application/admin/controller/Uploadify.php"],
             "version": {"type": "file", "file": "data/conf/version.txt",
                         "regular": "(\d+.\d+.\d+)", "regular_len": 0,
                         "vul_version": "1.5.1~1.5.4", "ver_type": "range"},
             "repair_file": {"type": "file",
                             "file": [{"file": "application/common.php",
                                       "regular": '''$citysite_db->where(['domain'=>$s_arr[0]])->cache(true, EYOUCMS_CACHE_TIME, 'citysite')->count()'''}]},
             "repair": "参考https://www.eyoucms.com/rizhi/ \n升级eyoucms到最新版"
             },
            {"cms_list": [], "dangerous": "4", "cms_name": "eyoucms",
             "ps": "eyoucms 1.4.7 存在多个高危安全漏洞,CNVD-2020-46317,CNVD-2020-49065,CNVD-2020-44394,CNVD-2020-44392,CNVD-2020-44391,CNVD-2020-47671,CNVD-2020-50721",
             "name": "eyoucms 1.4.7 存在多个高危安全漏洞,CNVD-2020-46317,CNVD-2020-49065,CNVD-2020-44394,CNVD-2020-44392,CNVD-2020-44391,CNVD-2020-47671,CNVD-2020-50721",
             "determine": ["data/conf/version.txt", "application/api/controller/Uploadify.php",
                           "application/extra/extra_cache_key.php",
                           "application/admin/controller/Uploadify.php"],
             "version": {"type": "file", "file": "data/conf/version.txt",
                         "regular": "(\d+.\d+.\d+)", "regular_len": 0,
                         "vul_version": "1.4.7~1.4.7", "ver_type": "range"},
             "repair_file": {"type": "file",
                             "file": [{"file": "application/common.php",
                                       "regular": '''function GetTagIndexRanking($limit = 5, $field = 'id, tag')'''}]},
             "repair": "参考https://www.eyoucms.com/rizhi/ \n升级eyoucms到最新版"
             },
            {"cms_list": [], "dangerous": "4", "cms_name": "eyoucms",
             "ps": "eyoucms 1.4.6 存在多个高危安全漏洞,CNVD-2020-44116,CNVD-2020-32622,CNVD-2020-28132,CNVD-2020-28083,CNVD-2020-28064,CNVD-2020-33104",
             "name": "eyoucms 1.4.6 存在多个高危安全漏洞,CNVD-2020-44116,CNVD-2020-32622,CNVD-2020-28132,CNVD-2020-28083,CNVD-2020-28064,CNVD-2020-33104",
             "determine": ["data/conf/version.txt", "application/api/controller/Uploadify.php",
                           "application/extra/extra_cache_key.php",
                           "application/admin/controller/Uploadify.php"],
             "version": {"type": "file", "file": "data/conf/version.txt",
                         "regular": "(\d+.\d+.\d+)", "regular_len": 0,
                         "vul_version": "1.4.6~1.4.6", "ver_type": "range"},
             "repair_file": {"type": "file",
                             "file": [{"file": "application/common.php",
                                       "regular": '''preg_replace('#^(/[/\w]+)?(/uploads/|/public/static/)#i'''}]},
             "repair": "参考https://www.eyoucms.com/rizhi/ \n升级eyoucms到最新版"
             }, 
            {"cms_list": [], "dangerous": "4", "cms_name": "eyoucms",
               "ps": "eyoucms 1.3.9~1.4.4 存在多个安全漏洞CNVD-2020-02271,CNVD-2020-02824,CNVD-2020-18735,CNVD-2020-18677,CNVD-2020-23229,CNVD-2020-23805,CNVD-2020-23820",
               "name": "eyoucms 1.3.9~1.4.4 存在多个安全漏洞CNVD-2020-02271,CNVD-2020-02824,CNVD-2020-18735,CNVD-2020-18677,CNVD-2020-23229,CNVD-2020-23805,CNVD-2020-23820",
               "determine": ["data/conf/version.txt", "application/api/controller/Uploadify.php",
                             "application/extra/extra_cache_key.php",
                             "application/admin/controller/Uploadify.php"],
               "version": {"type": "file", "file": "data/conf/version.txt",
                           "regular": "(\d+.\d+.\d+)", "regular_len": 0,
                           "vul_version": "1.3.9~1.4.4", "ver_type": "range"},
               "repair_file": {"type": "file",
                               "file": [{"file": "application/common.php",
                                         "regular": '''$TimingTaskRow = model('Weapp')->getWeappList('TimingTask');'''}]},
               "repair": "参考https://www.eyoucms.com/rizhi/ \n升级eyoucms到最新版"
               },
            {"cms_list": [], "dangerous": "4", "cms_name": "eyoucms", "ps": "eyoucms 1.4.1 存在命令执行漏洞",
             "name": "eyoucms 1.4.1 存在命令执行漏洞",
             "determine": ["data/conf/version.txt", "application/api/controller/Uploadify.php",
                           "application/extra/extra_cache_key.php",
                           "application/admin/controller/Uploadify.php"],
             "version": {"type": "file", "file": "data/conf/version.txt",
                         "regular": "(\d+.\d+.\d+)", "regular_len": 0,
                         "vul_version": "1.4.1~1.4.1", "ver_type": "range"},
             "repair_file": {"type": "file",
                             "file": [{"file": "application/route.php",
                                       "regular": '''$weapp_route_file = 'plugins/route.php';'''}]},
             "repair": "参考https://www.eyoucms.com/rizhi/ \n升级eyoucms到最新版"
             },
            {"cms_list": [], "dangerous": "3", "cms_name": "eyoucms",
             "ps": "eyoucms<=1.3.8 存在SQL注入、存在插件上传漏洞",
             "name": "eyoucms<=1.3.8 存在SQL注入、存在插件上传漏洞",
             "determine": ["data/conf/version.txt", "application/api/controller/Uploadify.php",
                           "application/extra/extra_cache_key.php",
                           "application/admin/controller/Uploadify.php"],
             "version": {"type": "file", "file": "data/conf/version.txt",
                         "regular": "(\d+.\d+.\d+)", "regular_len": 0,
                         "vul_version": "1.0.0~1.3.8", "ver_type": "range"},
             "repair_file": {"type": "file",
                             "file": [{"file": "core/library/think/template/taglib/Eyou.php",
                                       "regular": '''$notypeid  = !empty($tag['notypeid']) ? $tag['notypeid'] : '';'''}]},
             "repair": "参考https://www.eyoucms.com/rizhi/ \n升级eyoucms到最新版"
             },
            {"cms_list": [], "dangerous": "3", "cms_name": "eyoucms", "ps": "eyoucms<=1.3.4 存在后台文件上传漏洞",
             "name": "eyoucms<=1.3.4 存在后台文件上传漏洞",
             "determine": ["data/conf/version.txt", "application/api/controller/Uploadify.php",
                           "application/extra/extra_cache_key.php",
                           "application/admin/controller/Uploadify.php"],
             "version": {"type": "file", "file": "data/conf/version.txt",
                         "regular": "(\d+.\d+.\d+)", "regular_len": 0,
                         "vul_version": "1.0.0~1.3.4", "ver_type": "range"},
             "repair_file": {"type": "file",
                             "file": [{"file": "application/common.php",
                                       "regular": '''include_once EXTEND_PATH."function.php";'''}]},
             "repair": "参考https://www.eyoucms.com/rizhi/ \n升级eyoucms到最新版"
             },
            {"cms_list": [], "dangerous": "3", "cms_name": "eyoucms", "ps": "eyoucms 1.0 存在任意文件上传漏洞",
             "name": "eyoucms 1.0 存在任意文件上传漏洞",
             "determine": ["data/conf/version.txt", "application/api/controller/Uploadify.php",
                           "application/extra/extra_cache_key.php",
                           "application/admin/controller/Uploadify.php"],
             "version": {"type": "file", "file": "data/conf/version.txt",
                         "regular": "(\d+.\d+.\d+)", "regular_len": 0,
                         "vul_version": "1.0.0~1.1.0", "ver_type": "range"},
             "repair_file": {"type": "file",
                             "file": [{"file": "application/api/controller/Uploadify.php",
                                       "regular": '''目前没用到这个api接口'''}]},
             "repair": "参考https://www.eyoucms.com/rizhi/ \n升级eyoucms到最新版"
             },
            {"cms_list": [], "dangerous": "3", "cms_name": "eyoucms", "ps": "eyoucms 1.6.1 存在反序列化漏洞",
             "name": "eyoucms 1.6.1 存在反序列化漏洞",
             "determine": ["data/conf/version.txt", "application/api/controller/Uploadify.php",
                           "application/extra/extra_cache_key.php",
                           "application/admin/controller/Uploadify.php"],
             "version": {"type": "file", "file": "data/conf/version.txt",
                         "regular": "(\d+.\d+.\d+)", "regular_len": 0,
                         "vul_version": "1.6.1~1.6.1", "ver_type": "range"},
             "repair_file": {"type": "file",
                             "file": []},
             "repair": "参考https://www.eyoucms.com/rizhi/ \n升级eyoucms到最新版"
             },
            {"cms_list": [], "dangerous": "2", "cms_name": "海洋CMS", "ps": "海洋CMS 版本过低",
             "name": "海洋CMS 版本过低",
             "determine": ["data/admin/ver.txt", "include/common.php", "include/main.class.php",
                           "detail/index.php"],
             "version": {"type": "file", "file": "data/admin/ver.txt",
                         "regular": "(\d+.\d+?|\d+)", "regular_len": 0,
                         "vul_version": ["6.28", "6.54", "7.2", "8.4", "8.5", "8.6", "8.7", "8.8", "8.9", "9", "9.1",
                                         "9.2", "9.3", "9.4", "9.5", "9.6", "9.7", "9.8", "9.9", "9.91", "9.92", "9.93",
                                         "9.94", "9.96", "9.97", "9.98", "9.99", "10", "10.1", "10.2", "10.3", "10.4",
                                         "10.5", "10.6", "10.7", "10.8", "10.9", "11", "11.1", "11.2", "11.3", "11.4",
                                         "11.5"], "ver_type": "list"},
             "repair_file": {"type": "version", "file": []},
             "repair": "建议升级到海洋CMS 最新版 https://www.seacms.net/p-549"
             },
            {"cms_list": [], "dangerous": "3", "cms_name": "海洋CMS", "ps": "海洋CMS <=9.95存在前台RCE",
             "name": "海洋CMS <=9.95存在前台RCE",
             "determine": ["data/admin/ver.txt", "include/common.php", "include/main.class.php",
                           "detail/index.php"],
             "version": {"type": "file", "file": "data/admin/ver.txt",
                         "regular": "(\d+.\d+?|\d+)", "regular_len": 0,
                         "vul_version": ["6.28", "6.45", "6.54", "6.55", "6.61", "7.2", "8.4", "8.5", "8.6", "8.7",
                                         "8.8", "8.9", "9", "9.1",
                                         "9.2", "9.3", "9.4", "9.5", "9.6", "9.7", "9.8", "9.9", "9.91", "9.92", "9.93",
                                         "9.94"], "ver_type": "list"},
             "repair_file": {"type": "file",
                             "file": [{"file": "include/common.php",
                                       "regular": ''''$jpurl='//'.$_SERVER['SERVER_NAME']'''}]},
             "repair": "建议升级到海洋CMS最新版 https://www.seacms.net/p-549"
             },
            {"cms_list": [], "dangerous": "3", "cms_name": "海洋CMS", "ps": "海洋CMS 10.1后台存在代码执行漏洞",
             "name": "海洋CMS 10.1存在多处高危后台代码执行漏洞",
             "determine": ["data/admin/ver.txt", "include/common.php", "include/main.class.php",
                           "detail/index.php"],
             "version": {"type": "file", "file": "data/admin/ver.txt",
                         "regular": "(\d+.\d+?|\d+)", "regular_len": 0,
                         "vul_version": ["10.1"], "ver_type": "list"},
             "repair_file": {"type": "file",
                             "file": []},
             "repair": "建议升级到海洋CMS最新版 https://www.seacms.net/p-549"
             },
            {"cms_list": [], "dangerous": "3", "cms_name": "ThinkCMF", "ps": "ThinkCMF CVE-2019-6713漏洞",
             "name": "ThinkCMF CVE-2019-6713",
             "determine": ["public/index.php", "app/admin/hooks.php", "app/admin/controller/NavMenuController.php",
                           "simplewind/cmf/hooks.php"],
             "version": {"type": "file", "file": "public/index.php",
                         "regular": "THINKCMF_VERSION.+'(\d+.\d+.\d+)'", "regular_len": 0,
                         "vul_version": ["5.0.190111", "5.0.181231", "5.0.181212", "5.0.180901", "5.0.180626",
                                         "5.0.180525", "5.0.180508"], "ver_type": "list"},
             "repair_file": {"type": "file",
                             "file": [{"file": "app/admin/validate/RouteValidate.php",
                                       "regular": '''protected function checkUrl($value, $rule, $data)'''}]},
             "repair": "1.修改代码 https://github.com/thinkcmf/thinkcmf/commit/217b6f8ad77a2917634bb9dd9c1f4ccf2c4c2930\n"
                       "2.升级到最新版 https://github.com/thinkcmf/thinkcmf/releases/tag/5.0.190419"
             },
            {"cms_list": [], "dangerous": "3", "cms_name": "ThinkCMF", "ps": "ThinkCMF templateFile远程代码执行漏洞",
             "name": "ThinkCMF templateFile远程代码执行漏洞",
             "determine": ["simplewind/Core/ThinkPHP.php", "index.php",
                           "data/conf/db.php", "application/Admin/Controller/NavcatController.class.php",
                           "application/Comment/Controller/WidgetController.class.php"],
             "version": {"type": "file", "file": "index.php",
                         "regular": "THINKCMF_VERSION.+(\d+.\d+.\d+)'", "regular_len": 0,
                         "vul_version": "1.6.0~2.2.2", "ver_type": "range"},
             "repair_file": {"type": "file",
                             "file": [{"file": "application/Comment/Controller/WidgetController.class.php",
                                       "regular": '''protected function display('''}]},
             "repair": "修复建议如下\n"
                       "1.修改代码 https://gitee.com/thinkcmf/ThinkCMFX/commit/559b868283bc491cf858d2f85bcd5b6cfa425d63\n"
                       "2.升级到最新版 https://gitee.com/thinkcmf/ThinkCMFX/releases/X2.2.4"
             },
            {"cms_list": [], "dangerous": "3", "cms_name": "zfaka", "ps": "zfaka存在SQL注入漏洞",
             "name": "zfaka存在SQL注入漏洞",
             "determine": ["application/init.php", "application/function/F_Network.php",
                           "application/controllers/Error.php", "application/modules/Admin/controllers/Profiles.php"],
             "version": {"type": "file", "file": "application/init.php",
                         "regular": "VERSION.+'(\d+.\d+.\d+)'", "regular_len": 0,
                         "vul_version": "1.0.0~1.4.4", "ver_type": "range"},
             "repair_file": {"type": "file", "file": [{"file": "application/function/F_Network.php",
                                                       "regular": '''if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4'''}]},
             "repair": "修复建议:\n"
                       "1.修改代码https://github.com/zlkbdotnet/zfaka/commit/f0f504528347a758fc34fb4b8dbc69377b099b8e?branch=f0f504528347a758fc34fb4b8dbc69377b099b8e&diff=split\n"
                       "2.升级到1.4.5"
             },
            {"cms_list": [], "dangerous": "3", "cms_name": "dedecms", "ps": "dedecms 20210719安全更新",
             "name": "dedecms 20210719安全更新",
             "determine": ["data/admin/ver.txt", "data/common.inc.php",
                           "dede/shops_operations_userinfo.php", "member/edit_space_info.php"],
             "version": {"type": "file", "file": "data/admin/ver.txt",
                         "regular": "(\d+)", "regular_len": 0,
                         "vul_version": ["20180109"], "ver_type": "list"},
             "repair_file": {"type": "file", "file": [{"file": "include/dedemodule.class.php",
                                                       "regular": '''if(preg_match("#[^a-z]+(eval|assert)[\s]*[(]#i"'''}]},
             "repair": "参考https://www.dedecms.com/package.html?t=1626652800\n 升级到最新版本"
             },
            {"cms_list": [], "dangerous": "3", "cms_name": "dedecms", "ps": "dedecms 20220125安全更新",
             "name": "dedecms 20220125安全更新",
             "determine": ["data/admin/ver.txt", "data/common.inc.php",
                           "dede/shops_operations_userinfo.php", "member/edit_space_info.php"],
             "version": {"type": "file", "file": "data/admin/ver.txt",
                         "regular": "(\d+)", "regular_len": 0,
                         "vul_version": ["20180109", "20220325", "20210201", "20210806"], "ver_type": "list"},
             "repair_file": {"type": "file", "file": [{"file": "include/downmix.inc.php",
                                                       "regular": '''上海卓卓网络科技有限公司'''}]},
             "repair": "参考https://www.dedecms.com/package.html?t=1643068800\n 升级到最新版本"
             },
            {"cms_list": [], "dangerous": "3", "cms_name": "dedecms", "ps": "dedecms 20220218安全更新",
             "name": "dedecms 20220218安全更新",
             "determine": ["data/admin/ver.txt", "data/common.inc.php",
                           "dede/shops_operations_userinfo.php", "member/edit_space_info.php"],
             "version": {"type": "file", "file": "data/admin/ver.txt",
                         "regular": "(\d+)", "regular_len": 0,
                         "vul_version": ["20180109", "20220325", "20210201", "20210806"], "ver_type": "list"},
             "repair_file": {"type": "file", "file": [{"file": "dede/file_manage_control.php",
                                                       "regular": '''phpinfo,eval,assert,exec,passthru,shell_exec,system,proc_open,popen'''}]},
             "repair": "参考https://www.dedecms.com/package.html?t=1645142400\n 升级到最新版本"
             }, 
            {"cms_list": [], "dangerous": "3", "cms_name": "dedecms", "ps": "dedecms 20220310安全更新",
               "name": "dedecms 20220310安全更新",
               "determine": ["data/admin/ver.txt", "data/common.inc.php",
                             "dede/shops_operations_userinfo.php", "member/edit_space_info.php"],
               "version": {"type": "file", "file": "data/admin/ver.txt",
                           "regular": "(\d+)", "regular_len": 0,
                           "vul_version": ["20180109", "20220325", "20210201", "20210806"], "ver_type": "list"},
               "repair_file": {"type": "file", "file": [{"file": "dede/file_manage_control.php",
                                                         "regular": '''phpinfo,eval,assert,exec,passthru,shell_exec,system,proc_open,popen'''}]},
               "repair": "参考https://www.dedecms.com/package.html?t=1646870400\n 升级到最新版本"
               },
            {"cms_list": [], "dangerous": "3", "cms_name": "dedecms", "ps": "dedecms 20220325安全更新",
             "name": "dedecms 20220325安全更新",
             "determine": ["data/admin/ver.txt", "data/common.inc.php",
                           "dede/shops_operations_userinfo.php", "member/edit_space_info.php"],
             "version": {"type": "file", "file": "data/admin/ver.txt",
                         "regular": "(\d+)", "regular_len": 0,
                         "vul_version": ["20180109", "20220325", "20210201", "20210806"], "ver_type": "list"},
             "repair_file": {"type": "file", "file": [{"file": "plus/mytag_js.php",
                                                       "regular": '''phpinfo,eval,assert,exec,passthru,shell_exec,system,proc_open,popen'''}]},
             "repair": "参考https://www.dedecms.com/package.html?t=1648166400\n 升级到最新版本"
             },
            {"cms_list": [], "dangerous": "2", "cms_name": "dedecms", "ps": "dedecms 已开启会员注册功能",
             "name": "dedecms 已开启会员注册功能",
             "determine": ["data/admin/ver.txt", "data/common.inc.php",
                           "dede/shops_operations_userinfo.php", "member/edit_space_info.php"],
             "version": {"type": "file", "file": "data/admin/ver.txt",
                         "regular": "(\d+)", "regular_len": 0,
                         "vul_version": ["20180109", "20220325", "20210201", "20210806"], "ver_type": "list"},
             "repair_file": {"type": "phpshell", "file": [{"file": "member/get_user_cfg_mb_open.php",
                                                           "phptext": '''<?php require_once(dirname(__FILE__).'/../include/common.inc.php');echo 'start'.$cfg_mb_open.'end';?>''',
                                                           "regular": '''start(\w)end''', "reulst_type": "str",
                                                           "result": "startYend"}]},
             "repair": "建议关闭后台会员注册功能"
             }, {"cms_list": [], "dangerous": "3", "cms_name": "MetInfo", "ps": "MetInfo 7.5.0存在SQL注入漏洞",
               "name": "MetInfo7.5.0存在SQL注入漏洞",
               "determine": ["cache/config/config_metinfo.php", "app/system/entrance.php",
                             "app/system/databack/admin/index.class.php", "cache/config/app_config_metinfo.php"],
               "version": {"type": "file", "file": "cache/config/config_metinfo.php",
                           "regular": "value.+'(\d+.\d+.\d+)'", "vul_version": "7.5.0~7.5.0", "ver_type": "range"},
               "repair_file": {"type": "version", "file": []},
               "repair": "参考https://www.metinfo.cn/log/ 建议升级到最新版本"
               },
            {"cms_list": [], "dangerous": "3", "cms_name": "MetInfo", "ps": "MetInfo 7.3.0存在SQL注入漏洞、XSS漏洞",
             "name": "MetInfo 7.3.0存在SQL注入漏洞、XSS漏洞",
             "determine": ["app/system/entrance.php", "app/system/admin/admin/index.class.php",
                           "app/system/admin/admin/templates/admin_add.php"],
             "version": {"type": "file", "file": "app/system/entrance.php",
                         "regular": "SYS_VER.+'(\d+.\d+.\d+)'", "vul_version": "7.3.0~7.3.0", "ver_type": "range"},
             "repair_file": {"type": "version", "file": []},
             "repair": "参考https://www.metinfo.cn/log/ 建议升级到最新版本"
             },
            {"cms_list": [], "dangerous": "3", "cms_name": "MetInfo", "ps": "MetInfo 7.2.0存在SQL注入漏洞、XSS漏洞",
             "name": "MetInfo 7.2.0存在SQL注入漏洞、XSS漏洞",
             "determine": ["app/system/entrance.php", "app/system/admin/admin/index.class.php",
                           "app/system/admin/admin/templates/admin_add.php"],
             "version": {"type": "file", "file": "app/system/entrance.php",
                         "regular": "SYS_VER.+'(\d+.\d+.\d+)'", "vul_version": "7.2.0~7.2.0", "ver_type": "range"},
             "repair_file": {"type": "version", "file": []},
             "repair": "参考https://www.metinfo.cn/log/ 建议升级到最新版本"
             },
            {"cms_list": [], "dangerous": "3", "cms_name": "MetInfo",
             "ps": "MetInfo 7.1.0存在文件上传漏洞、SQL注入漏洞、XSS漏洞",
             "name": "MetInfo 7.1.0存在文件上传漏洞、SQL注入漏洞、XSS漏洞",
             "determine": ["app/system/entrance.php", "app/system/admin/admin/index.class.php",
                           "app/system/admin/admin/templates/admin_add.php"],
             "version": {"type": "file", "file": "app/system/entrance.php",
                         "regular": "SYS_VER.+'(\d+.\d+.\d+)'", "vul_version": "7.1.0~7.1.0", "ver_type": "range"},
             "repair_file": {"type": "version", "file": []},
             "repair": "参考https://www.metinfo.cn/log/ 建议升级到最新版本"
             },
            {"cms_list": [], "dangerous": "3", "cms_name": "MetInfo", "ps": "MetInfo 7.0.0 存在SQL注入漏洞",
             "name": "MetInfo7.0.0存在SQL注入漏洞",
             "determine": ["app/system/entrance.php", "app/system/admin/admin/index.class.php",
                           "app/system/admin/admin/templates/admin_add.php"],
             "version": {"type": "file", "file": "app/system/entrance.php",
                         "regular": "SYS_VER.+'(\d+.\d+.\d+)'", "vul_version": "7.0.0~7.0.0", "ver_type": "range"},
             "repair_file": {"type": "version", "file": []},
             "repair": "参考https://www.metinfo.cn/log/ 建议升级到最新版本"
             },
            {"cms_list": [], "dangerous": "3", "cms_name": "MetInfo", "ps": "MetInfo 6.1.2存在SQL注入漏洞",
             "name": "MetInfo 6.1.2存在SQL注入漏洞",
             "determine": ["app/system/entrance.php", "app/system/admin/admin/templates/admin_add.php"],
             "version": {"type": "file", "file": "app/system/entrance.php",
                         "regular": "SYS_VER.+'(\d+.\d+.\d+)'", "vul_version": "6.1.2~6.1.2", "ver_type": "range"},
             "repair_file": {"type": "version", "file": []},
             "repair": "参考https://www.metinfo.cn/log/ 建议升级到最新版本"
             },
            {"cms_list": [], "dangerous": "3", "cms_name": "MetInfo",
             "ps": "MetInfo 6.1.1 存在已知后台权限可以获取webshell漏洞",
             "name": "MetInfo 6.1.1 存在已知后台权限可以获取webshell漏洞",
             "determine": ["app/system/entrance.php", "app/system/admin/admin/templates/admin_add.php"],
             "version": {"type": "file", "file": "app/system/entrance.php",
                         "regular": "SYS_VER.+'(\d+.\d+.\d+)'", "vul_version": "6.1.1~6.1.1", "ver_type": "range"},
             "repair_file": {"type": "version", "file": []},
             "repair": "参考https://www.metinfo.cn/log/ 建议升级到最新版本"
             },
            {"cms_list": [], "dangerous": "2", "cms_name": "emlog", "ps": "emlog版本太低建议升级到Pro版本",
             "name": "emlog版本太低建议升级到Pro版本",
             "determine": ["include/lib/option.php", "admin/views/template_install.php",
                           "include/lib/checkcode.php", "include/controller/author_controller.php"],
             "version": {"type": "file", "file": "include/lib/option.php",
                         "regular": "EMLOG_VERSION.+'(\d+.\d+.\d+)'", "vul_version": "5.3.1~6.0.0",
                         "ver_type": "range"},
             "repair_file": {"type": "version", "file": []},
             "repair": "参考https://www.emlog.net/docs/#/531toPro 建议升级到最新版本"
             },
            {"cms_list": [], "dangerous": "1", "cms_name": "帝国CMS", "ps": "EmpireCMs7.0后台XSS漏洞",
             "name": "EmpireCMs7.0后台XSS漏洞",
             "determine": ["e/class/EmpireCMS_version.php", "e/search/index.php",
                           "e/member/EditInfo/index.php", "e/ViewImg/index.html"],
             "version": {"type": "file", "file": "e/class/EmpireCMS_version.php",
                         "regular": "EmpireCMS_VERSION.+'(\d+.\d+)'", "vul_version": "7.0~7.0", "ver_type": "range"},
             "repair_file": {"type": "version", "file": []},
             "repair": "漏洞修复可参考/e/admin/openpage/AdminPage.php?ehash_f9Tj7=ZMhwowHjtSwqyRuiOylK&mainfile=javascript:alert(1)"
             },
            {"cms_list": [], "dangerous": "2", "cms_name": "帝国CMS", "ps": "EmpireCMs6.0~7.5 后台代码执行",
             "name": "EmpireCMs6.0~7.5 后台代码执行",
             "determine": ["e/class/EmpireCMS_version.php", "e/search/index.php",
                           "e/member/EditInfo/index.php", "e/ViewImg/index.html"],
             "version": {"type": "file", "file": "e/class/EmpireCMS_version.php",
                         "regular": "EmpireCMS_VERSION.+'(\d+.\d+)'", "vul_version": "6.0~7.5", "ver_type": "range"},
             "repair_file": {"type": "version", "file": []},
             "repair": "参考https://blog.csdn.net/ws13129/article/details/90071260 建议升级到最新版本"
             },
            {"cms_list": [], "dangerous": "2", "cms_name": "帝国CMS", "ps": "EmpireCMs6.0~7.5 后台导入模型代码执行",
             "name": "EmpireCMs6.0~7.5 后台导入模型代码执行",
             "determine": ["e/class/EmpireCMS_version.php", "e/search/index.php",
                           "e/member/EditInfo/index.php", "e/ViewImg/index.html"],
             "version": {"type": "file", "file": "e/class/EmpireCMS_version.php",
                         "regular": "EmpireCMS_VERSION.+'(\d+.\d+)'", "vul_version": "6.0~7.5", "ver_type": "range"},
             "repair_file": {"type": "version", "file": []},
             "repair": "参考https://blog.csdn.net/ws13129/article/details/90071260 建议升级到最新版本"
             },
            {"cms_list": [], "dangerous": "2", "cms_name": "discuz", "ps": "Discuz utility组件对外访问",
             "name": "Discuz utility组件对外访问",
             "determine": ["uc_client/client.php", "uc_server/lib/uccode.class.php",
                           "uc_server/model/version.php", "source/discuz_version.php"],
             "version": {"type": "single_file", "file": "utility/convert/index.php",
                         "regular": "DISCUZ_RELEASE.+'(\d+)'", "regular_len": 0,
                         "vul_version": ["1"], "ver_type": "list"},
             "repair_file": {"type": "single_file", "file": [{"file": "utility/convert/index.php",
                                                              "regular": '''$source = getgpc('source') ? getgpc('source') : getgpc('s');'''}]},
             "repair": "修复漏洞参考删除utility目录"
             },
            {"cms_list": [], "dangerous": "2", "cms_name": "discuz",
             "ps": "Discuz邮件认证入口CSRF以及时间限制可绕过漏洞",
             "name": "Discuz邮件认证入口CSRF以及时间限制可绕过漏洞",
             "determine": ["uc_client/client.php", "uc_server/lib/uccode.class.php",
                           "uc_server/model/version.php", "source/discuz_version.php"],
             "version": {"type": "file", "file": "source/discuz_version.php",
                         "regular": "DISCUZ_RELEASE.+'(\d+)'", "regular_len": 0,
                         "vul_version": ["20210816",
                                         "20210630", "20210520", "20210320", "20210119", "20200818", "20191201",
                                         "20190917"], "ver_type": "list"},
             "repair_file": {"type": "file", "file": [{"file": "source/admincp/admincp_setting.php",
                                                       "regular": '''showsetting('setting_permissions_mailinterval', 'settingnew[mailinterval]', $setting['mailinterval'], 'text');'''}]},
             "repair": "修复漏洞参考https://gitee.com/Discuz/DiscuzX/pulls/1276/commits"
             },
            {"cms_list": [], "dangerous": "3", "cms_name": "discuz", "ps": "Discuz 报错注入SQL",
             "name": "Discuz 报错注入SQL",
             "determine": ["uc_client/client.php", "uc_server/lib/uccode.class.php",
                           "uc_server/model/version.php", "source/discuz_version.php"],
             "version": {"type": "file", "file": "source/discuz_version.php",
                         "regular": "DISCUZ_RELEASE.+'(\d+)'", "regular_len": 0,
                         "vul_version": ["20211124", "20211022", "20210926", "20210917", "20210816",
                                         "20210630", "20210520", "20210320", "20210119", "20200818", "20191201",
                                         "20190917"], "ver_type": "list"},
             "repair_file": {"type": "file", "file": [
                 {"file": "api/uc.php",
                  "regular": '''if($len > 22 || $len < 3 || preg_match("/\s+|^c:\\con\\con|[%,\*\"\s\<\>\&\(\)']/is", $get['newusername']))'''}]},
             "repair": "修复漏洞参考https://gitee.com/Discuz/DiscuzX/pulls/1349"
             }, {
                "cms_list": [], "dangerous": "3", "cms_name": "discuz", "ps": "Discuz备份恢复功能执行任意SQL漏洞",
                "name": "Discuz备份恢复功能执行任意SQL漏洞",
                "determine": ["uc_client/client.php", "uc_server/lib/uccode.class.php", "uc_server/model/version.php",
                              "source/discuz_version.php"],
                "version": {"type": "file", "file": "source/discuz_version.php", "regular": "DISCUZ_RELEASE.+'(\d+)'",
                            "regular_len": 0,
                            "vul_version": ["20211231", "20211124", "20211022", "20210926", "20210917", "20210816",
                                            "20210630", "20210520", "20210320", "20210119", "20200818", "20191201",
                                            "20190917"], "ver_type": "list"},
                "repair_file": {"type": "file", "file": [
                    {"file": "api/db/dbbak.php",
                     "regular": '''if(!preg_match('/^backup_(\d+)_\w+$/', $get['sqlpath']) || !preg_match('/^\d+_\w+\-(\d+).sql$/', $get['dumpfile']))'''}]},
                "repair": "修复漏洞参考https://gitee.com/Discuz/DiscuzX/releases/v3.4-20220131"},
            {"cms_list": [], "dangerous": "4", "cms_name": "Thinkphp", "ps": "thinkphp5.0.X漏洞",
             "name": "Thinkphp5.X代码执行",
             "determine": ["thinkphp/base.php", "thinkphp/library/think/App.php", "thinkphp/library/think/Request.php"],
             "version": {"type": "file", "file": "thinkphp/base.php", "regular": "THINK_VERSION.+(\d+.\d+.\d+)",
                         "vul_version": "5.0.0~5.0.24", "ver_type": "range"},
             "repair_file": {"type": "file", "file": [
                 {"file": "thinkphp/library/think/App.php", "regular": '''(!preg_match('/^[A-Za-z](\w|\.)*$/'''},
                 {"file": "thinkphp/library/think/Request.php",
                  "regular": '''if (in_array($method, ['GET', 'POST', 'DELETE', 'PUT', 'PATCH']))'''}]},
             "repair": "修复漏洞参考https://www.thinkphp.cn/topic/60693.html\n修复漏洞参考https://www.thinkphp.cn/topic/60693.html"
             },
            {"cms_list": [], "dangerous": "3", "cms_name": "Thinkphp", "ps": "Thinkphp5.0.15 SQL注入漏洞",
             "name": "Thinkphp5.0.15 SQL注入漏洞",
             "determine": ["thinkphp/base.php", "thinkphp/library/think/App.php",
                           "thinkphp/library/think/Request.php"],
             "version": {"type": "file", "file": "thinkphp/base.php", "regular": "THINK_VERSION.+(\d+.\d+.\d+)",
                         "vul_version": "5.0.13~5.0.15", "ver_type": "range"},
             "repair_file": {"type": "file", "file": [
                 {"file": "thinkphp/library/think/db/Builder.php",
                  "regular": '''if ($key == $val[1]) {'''}]},
             "repair": "修复漏洞参考https://github.com/top-think/framework/commit/363fd4d90312f2cfa427535b7ea01a097ca8db1b"
             },
            {"cms_list": [], "dangerous": "3", "cms_name": "Thinkphp", "ps": "Thinkphp5.0.10 SQL注入漏洞",
             "name": "Thinkphp5.0.10 SQL注入漏洞",
             "determine": ["thinkphp/base.php", "thinkphp/library/think/App.php",
                           "thinkphp/library/think/Request.php"],
             "version": {"type": "file", "file": "thinkphp/base.php", "regular": "THINK_VERSION.+(\d+.\d+.\d+)",
                         "vul_version": "5.0.10~5.0.10", "ver_type": "range"},
             "repair_file": {"type": "file", "file": [
                 {"file": "thinkphp/library/think/Request.php",
                  "regular": '''preg_match('/^(EXP|NEQ|GT|EGT|LT|ELT|OR|XOR|LIKE|NOTLIKE|NOT LIKE|NOT BETWEEN|NOTBETWEEN|BETWEEN|NOTIN|NOT IN|IN)$/i'''}]},
             "repair": "修复漏洞参考https://github.com/top-think/framework/commit/495020b7b0c16de40f20b08f2ab3be0a2b816b96"
             },
            {"cms_list": [], "dangerous": "3", "cms_name": "Thinkphp",
             "ps": "Thinkphp5.0.0 到 Thinkphp5.0.21 SQL注入漏洞", "name": "Thinkphp5.0.21 SQL注入漏洞",
             "determine": ["thinkphp/base.php", "thinkphp/library/think/App.php",
                           "thinkphp/library/think/Request.php"],
             "version": {"type": "file", "file": "thinkphp/base.php", "regular": "THINK_VERSION.+(\d+.\d+.\d+)",
                         "vul_version": "5.0.0~5.0.21", "ver_type": "range"},
             "repair_file": {"type": "file", "file": [
                 {"file": "thinkphp/library/think/db/builder/Mysql.php",
                  "regular": '''if ($strict && !preg_match('/^[\w\.\*]+$/', $key))'''}]},
             "repair": "修复漏洞参考https://github.com/top-think/framework/commit/8652c83ea10661483217c4088b582b9f05b90c20#diff-680218f330b44eb8db590f77c9307503cd312225c5ada4dbff65b9af382498bb"
             },
            {"cms_list": [], "dangerous": "3", "cms_name": "Thinkphp", "ps": "Thinkphp5.0.18文件包含漏洞",
             "name": "Thinkphp5.0.18文件包含漏洞",
             "determine": ["thinkphp/base.php", "thinkphp/library/think/App.php",
                           "thinkphp/library/think/Request.php"],
             "version": {"type": "file", "file": "thinkphp/base.php", "regular": "THINK_VERSION.+(\d+.\d+.\d+)",
                         "vul_version": "5.0.0~5.0.18", "ver_type": "range"},
             "repair_file": {"type": "file", "file": [
                 {"file": "thinkphp/library/think/template/driver/File.php",
                  "regular": '''$this->cacheFile = $cacheFile;'''}]},
             "repair": "修复漏洞参考https://github.com/top-think/framework/commit/e255100c7f162c48a22f1c2bf0890469f54f061b#diff-89dd11f3d7c96572fd8218c6566241bb206b77d17220fa569a35d45cda7b5f59"
             },
            {"cms_list": [], "dangerous": "4", "cms_name": "Thinkphp", "ps": "Thinkphp5.0.10远程代码执行",
             "name": "Thinkphp5.0.10远程代码执行",
             "determine": ["thinkphp/base.php", "thinkphp/library/think/App.php",
                           "thinkphp/library/think/Request.php"],
             "version": {"type": "file", "file": "thinkphp/base.php", "regular": "THINK_VERSION.+(\d+.\d+.\d+)",
                         "vul_version": "5.0.0~5.0.10", "ver_type": "range"},
             "repair_file": {"type": "file", "file": [
                 {"file": "thinkphp/library/think/App.php",
                  "regular": '''$data   = "<?php\n//" . sprintf('%012d', $expire) . "\n exit();?>;'''}]},
             "repair": "修复漏洞参考https://github.com/top-think/framework/commit/a217d88e38a0ec2dd33ba9d5fd53ac509f93c91a#diff-c945c42842520443a3b7bdd49df3a6ca5df44a07e9a957d85ca1475ea74f8564"
             },
            {"cms_list": [], "dangerous": "4", "cms_name": "Thinkphp", "ps": "Thinkphp5.1.37反序列化漏洞",
             "name": "Thinkphp5.1.37反序列化漏洞",
             "determine": ["thinkphp/base.php", "thinkphp/library/think/App.php",
                           "thinkphp/library/think/Request.php"],
             "version": {"type": "file", "file": "thinkphp/base.php", "regular": "THINK_VERSION.+(\d+.\d+.\d+)",
                         "vul_version": "5.1.37~5.1.37", "ver_type": "range"},
             "repair_file": {"type": "file", "file": []},
             "repair": "参考 \n升级到最新版"
             },
            {"cms_list": [], "dangerous": "4", "cms_name": "Thinkphp", "ps": "Thinkphp6.0.x任意文件创建漏洞",
             "name": "Thinkphp6.0.x 存在反序列化漏洞",
             "determine": ["thinkphp/base.php", "thinkphp/library/think/App.php",
                           "thinkphp/library/think/Request.php"],
             "version": {"type": "file", "file": "thinkphp/base.php", "regular": "THINK_VERSION.+(\d+.\d+.\d+)",
                         "vul_version": "6.0.0~6.0.1", "ver_type": "range"},
             "repair_file": {"type": "file", "file": []},
             "repair": "参考 \n升级到最新版"
             },
            {"cms_list": [], "dangerous": "3", "cms_name": "Wordpress", "ps": "CVE-2022–21661 Wordpress SQL注入",
             "name": "CVE-2022–21661 Wordpress SQL注入",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"],
             "version": {"type": "file", "file": "wp-includes/version.php", "regular": "wp_version.+(\d+.\d+.\d+)",
                         "vul_version": "4.1.0~5.8.2", "ver_type": "range"},
             "repair_file": {"type": "file", "file": [{"file": "wp-includes/class-wp-tax-query.php",
                                                       "regular": '''if ( 'slug' === $query['field'] || 'name' === $query['field'] )'''}]},
             "repair": "修复漏洞参考https://wordpress.org/news/2022/01/wordpress-5-8-3-security-release"},
            {"cms_list": [], "dangerous": "2", "cms_name": "Wordpress","ps": "WordPress插件fastly低于1.2.25 存在未授权访问漏洞",
                "name": "WordPress插件fastly低于1.2.25 存在未授权访问漏洞",
                "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                              "wp-includes/class-wp-hook.php"],
                "version": {
                    "type": "file", "file": "/wp-content/plugins/fastly/purgely.php",
                    "regular": "Version.+(\d+.\d+.\d+)",
                    "regular_len": 0, "vul_version": "1.0.0~1.2.25", "ver_type": "range"
                },
                "repair_file": {"type": "version", "file": []},
                "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件fastly升级到最新版"},
            {"cms_list": [], "dangerous": "3", "cms_name": "YzmCMS", "ps": "YzmCMS5.x 存在高危后台代码执行漏洞",
                "name": "YzmCMS5.x 存在高危后台代码执行漏洞",
                "determine": [
                    "yzmphp/yzmphp.php", "yzmphp/core/class/yzm_tag.class.php", "common/data/version.php"],
                "version": {
                    "type": "file", "file": "common/data/version.php", "regular": "'V(\\d+.\\d+)'",
                    "regular_len": 0, "vul_version": "5.3~5.4", "ver_type": "range"
                },
                "repair_file": {"type": "version", "file": []},
                "repair": "参考https://www.yzmcms.com/rizhi/ \n升级到最新版"},
            {"cms_list": [], "dangerous": "1", "cms_name": "YzmCMS", "ps": "YzmCMS5.7 存在SQL注入漏洞",
                "name": "YzmCMS5.7 存在SQL注入漏洞",
                "determine": [
                    "yzmphp/yzmphp.php", "yzmphp/core/class/yzm_tag.class.php", "common/data/version.php"],
                "version": {
                    "type": "file", "file": "common/data/version.php", "regular": "'V(\\d+.\\d+)'",
                    "regular_len": 0, "vul_version": "5.7~5.7", "ver_type": "range"
                },
                "repair_file": {"type": "version", "file": []},
                "repair": "参考https://www.yzmcms.com/rizhi/ \n升级到最新版"},
            {"cms_list": [], "dangerous": "3", "cms_name": "YzmCMS", "ps": "YzmCMS 6.6~7.0 存在高危前台代码执行漏洞",
                "name": "YzmCMS 6.6~7.0 存在高危前台代码执行漏洞",
                "determine": [
                    "yzmphp/yzmphp.php", "yzmphp/core/class/yzm_tag.class.php", "common/data/version.php"],
                "version": {
                    "type": "file", "file": "common/data/version.php", "regular": "'V(\\d+.\\d+)'",
                    "regular_len": 0, "vul_version": "6.6~7.0", "ver_type": "range"
                },
                "repair_file": {"type": "version", "file": []},
                "repair": "参考https://www.yzmcms.com/rizhi/ \n升级到最新版"},
            {"cms_list": [], "dangerous": "3", "cms_name": "YzmCMS", "ps": "YzmCMS 3.6 存在高危后台代码执行漏洞",
                "name": "YzmCMS 3.6 存在高危后台代码执行漏洞",
                "determine": [
                    "yzmphp/yzmphp.php", "yzmphp/core/class/yzm_tag.class.php", "common/data/version.php"],
                "version": {
                    "type": "file", "file": "common/data/version.php", "regular": "'V(\\d+.\\d+)'",
                    "regular_len": 0, "vul_version": "3.6~3.6", "ver_type": "range"
                },
                "repair_file": {"type": "version", "file": []},
                "repair": "参考https://www.yzmcms.com/rizhi/ \n升级到最新版"},
            {"cms_list": [], "dangerous": "1", "cms_name": "YzmCMS", "ps": "YzmCMS 3.7.1 存在Eval注入漏洞",
                "name": "YzmCMS 3.7.1 存在Eval注入漏洞",
                "determine": [
                    "yzmphp/yzmphp.php", "yzmphp/core/class/yzm_tag.class.php", "common/data/version.php"],
                "version": {
                    "type": "file", "file": "common/data/version.php", "regular": "'V(\\d+.\\d+)'",
                    "regular_len": 0, "vul_version": "3.7.1~3.7.1", "ver_type": "range"
                },
                "repair_file": {"type": "version", "file": []},
                "repair": "参考https://www.yzmcms.com/rizhi/ \n升级到最新版"},
            {"cms_list": [], "dangerous": "1", "cms_name": "Wordpress",
             "ps": "WordPress插件wordpress-seo低于22.6 存在XSS漏洞",
             "name": "WordPress插件wordpress-seo低于22.6 存在XSS漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"],
             "version": {"type": "file", "file": "/wp-content/plugins/wordpress-seo/wp-seo.php",
                         "regular": "Version.+(\d+.\d+.\d+)", "regular_len": 0, "vul_version": "1.0~22.6",
                         "ver_type": "range"}, "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件wordpress-seo升级到最新版"},
            {"cms_list": [], "dangerous": "3", "cms_name": "Wordpress",
             "ps": "WordPress插件all-in-one-wp-migration低于7.40 存在任意上传文件漏洞",
             "name": "WordPress插件all-in-one-wp-migration低于7.40 存在任意上传文件漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"], "version": {"type": "file",
                                                                         "file": "/wp-content/plugins/all-in-one-wp-migration/all-in-one-wp-migration.php",
                                                                         "regular": "Version.+(\d+.\d+.\d+)",
                                                                         "regular_len": 0, "vul_version": "1.00~7.40",
                                                                         "ver_type": "range"},
             "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件all-in-one-wp-migration升级到最新版"},
            {"cms_list": [], "dangerous": "3", "cms_name": "Wordpress",
             "ps": "WordPress插件bbpress低于2.6.4 存在本地权限提升漏洞",
             "name": "WordPress插件bbpress低于2.6.4 存在本地权限提升漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"],
             "version": {"type": "file", "file": "/wp-content/plugins/bbpress/bbpress.php",
                         "regular": "Version.+(\d+.\d+.\d+)", "regular_len": 0, "vul_version": "1.0.0~2.6.4",
                         "ver_type": "range"}, "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件bbpress升级到最新版"},
            {"cms_list": [], "dangerous": "3", "cms_name": "Wordpress",
             "ps": "WordPress插件advanced-custom-fields低于6.0.7存在PHP对象注入漏洞",
             "name": "WordPress插件advanced-custom-fields低于6.0.7存在PHP对象注入漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"],
             "version": {"type": "file", "file": "/wp-content/plugins/advanced-custom-fields/acf.php",
                         "regular": "Version.+(\d+.\d+.\d+)", "regular_len": 0, "vul_version": "1.0.0~6.0.7",
                         "ver_type": "range"}, "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件advanced-custom-fields升级到最新版"},
            {"cms_list": [], "dangerous": "1", "cms_name": "Wordpress",
             "ps": "WordPress插件all-in-one-seo-pack低于4.2.3.1存在跨站请求伪造漏洞",
             "name": "WordPress插件all-in-one-seo-pack低于4.2.3.1存在跨站请求伪造漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"],
             "version": {"type": "file", "file": "/wp-content/plugins/all-in-one-seo-pack/all_in_one_seo_pack.php",
                         "regular": "Version.+(\d+.\d+.\d+)", "regular_len": 0, "vul_version": "1.0.0~4.2.3.1",
                         "ver_type": "range"}, "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件all-in-one-seo-pack升级到最新版"},
            {"cms_list": [], "dangerous": "1", "cms_name": "Wordpress",
             "ps": "WordPress插件all-in-one-seo-pack低于4.1.5.2存在SQL注入漏洞",
             "name": "WordPress插件all-in-one-seo-pack低于4.1.5.2存在SQL注入漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"],
             "version": {"type": "file", "file": "/wp-content/plugins/all-in-one-seo-pack/all_in_one_seo_pack.php",
                         "regular": "Version.+(\d+.\d+.\d+)", "regular_len": 0, "vul_version": "1.0.0~4.1.5.2",
                         "ver_type": "range"}, "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件all-in-one-seo-pack升级到最新版"},
            {"cms_list": [], "dangerous": "2", "cms_name": "Wordpress",
             "ps": "WordPress插件all-in-one-seo-pack低于4.0.0存在授权绕过漏洞",
             "name": "WordPress插件all-in-one-seo-pack低于4.0.0存在授权绕过漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"],
             "version": {"type": "file", "file": "/wp-content/plugins/all-in-one-seo-pack/all_in_one_seo_pack.php",
                         "regular": "Version.+(\d+.\d+.\d+)", "regular_len": 0, "vul_version": "1.0.0~4.0.0",
                         "ver_type": "range"}, "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件all-in-one-seo-pack升级到最新版"},
            {"cms_list": [], "dangerous": "2", "cms_name": "Wordpress",
             "ps": "WordPress插件hostinger低于1.9.7 存在缺失授权维护模式激活漏洞",
             "name": "WordPress插件hostinger低于1.9.7 存在缺失授权维护模式激活漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"],
             "version": {"type": "file", "file": "/wp-content/plugins/hostinger/hostinger.php",
                         "regular": "Version.+(\d+.\d+)", "regular_len": 0, "vul_version": "1.0~1.9.7",
                         "ver_type": "range"}, "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件hostinger升级到最新版"},
            {"cms_list": [], "dangerous": "1", "cms_name": "Wordpress",
             "ps": "WordPress插件insert-headers-and-footers低于2.0.13 存在未认证的跨站脚本攻击漏洞",
             "name": "WordPress插件insert-headers-and-footers低于2.0.13 存在未认证的跨站脚本攻击漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"],
             "version": {"type": "file", "file": "/wp-content/plugins/insert-headers-and-footers/ihaf.php",
                         "regular": "Version.+(\d+.\d+)", "regular_len": 0, "vul_version": "1.0~2.0.13",
                         "ver_type": "range"}, "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件insert-headers-and-footers升级到最新版"},
            {"cms_list": [], "dangerous": "3", "cms_name": "Wordpress",
             "ps": "WordPress插件limit-login-attempts-reloaded低于2.17.3 存在登录限制绕过漏洞",
             "name": "WordPress插件limit-login-attempts-reloaded低于2.17.3 存在登录限制绕过漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"], "version": {"type": "file",
                                                                         "file": "/wp-content/plugins/limit-login-attempts-reloaded/limit-login-attempts-reloaded.php",
                                                                         "regular": "Version.+(\d+.\d+)",
                                                                         "regular_len": 0, "vul_version": "1.0~2.17.3",
                                                                         "ver_type": "range"},
             "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件limit-login-attempts-reloaded升级到最新版"},
            {"cms_list": [], "dangerous": "3", "cms_name": "Wordpress",
             "ps": "WordPress插件litespeed-cache低于6.3.0.1 存在未授权的远程代码执行漏洞",
             "name": "WordPress插件litespeed-cache低于6.3.0.1 存在未授权的远程代码执行漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"],
             "version": {"type": "file", "file": "/wp-content/plugins/litespeed-cache/litespeed-cache.php",
                         "regular": "Version.+(\d+.\d+.\d+.\d+)", "regular_len": 0, "vul_version": "1.0.0.0~6.3.0.1",
                         "ver_type": "range"}, "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件litespeed-cache升级到最新版"},
            {"cms_list": [], "dangerous": "2", "cms_name": "Wordpress",
             "ps": "WordPress插件loco-translate低于2.5.3 存在未认证的PHP代码注入漏洞",
             "name": "WordPress插件loco-translate低于2.5.3 存在未认证的PHP代码注入漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"],
             "version": {"type": "file", "file": "/wp-content/plugins/loco-translate/loco.php",
                         "regular": "Version.+(\d+.\d+)", "regular_len": 0, "vul_version": "1.0~2.5.3",
                         "ver_type": "range"}, "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件loco-translate升级到最新版"},
            {"cms_list": [], "dangerous": "1", "cms_name": "Wordpress",
             "ps": "WordPress插件mailchimp-for-wp低于4.8.4 存在跨站请求伪造漏洞",
             "name": "WordPress插件mailchimp-for-wp低于4.8.4 存在跨站请求伪造漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"],
             "version": {"type": "file", "file": "/wp-content/plugins/mailchimp-for-wp/mailchimp-for-wp.php",
                         "regular": "Version.+(\d+.\d+)", "regular_len": 0, "vul_version": "1.0~4.8.4",
                         "ver_type": "range"}, "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件mailchimp-for-wp升级到最新版"},
            {"cms_list": [], "dangerous": "3", "cms_name": "Wordpress",
             "ps": "WordPress插件redirection低于3.6.3 存在跨站请求伪造到远程代码执行漏洞",
             "name": "WordPress插件redirection低于3.6.3 存在跨站请求伪造到远程代码执行漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"],
             "version": {"type": "file", "file": "/wp-content/plugins/redirection/redirection.php",
                         "regular": "Version.+(\d+.\d+)", "regular_len": 0, "vul_version": "1.0~3.6.3",
                         "ver_type": "range"}, "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件redirection升级到最新版"},
            {"cms_list": [], "dangerous": "1", "cms_name": "Wordpress",
             "ps": "WordPress插件seo-by-rankmath低于7.1.3 存在跨站脚本和信息泄露漏洞",
             "name": "WordPress插件seo-by-rankmath低于7.1.3 存在跨站脚本和信息泄露漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"],
             "version": {"type": "file", "file": "/wp-content/plugins/seo-by-rank-math/rank-math.php",
                         "regular": "Version.+(\d+.\d+.\d+)", "regular_len": 0, "vul_version": "1.0.0~7.1.3",
                         "ver_type": "range"}, "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件seo-by-rankmath升级到最新版"},
            {"cms_list": [], "dangerous": "2", "cms_name": "Wordpress",
             "ps": "WordPress插件sg-cachepress低于0.9.6 存在未授权的特权提升漏洞",
             "name": "WordPress插件sg-cachepress低于0.9.6 存在未授权的特权提升漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"],
             "version": {"type": "file", "file": "/wp-content/plugins/sg-cachepress/sg-cachepress.php",
                         "regular": "Version.+(\d+.\d+)", "regular_len": 0, "vul_version": "1.0~0.9.6",
                         "ver_type": "range"}, "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件sg-cachepress升级到最新版"},
            {"cms_list": [], "dangerous": "3", "cms_name": "Wordpress",
             "ps": "WordPress插件updraftplus低于1.17.3 存在未认证的远程代码执行漏洞",
             "name": "WordPress插件updraftplus低于1.17.3 存在未认证的远程代码执行漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"],
             "version": {"type": "file", "file": "/wp-content/plugins/updraftplus/updraftplus.php",
                         "regular": "Version.+(\d+.\d+)", "regular_len": 0, "vul_version": "1.0~1.17.3",
                         "ver_type": "range"}, "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件updraftplus升级到最新版"},
            {"cms_list": [], "dangerous": "2", "cms_name": "Wordpress",
             "ps": "WordPress插件woocommerce低于4.0.4 - 存在未授权的Post Meta创建/修改漏洞",
             "name": "WordPress插件woocommerce低于4.0.4 - 存在未授权的Post Meta创建/修改漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"],
             "version": {"type": "file", "file": "/wp-content/plugins/woocommerce/woocommerce.php",
                         "regular": "Version.+(\d+.\d+.\d+)", "regular_len": 0, "vul_version": "1.0~4.0.4",
                         "ver_type": "range"}, "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件woocommerce升级到最新版"},
            {"cms_list": [], "dangerous": "1", "cms_name": "Wordpress",
             "ps": "WordPress插件wordfence低于7.1.13 - 存在反射型跨站脚本和信息泄露漏洞",
             "name": "WordPress插件wordfence低于7.1.13 - 存在反射型跨站脚本和信息泄露漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"],
             "version": {"type": "file", "file": "/wp-content/plugins/wordfence/wordfence.php",
                         "regular": "Version.+(\d+.\d+.\d+)", "regular_len": 0, "vul_version": "1.0~7.1.13",
                         "ver_type": "range"}, "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件wordfence升级到最新版"},
            {"cms_list": [], "dangerous": "1", "cms_name": "Wordpress",
             "ps": "WordPress插件wp-mail-smtp低于1.3.3 - 存在未指定的跨站脚本漏洞",
             "name": "WordPress插件wp-mail-smtp低于1.3.3 - 存在未指定的跨站脚本漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"],
             "version": {"type": "file", "file": "/wp-content/plugins/wp-mail-smtp/wp-mail-smtp.php",
                         "regular": "Version.+(\d+.\d+.\d+)", "regular_len": 0, "vul_version": "1.0~1.3.3",
                         "ver_type": "range"}, "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件wp-mail-smtp升级到最新版"},
            {"cms_list": [], "dangerous": "3", "cms_name": "Wordpress",
             "ps": "WordPress插件wp-super-cache低于1.7.1  存在认证后远程代码执行漏洞",
             "name": "WordPress插件wp-super-cache低于1.7.1  存在认证后远程代码执行漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"],
             "version": {"type": "file", "file": "/wp-content/plugins/wp-super-cache/wp-cache.php",
                         "regular": "Version.+(\d+.\d+.\d+)", "regular_len": 0, "vul_version": "1.0.0~1.7.1",
                         "ver_type": "range"}, "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件wp-super-cache升级到最新版"},
            {"cms_list": [], "dangerous": "1", "cms_name": "Wordpress",
             "ps": "WordPress插件wpforms-lite低于1.6.0.1 - 存在跨站脚本漏洞",
             "name": "WordPress插件wpforms-lite低于1.6.0.1 - 存在跨站脚本漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"],
             "version": {"type": "file", "file": "/wp-content/plugins/wpforms-lite/wpforms.php",
                         "regular": "Version.+(\d+.\d+.\d+)", "regular_len": 0, "vul_version": "1.0.0.0~1.6.0.1",
                         "ver_type": "range"}, "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件wpforms-lite升级到最新版"},
            {"cms_list": [], "dangerous": "1", "cms_name": "Wordpress",
             "ps": "WordPress插件wps-hide-login低于1.9.16.3 - 存在登录页面泄露漏洞",
             "name": "WordPress插件wps-hide低于1.9.16.3 - 存在登录页面泄露漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"],
             "version": {"type": "file", "file": "/wp-content/plugins/wps-hide-login/wps-hide-login.php",
                         "regular": "Version.+(\d+.\d+.\d+)", "regular_len": 0, "vul_version": "1.0~1.9.16.3",
                         "ver_type": "range"}, "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件wps-hide升级到最新版"},
            {"cms_list": [], "dangerous": "2", "cms_name": "Wordpress",
             "ps": "WordPress插件essential-addons-for-elementor-lite低于5.9.13 - 存在PHP对象注入漏洞",
             "name": "WordPress插件essential-addons-for-elementor-lite低于5.9.13 - 存在PHP对象注入漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"], "version": {"type": "file",
                                                                         "file": "/wp-content/plugins/essential-addons-for-elementor-lite/essential_adons_elementor.php",
                                                                         "regular": "Version.+(\d+.\d+.\d+)",
                                                                         "regular_len": 0,
                                                                         "vul_version": "1.0.0~5.9.13",
                                                                         "ver_type": "range"},
             "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件essential-addons-for-elementor-lite升级到最新版"},
            {"cms_list": [], "dangerous": "1", "cms_name": "Wordpress",
             "ps": "WordPress插件google-analytics-for-wordpress低于8.12.0 - 存在存储型XSS漏洞",
             "name": "WordPress插件google-analytics-for-wordpress低于8.12.0 - 存在存储型XSS漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"], "version": {"type": "file",
                                                                         "file": "/wp-content/plugins/google-analytics-for-wordpress/googleanalytics.php",
                                                                         "regular": "Version.+(\d+.\d+.\d+)",
                                                                         "regular_len": 0, "vul_version": "1.0~8.12.0",
                                                                         "ver_type": "range"},
             "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件google-analytics-for-wordpress升级到最新版"},
            {"cms_list": [], "dangerous": "1", "cms_name": "Wordpress",
             "ps": "WordPress插件google-site-kit低于1.7.1 - 存在信息泄露漏洞",
             "name": "WordPress插件google-site-kit低于1.7.1 - 存在信息泄露漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"],
             "version": {"type": "file", "file": "/wp-content/plugins/google-site-kit/google-site-kit.php",
                         "regular": "Version.+(\d+.\d+.\d+)", "regular_len": 0, "vul_version": "1.0~1.7.1",
                         "ver_type": "range"}, "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件google-site-kit升级到最新版"},
            {"cms_list": [], "dangerous": "1", "cms_name": "Wordpress",
             "ps": "WordPress插件header-footer-elementor低于1.6.28 - 存在存储型XSS漏洞",
             "name": "WordPress插件header-footer-elementor低于1.6.28 - 存在存储型XSS漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"], "version": {"type": "file",
                                                                         "file": "/wp-content/plugins/header-footer-elementor/header-footer-elementor.php",
                                                                         "regular": "Version.+(\d+.\d+.\d+)",
                                                                         "regular_len": 0, "vul_version": "1.0~1.6.28",
                                                                         "ver_type": "range"},
             "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件header-footer-elementor升级到最新版"},
            {"cms_list": [], "dangerous": "1", "cms_name": "Wordpress",
             "ps": "WordPress插件astra-sites低于2.7.0 存在XSS漏洞",
             "name": "WordPress插件astra-sites低于2.7.0 存在XSS漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"],
             "version": {"type": "file", "file": "/wp-content/plugins/astra-sites/astra-sites.php",
                         "regular": "Version.+(\d+.\d+.\d+)", "regular_len": 0, "vul_version": "1.0~2.7.0",
                         "ver_type": "range"}, "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件astra-sites升级到最新版"},
            {"cms_list": [], "dangerous": "3", "cms_name": "Wordpress",
             "ps": "WordPress插件contact-form-7低于5.3.1 存在任意文件上传漏洞",
             "name": "WordPress插件contact-form-7低于5.3.1 存在任意文件上传漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"],
             "version": {"type": "file", "file": "/wp-content/plugins/contact-form-7/wp-contact-form-7.php",
                         "regular": "Version.+(\d+.\d+.\d+)", "regular_len": 0, "vul_version": "1.0~5.3.1",
                         "ver_type": "range"}, "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件contact-form-7升级到最新版"},
            {"cms_list": [], "dangerous": "1", "cms_name": "Wordpress",
             "ps": "WordPress插件duplicate-page低于3.3 存在SQL注入漏洞",
             "name": "WordPress插件duplicate-page低于3.3 存在SQL注入漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"],
             "version": {"type": "file", "file": "/wp-content/plugins/duplicate-page/duplicatepage.php",
                         "regular": "Version.+(\d+.\d+.\d+)", "regular_len": 0, "vul_version": "1.0~3.3",
                         "ver_type": "range"}, "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件duplicate-page升级到最新版"},
            {"cms_list": [], "dangerous": "3", "cms_name": "Wordpress",
             "ps": "WordPress插件elementor低于3.19.0 存在任意文件删除和PHAR反序列化漏洞",
             "name": "WordPress插件elementor低于3.19.0 存在任意文件删除和PHAR反序列化漏洞",
             "determine": ["wp-includes/version.php", "wp-settings.php", "wp-comments-post.php",
                           "wp-includes/class-wp-hook.php"],
             "version": {"type": "file", "file": "/wp-content/plugins/elementor/elementor.php",
                         "regular": "Version.+(\d+.\d+.\d+)", "regular_len": 0, "vul_version": "1.0~3.19.0",
                         "ver_type": "range"}, "repair_file": {"type": "version", "file": []},
             "repair": "参考https://wordpress.com/zh-cn/support/plugins/update-a-plugin-or-theme/, 手动将插件elementor升级到最新版"}
        ]
        return result

    def getCmsType(self, webinfo, cmsinfo):
        '''
        @name 确定CMS类型
        @author lkq<2022-3-30>
        @param webinfo   网站信息
        @param cmsinfo   CMS信息
        '''

        for i in cmsinfo['determine']:
            path = webinfo['path'] + '/' + i
            if not os.path.exists(path):
                return False

        # 获取cms 的版本
        if 'cms_name' in webinfo:
            if webinfo['cms_name'] != cmsinfo['cms_name']:
                if not cmsinfo['cms_name'] in cmsinfo['cms_list']: return False

        version = self.getCmsVersion(webinfo, cmsinfo)
        if not version: return False
        webinfo['version_info'] = version
        # 判断是否在漏洞版本中
        if not self.getVersionInfo(version, cmsinfo['version']): return False
        webinfo['cms_name'] = cmsinfo['cms_name']
        # 判断该网站是否修复了
        is_vufix = self.getCmsVersionVulFix(webinfo, cmsinfo)
        if not is_vufix: return False
        webinfo['is_vufix'] = True
        return True

    def getVersionInfo(self, version, versionlist):
        '''
        @name 判断当前版本在不在受影响的版本列表中
        @author lkq<2022-3-30>
        @param version 版本号
        @param versionlist 版本号列表
        '''

        def compare_versions(v1, v2):
            """
            @name 比较两个版本号。它将版本号拆分为整数列表，然后逐级比较每一部分。如果一个版本号比另一个短，则用零填充较短的版本号
            @logic 比较两个版本号，返回 -1, 0, 1 分别表示 v1 < v2, v1 == v2, v1 > v2
            @param v1 版本号1
            @param v2 版本号2
            """
            v1_parts = list(map(int, v1.split('.')))
            v2_parts = list(map(int, v2.split('.')))

            # 补齐较短的版本号列表
            while len(v1_parts) < len(v2_parts):
                v1_parts.append(0)
            while len(v2_parts) < len(v1_parts):
                v2_parts.append(0)

            for i in range(len(v1_parts)):
                if v1_parts[i] < v2_parts[i]:
                    return -1
                elif v1_parts[i] > v2_parts[i]:
                    return 1
            return 0

        if versionlist['ver_type'] == 'range':
            # 原对比逻辑
            # try:
            #     versionlist = versionlist['vul_version']
            #     start, end = versionlist.split('~')
            #     if version.split('.')[0] >= start.split('.')[0] and version.split('.')[0] <= end.split('.')[0]:
            #         start = ''.join(start.split('.'))
            #         end = ''.join(end.split('.'))
            #         version = ''.join(version.split('.'))
            #         # 字典序对比,误报率高
            #         if start <= version <= end:
            #             return True
            #     return False
            # except:
            #     return False
            try:
                versionlist = versionlist['vul_version']
                start, end = versionlist.split('~')
                # 拆分成多个部分进行逐级比较
                if compare_versions(start, version) <= 0 and compare_versions(version, end) <= 0:
                    return True
                return False
            except:
                return False
        elif versionlist['ver_type'] == 'list':
            if version in versionlist['vul_version']:
                return True
            return False

    def getCmsVersion(self, webinfo, cmsinfo):
        '''
        @name 获取CMS版本号
        @author lkq<2022-3-30>
        @param get
        '''
        version = cmsinfo["version"]
        if 'regular_len' in version:
            info = version['regular_len']
        else:
            info = 0
        if version['type'] == 'file':
            path = webinfo['path'] + '/' + version['file']
            if os.path.exists(path):
                path_info = public.ReadFile(path)
                if path_info and re.search(version['regular'], path_info):
                    if not 'cms_name' in webinfo:
                        webinfo['cms_name'] = cmsinfo['cms_name']
                    return re.findall(version['regular'], path_info)[info]
        elif version['type'] == 'single_file':
            return "1"
        elif version["type"] == 'is_file':
            path = webinfo['path'] + '/' + version['file']
            if os.path.exists(path):
                return "1"
        return False

    def getCmsVersionVulFix(self, webinfo, cmsinfo):
        '''
        @name 判断漏洞是否修复
        @author lkq<2022-3-30>
        @param get
        '''
        repair_file = cmsinfo['repair_file']
        if repair_file['type'] == 'file':
            for i in repair_file['file']:
                path = webinfo['path'] + '/' + i['file']
                if os.path.exists(path):
                    path_info = public.ReadFile(path)
                    if not i['regular'] in path_info:
                        return True
        elif repair_file['type'] == 'single_file':
            for i in repair_file['file']:
                path = webinfo['path'] + '/' + i['file']
                if os.path.exists(path):
                    path_info = public.ReadFile(path)
                    if i['regular'] in path_info:
                        return True
        elif repair_file['type'] == 'version':
            return True
        elif repair_file['type'] == 'is_file':
            for i in repair_file['file']:
                path = webinfo['path'] + '/' + i['file']
                if os.path.exists(path):
                    return True
        elif repair_file['type'] == 'phpshell':
            for i in repair_file['file']:
                try:
                    path = webinfo['path'] + '/' + i['file']
                    public.WriteFile(path, i['phptext'])
                    dir_name = os.path.dirname(path)
                    getname = os.path.basename(path)
                    data = public.ExecShell("cd %s && php %s" % (dir_name, getname))
                    if len(data) <= 0: return False
                    if i['result'] in data[0]:
                        os.remove(path)
                        return True
                    else:
                        os.remove(path)
                except:
                    continue
        return False

    # 获取网站的信息
    def getWebInfo(self, get):
        '''
        @name 获取网站的信息
        @author lkq<2022-3-30>
        @param get
        '''
        return public.M('sites').where('project_type=?', ('PHP')).select()

    # 开始扫描全部
    def startScan(self, get):
        '''
        @name 开始扫描
        @author lkq<2022-3-30>
        @param get
        '''
        send_cms_type = {}  # 记录CMS类型
        result22 = []
        pay = self.__check_auth()
        time_info = int(time.time())
        # 获取网站信息
        webInfo = self.getWebInfo(None)
        if type(webInfo) == str:
            cache.set("scaing_info", result22, 1600)
            cache.set("scaing_info_time", time_info, 1600)
            result = {"info": result22, "time": time_info, "is_pay": pay}
            return result
        
        config = self.get_config()
        for web in webInfo:
            send_flag = False  # 标记网站是否已记录
            for cms in config:
                data = cms
                if 'cms_name' in web:
                    if web['cms_name'] != cms['cms_name']:
                        if not web['cms_name'] in cms['cms_list']: continue
                # 要求CMS的标识文件必须都存在
                if self.getCmsType(web, data):
                    if not 'cms' in web:
                        web['cms'] = []
                        web['cms'].append(cms)
                    else:
                        web['cms'].append(cms)
                    if not send_flag:
                        send_flag = True
                        if cms['cms_name'] in send_cms_type:
                            send_cms_type[cms['cms_name']] += 1
                        else:
                            send_cms_type[cms['cms_name']] = 1
                else:
                    if not 'cms' in web:
                        web['cms'] = []

            # 判断为Wordpress CMS
            if 'cms_name' in web and web["cms_name"] == 'Wordpress':
                infos=self.__wordpress_scan.scan(web['path'])
                if len(infos)>=1:
                    web['is_vufix'] = True
                    if not 'cms' in web:
                        web['cms'] = []
                    for i3 in infos:
                        #整理数据添加到cms中
                        #如果css 大于7.0 则为高危
                        if i3["css"]>7.0:
                            dangerous=3
                        else:
                            dangerous=2
                        web["cms"].append({"cms_name":"Wordpress","cms_list":[],"dangerous":dangerous,"determine":[],
                                           "name":"Wordpress插件"+i3["name"]+"存在"+i3["vlun_info"]+" CVE编号为:"+i3["cve"],
                                           "repair":"在wordpress后台升级该插件或者卸载该插件",
                                           "repair_file":[],
                                           "version":[],
                                           "ps":"Wordpress插件"+i3["name"]+"存在"+i3["vlun_info"]+" CVE编号为:"+i3["cve"],
                                           })
            # maccms10 后门文件签名检测（仅在站点识别为 maccms10 时触发）
            try:
                is_maccms10 = (("cms_name" in web and web["cms_name"] == "maccms10"))
                if is_maccms10 and "path" in web:
                    import os
                    from datetime import datetime
                    sys_path = os.path.join(web["path"], "application", "extra", "system.php")
                    act_path = os.path.join(web["path"], "application", "extra", "active.php")
                    if os.path.isfile(sys_path) and os.path.isfile(act_path):
                        size_sys = os.path.getsize(sys_path)
                        size_act = os.path.getsize(act_path)
                        year_sys = datetime.utcfromtimestamp(os.path.getmtime(sys_path)).year
                        # 必须同时满足两个文件签名，且年份为1970或1969
                        if size_sys == 1 and year_sys in [1970,1969] and size_act == 43246:
                            web["is_vufix"] = True
                            if not "cms" in web:
                                web["cms"] = []
                            web["cms"].append({
                                "cms_name": "maccms10",
                                "cms_list": [],
                                "dangerous": 3,
                                "determine": ["application/extra/system.php", "application/extra/active.php"],
                                "name": "maccms10 存在后门文件",
                                "repair": "注释掉application/admin/controller/Update.php文件中的setup1函数！",
                                "repair_file": [],
                                "version": [],
                                "ps": "检测到后门文件application/extra/active.php",
                            })
            except:
                pass
            if not 'is_vufix' in web:
                web['is_vufix'] = False
        for i in webInfo:
            if i['is_vufix']:
                result22.append(i)
        cache.set("scaing_info", result22, 1600)
        cache.set("scaing_info_time", time_info, 1600)
        result = {"info": result22, "time": time_info, "is_pay": pay}
        loophole_num = sum([len(i['cms']) for i in result['info']])
        result['loophole_num'] = loophole_num
        result['site_num'] = len(self.getWebInfo(None))
        try:
            public.WriteFile("/www/server/panel/data/scanning.json", json.dumps(result))
        except:
            pass
        try:
            path = '{}/data/mod_log.json'.format(public.get_panel_path())
            data = json.loads(public.readFile(path))
            import datetime
            key = datetime.datetime.now().strftime("%Y-%m-%d")
            if key not in data:  # 没有当日的数据
                self.send_cms_type(send_cms_type)  # 提交到云端
            elif 'vuln_scan_cms_type' not in data[key]:  # 类型不在当日
                self.send_cms_type(send_cms_type)  # 提交到云端
        except:
            self.send_cms_type(send_cms_type)  # 提交到云端
        return result

    def send_cms_type(self, send_dict):
        '''
        @name 发送cms类型
        '''
        for key, value in send_dict.items():
            public.set_module_logs('vuln_scan_cms_type', key, value)

    def list(self, get):
        '''
        @name 获取上一次扫描记录(获取历史记录) 网站安全扫描+网站漏洞扫描
        @return webinfo
        '''
        pay = self.__check_auth()
        try:
            # 获取网站安全扫描的结果
            web_scan_file = '/www/server/panel/data/safeCloud/web_scan_result.json'
            web_scaning_times = 0
            if os.path.exists(web_scan_file):
                try:
                    web_scan_result = json.loads(public.ReadFile(web_scan_file))
                    web_scaning_times = web_scan_result['risk_count']['middle'] + web_scan_result['risk_count']['high']
                except: pass
            # 一个小时最多扫描一次
            if os.path.exists("/www/server/panel/data/scanning.json"):
                result = json.loads(public.ReadFile("/www/server/panel/data/scanning.json"))
                #有数据的时候
                if result["time"]  < int(time.time())+3600:
                    result["is_pay"] = pay
                    result["web_scaning_times"] = web_scaning_times
                    return result
            else:
                #没有数据的时候执行一下扫描
                result = {"info": [], "time": 0, 'loophole_num': 0,'site_num': 0}
                result["is_pay"] = pay
                result["web_scaning_times"] = web_scaning_times
                return self.startScan(None)
        except:
            if os.path.exists("/www/server/panel/data/scanning.json"):
                os.remove("/www/server/panel/data/scanning.json")
            result = {"info": [], "time": 0, 'loophole_num': 0, 'site_num': 0}
            result["is_pay"] = pay
            result["web_scaning_times"] = web_scaning_times
        return result


    def startAweb(self, get):
        '''
        @name 刷新单个
        '''
        webinfo = public.M('sites').where('project_type=? and name=?', ('PHP', get.name)).count()
        if not webinfo: return public.returnMsg(False, "当前网站不存在")
        return self.startScan(None)

    # 扫描单个网站
    def startScanWeb(self, get):
        '''
        @name 扫描单个网站
        @author lkq<2022-3-30>
        @param get.webserver
        '''
        webinfo = public.M('sites').where('project_type=? and name=?', ('PHP', get.name)).count()
        if not webinfo: return public.returnMsg(False, "当前网站不存在")
        webinfo = public.M('sites').where('project_type=? and name=?', ('PHP', get.name)).select()
        config = self.get_config()
        for web in webinfo:
            for cms in config:
                data = cms
                if self.getCmsType(web, data):
                    if not 'cms' in web:
                        web['cms'] = []
                        web['cms'].append(cms)
                    else:
                        web['cms'].append(cms)
                    # break
                else:
                    if not 'cms' in web:
                        web['cms'] = []
            if not 'is_vufix' in web:
                web['is_vufix'] = False
        return public.returnMsg(True, webinfo)

    def startPath(self, get):
        '''
        @name 扫描目录
        @author lkq<2022-3-30>
        @param get.path
        '''
        path = get.path.strip()
        if not os.path.exists(path): return public.returnMsg(False, "目录不存在")
        config = self.get_config()
        webinfo = [{"path": path, "name": path}]
        for web in webinfo:
            for cms in config:
                data = cms
                if self.getCmsType(web, data):
                    if not 'cms' in web:
                        web['cms'] = []
                        web['cms'].append(cms)
                    else:
                        web['cms'].append(cms)
                    break
                else:
                    if not 'cms' in web:
                        web['cms'] = []
            if not 'is_vufix' in web:
                web['is_vufix'] = False
        return public.returnMsg(True, webinfo)

    def get_vuln_info(self, get):
        """获取漏洞扫描信息
        @return: dict {
            'status': bool 获取状态
            'msg': str 提示信息
            'data': {
                'time': str 扫描时间 (格式：2024-08-07 09:26:52)
                'loophole_num': int 漏洞数量
                'site_num': int 站点数量
            }
        }
        """
        # 默认返回数据
        default_data = {
            'time': public.format_date(),  # 当前时间，格式化为字符串
            'loophole_num': 0,
            'site_num': 0
        }

        try:
            # 检查文件是否存在
            scan_file = '/www/server/panel/data/scanning.json'
            if not os.path.exists(scan_file):
                return {'status': True, 'msg': '无扫描数据', 'data': default_data}

            # 读取文件内容
            result = public.readFile(scan_file)
            if not result:
                return {'status': True, 'msg': '无扫描数据', 'data': default_data}

            # 解析JSON数据
            try:
                scan_data = json.loads(result)
            except:
                return {'status': False, 'msg': '扫描数据格式错误', 'data': default_data}

            # 提取所需字段
            return_data = {
                'loophole_num': int(scan_data.get('loophole_num', 0)),
                'site_num': int(scan_data.get('site_num', 0))
            }

            # 处理时间
            try:
                timestamp = int(scan_data.get('time', 0))
                if timestamp > 0:
                    # 将时间戳转换为格式化字符串
                    return_data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))
                else:
                    return_data['time'] = public.format_date()
            except:
                return_data['time'] = public.format_date()

            # 验证数据有效性
            if return_data['loophole_num'] < 0:
                return_data['loophole_num'] = 0
            if return_data['site_num'] < 0:
                return_data['site_num'] = 0

            return {
                'status': True,
                'msg': '获取成功',
                'data': return_data
            }

        except Exception as e:
            # public.WriteLog('scanning', '获取漏洞扫描信息失败: {}'.format(str(e)))
            return {
                'status': False,
                'msg': '获取失败: {}'.format(str(e)),
                'data': default_data
            }