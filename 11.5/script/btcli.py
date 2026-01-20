#!/www/server/panel/pyenv/bin/python3
# coding: utf-8
"""
BT-CLI - 宝塔面板命令行管理工具
用于通过命令行方式管理宝塔面板的网站、数据库、FTP等资源
"""

import psutil
import sys
import os
import argparse
from typing import Optional, Dict, List, Any
import json
from datetime import datetime

# 添加宝塔面板类路径
BT_PANEL = '/www/server/panel'
BT_CLASS = '/www/server/panel/class'

for p in (BT_PANEL, BT_CLASS):
    if p not in sys.path and os.path.isdir(p):
        sys.path.insert(0, p)

import public
import panelSite
import database
import ftp
import re
    
# except ImportError:
#     print("错误: 无法导入宝塔面板模块，请确保在宝塔面板环境中运行此脚本")
#     sys.exit(1)


# ============================================
# 颜色输出工具类
# ============================================
class Colors:
    """终端颜色输出"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    _remove_color_re = re.compile(r'\033\[[\d;]+m')

    @staticmethod
    def success(text):
        return f"{Colors.OKGREEN}{text}{Colors.ENDC}"
    
    @staticmethod
    def error(text):
        return f"{Colors.FAIL}{text}{Colors.ENDC}"
    
    @staticmethod
    def warning(text):
        return f"{Colors.WARNING}{text}{Colors.ENDC}"
    
    @staticmethod
    def info(text):
        return f"{Colors.OKCYAN}{text}{Colors.ENDC}"
    
    @staticmethod
    def header(text):
        return f"{Colors.HEADER}{Colors.BOLD}{text}{Colors.ENDC}"

    @staticmethod
    def remove_color(text):
        return Colors._remove_color_re.sub('', text)


# ============================================
# 表格输出工具
# ============================================
class TablePrinter:
    """表格化输出数据"""

    @staticmethod
    def get_char_width(char):
        """获取单个字符的实际显示宽度"""
        # 判断是否为中文字符或其他双字节字符
        if '\u4e00' <= char <= '\u9fff' or \
                '\u3400' <= char <= '\u4dbf' or \
                '\uf900' <= char <= '\ufaff' or \
                '\u3040' <= char <= '\u309f' or \
                '\u30a0' <= char <= '\u30ff':
            return 2  # 中文字符占2个字符宽度
        else:
            return 1  # 英文字符占1个字符宽度

    @staticmethod
    def get_string_display_width(s):
        """获取字符串的实际显示宽度"""
        width = 0
        s = Colors.remove_color(s)
        for char in s:
            width += TablePrinter.get_char_width(char)
        return width

    @staticmethod
    def pad_string_with_chinese(s, target_width):
        """对字符串进行中英文混合填充"""
        current_width = TablePrinter.get_string_display_width(s)

        if current_width >= target_width:
            return s

        # 计算需要补充的空格数
        padding_needed = target_width - current_width
        return s + " " * padding_needed

    @staticmethod
    def print_table(headers: List[str], rows: List[List[str]], title: str = None):
        """打印表格"""
        if title:
            print(f"\n{Colors.header(title)}")

        if not rows:
            print(Colors.warning("  暂无数据"))
            return

        # 计算每列的最大显示宽度（考虑中英文混合）
        col_widths = []
        for i, header in enumerate(headers):
            # 表头宽度
            header_width = TablePrinter.get_string_display_width(header)
            max_width = header_width

            # 检查数据行中该列的最大宽度
            for row in rows:
                cell_width = TablePrinter.get_string_display_width(str(row[i]))
                max_width = max(max_width, cell_width)

            col_widths.append(max_width)

        # 打印表头
        header_parts = []
        for i, h in enumerate(headers):
            # 对表头进行填充，考虑中英文混合宽度
            padded_header = TablePrinter.pad_string_with_chinese(h, col_widths[i])
            header_parts.append(padded_header)

        header_line = " | ".join(header_parts)
        print(f"\n  {Colors.BOLD}{header_line}{Colors.ENDC}")
        print("  " + "-" * len(header_line.replace('\033', '')))  # 移除ANSI转义字符后计算长度

        # 打印数据行
        for row in rows:
            row_parts = []
            for i, cell in enumerate(row):
                padded_cell = TablePrinter.pad_string_with_chinese(str(cell), col_widths[i])
                row_parts.append(padded_cell)

            row_line = " | ".join(row_parts)
            print(f"  {row_line}")

        print()


# ============================================
# 网站管理模块
# ============================================
class SiteManager:
    """网站管理类"""
    
    def __init__(self):
        self.site_obj = panelSite.panelSite()
    
    def list_sites(self):
        """显示网站列表"""
        try:
            # 获取网站列表
            result = public.M('sites').field('id,name,path,status,ps,addtime').select()
            
            if not result:
                print(Colors.warning("暂无网站"))
                return
            
            # 准备表格数据
            headers = ["ID", "网站名称", "状态", "路径", "备注", "创建时间"]
            rows = []
            
            for site in result:
                status = Colors.success("运行中") if site['status'] == '1' else Colors.error("已停止")
                rows.append([
                    site['id'],
                    site['name'],
                    status,
                    site['path'][:40] + "..." if len(site['path']) > 40 else site['path'],
                    site.get('ps', '-')[:20],
                    site['addtime']
                ])
            
            TablePrinter.print_table(headers, rows, f"网站列表 (共 {len(rows)} 个)")
            
        except Exception as e:
            print(Colors.error(f"获取网站列表失败: {str(e)}"))
    
    def add_site(self, webname: dict, path: str = None, php_version: str = "00", **kwargs):
        """
        添加网站
        
        Args:
            webname: 域名
            path: 网站路径，默认为 /www/wwwroot/域名
            php_version: PHP版本，默认纯静态
            **kwargs: 其他参数（预留）
        """
        try:
            # 构造参数
            args = public.dict_obj()
            args.webname = json.dumps(webname)
            args.path = path
            args.type_id = 0
            args.type = 'PHP'
            args.version = php_version
            args.port = '80'
            args.ps = kwargs.get('ps', webname["domain"])
            args.ftp = kwargs.get('ftp', 'false')
            args.ftp_username = kwargs.get('ftp_username', '')
            args.ftp_password = kwargs.get('ftp_password', '')
            args.sql = kwargs.get('sql', 'false')
            args.codeing = kwargs.get('codeing', 'utf8mb4')
            args.datauser = kwargs.get('datauser', '')
            args.datapassword = kwargs.get('datapassword', '')
            
            result = self.site_obj.AddSite(args)
            
            if result.get('siteStatus'):
                print(Colors.success(f"✓ 网站创建成功: {webname['domain']}"))
                print(f"  路径: {path}")
            else:
                print(Colors.error(f"✗ 网站创建失败: {result.get('msg', '未知错误')}"))
                
        except Exception as e:
            print(Colors.error(f"添加网站失败: {str(e)}"))
    
    def delete_site(self, site_id: int = None, site_name: str = None, **kwargs):
        """
        删除网站
        
        Args:
            site_id: 网站ID
            site_name: 网站名称
            **kwargs: 其他参数，如 webname, ftp, database, path
        """
        try:
            # 如果提供的是网站名称，查询ID
            if site_name and not site_id:
                site_info = public.M('sites').where('name=?', (site_name,)).find()
                if not site_info:
                    print(Colors.error(f"网站不存在: {site_name}"))
                    return
                site_id = site_info['id']

            if site_id and not site_name:
                site_info = public.M('sites').where('id=?', (site_id,)).find()
                if not site_info:
                    print(Colors.error(f"网站不存在: {site_id}"))
                    return
                site_name = site_info['name']
            
            if not site_id and not site_name:
                print(Colors.error("请提供网站ID或网站名称"))
                return
            
            # 确认删除
            path_confirm = input(Colors.warning(f"是否删除网站目录)? [y/N]: "))
            if path_confirm.lower() != 'y':
                path_check = 0
            else:
                path_check = 1

            ftp_confirm = input(Colors.warning(f"是否删除FTP账户)? [y/N]: "))
            if ftp_confirm.lower() != 'y':
                ftp_check = 0
            else:
                ftp_check = 1

            database_confirm = input(Colors.warning(f"是否删除数据库)? [y/N]: "))
            if database_confirm.lower() != 'y':
                database_check = 0
            else:
                database_check = 1
            
            confirm = input(Colors.warning(f"确认删除网站 (ID: {site_id})? [y/N]: "))
            if confirm.lower() != 'y':
                print("已取消")
                return
            
            # 构造参数
            args = public.dict_obj()
            args.id = site_id
            args.webname = site_name
            args.ftp = ftp_check
            args.database = database_check
            args.path = path_check
            
            result = self.site_obj.DeleteSite(args)
            
            if result.get('status'):
                print(Colors.success(f"✓ 网站删除成功"))
            else:
                print(Colors.error(f"✗ 网站删除失败: {result.get('msg', '未知错误')}"))
                
        except Exception as e:
            print(Colors.error(f"删除网站失败: {str(e)}"))
    
    # ============ 预留功能接口 ============
    
    def backup_site(self, site_id: int):
        """备份网站（预留）"""
        print(Colors.warning("功能开发中..."))
    
    def restore_site(self, site_id: int, backup_file: str):
        """恢复网站（预留）"""
        print(Colors.warning("功能开发中..."))
    
    def edit_site(self, site_id: int, **kwargs):
        """修改网站配置（预留）"""
        print(Colors.warning("功能开发中..."))
    
    def add_proxy_site(self, domains: str, proxy_pass: str, proxy_host: str, proxy_type: str, remark: str):
        from mod.project.proxy.comMod import main as proxyMod
        pMod = proxyMod()

        args = public.dict_obj()
        args.domains = domains
        args.proxy_pass = proxy_pass
        args.proxy_host = proxy_host
        args.proxy_type = proxy_type
        args.remark = remark
        result = pMod.create(args)
        if result.get('status'):
            print(Colors.success(f"✓ 反代项目创建成功: {domains}"))
        else:
            print(Colors.error(f"✗ 反代项目创建失败: {result.get('msg', '未知错误')}"))


# ============================================
# 数据库管理模块
# ============================================
class DatabaseManager:
    """数据库管理类"""
    
    def __init__(self):
        self.db_obj = database.database()

    def get_mysql_status(self):
        if not os.path.exists("/www/server/mysql/bin/mysql"):
            return False
        args=public.dict_obj()
        args.sid = 0
        result = self.db_obj.CheckDatabaseStatus(args)
        if result.get('status'):
            return True
        else:
            return False
    
    def list_databases(self):
        """显示数据库列表"""
        try:
            result = public.M('databases').field('id,name,username,password,accept,ps,addtime').select()
            
            if not result:
                print(Colors.warning("暂无数据库"))
                return
            
            headers = ["ID", "数据库名", "用户名", "密码", "访问权限", "备注", "创建时间"]
            rows = []
            
            for db in result:
                # 密码打码显示
                password_masked = '*' * 8 if db.get('password') else '-'
                rows.append([
                    db['id'],
                    db['name'],
                    db['username'],
                    password_masked,
                    db.get('accept', 'localhost'),
                    db.get('ps', '-')[:15],
                    db['addtime']
                ])
            
            TablePrinter.print_table(headers, rows, f"数据库列表 (共 {len(rows)} 个)")
            
        except Exception as e:
            print(Colors.error(f"获取数据库列表失败: {str(e)}"))
    
    def add_database(self, db_name: str, password: str = None, **kwargs):
        """
        添加数据库
        
        Args:
            db_name: 数据库名
            password: 密码，不提供则自动生成
            **kwargs: 其他参数
        """
        try:
            # if not password:
            #     password = public.GetRandomString(16)
            
            # 构造参数
            args = public.dict_obj()
            args.name = db_name
            args.codeing = kwargs.get('codeing', 'utf8mb4')
            args.db_user = kwargs.get('db_user', db_name)
            args.password = password
            args.address = kwargs.get('address', '127.0.0.1')
            args.ps = kwargs.get('ps', db_name)
            args.sid = kwargs.get('sid', 0)
            
            result = self.db_obj.AddDatabase(args)
            
            if result.get('status'):
                print(Colors.success(f"✓ 数据库创建成功: {db_name}"))
                print(f"  用户名: {db_name}")
                print(f"  密码: {password}")
            else:
                print(Colors.error(f"✗ 数据库创建失败: {result.get('msg', '未知错误')}"))
                
        except Exception as e:
            print(Colors.error(f"添加数据库失败: {str(e)}"))
    
    def delete_database(self, db_id: int = None, db_name: str = None):
        """
        删除数据库
        
        Args:
            db_id: 数据库ID
            db_name: 数据库名称
        """
        try:
            # 如果提供的是数据库名称，查询ID
            if db_name and not db_id:
                db_info = public.M('databases').where('name=?', (db_name,)).find()
                if not db_info:
                    print(Colors.error(f"数据库不存在: {db_name}"))
                    return
                db_id = db_info['id']
            
            if not db_id:
                print(Colors.error("请提供数据库ID或数据库名称"))
                return
            
            # 确认删除
            confirm = input(Colors.warning(f"确认删除数据库 (ID: {db_id})? [y/N]: "))
            if confirm.lower() != 'y':
                print("已取消")
                return
            
            # 构造参数
            args = public.dict_obj()
            args.id = db_id
            args.name = db_name or db_id
            
            result = self.db_obj.DeleteDatabase(args)
            
            if result.get('status'):
                print(Colors.success(f"✓ 数据库删除成功"))
            else:
                print(Colors.error(f"✗ 数据库删除失败: {result.get('msg', '未知错误')}"))
                
        except Exception as e:
            print(Colors.error(f"删除数据库失败: {str(e)}"))

    def get_database_password(self, db_id: int = None, db_name: str = None):
        """
        获取数据库密码
        
        Args:
            db_id: 数据库ID
            db_name: 数据库名称
        """
        try:
            if db_name and not db_id:
                db_info = public.M('databases').where('name=?', (db_name,)).find()
                if not db_info:
                    print(Colors.error(f"数据库不存在: {db_name}"))
                    return
                db_id = db_info['id']

            if not db_id:
                print(Colors.error("请提供数据库ID或数据库名称"))
                return

            db_info = public.M('databases').where('id=?', (db_id,)).find()
            if not db_info:
                print(Colors.error(f"数据库不存在: {db_id}"))
                return
            print("")
            print(Colors.success(f"✓ 数据库密码获取成功"))
            print(f"  密码: {db_info['password']}")
        except Exception as e:
            print(Colors.error(f"获取数据库密码失败: {str(e)}"))

    # ============ 预留功能接口 ============
    
    def backup_database(self, db_id: int):
        """备份数据库（预留）"""
        print(Colors.warning("功能开发中..."))
    
    def change_password(self, db_id: int, new_password: str):
        """修改数据库密码（预留）"""
        print(Colors.warning("功能开发中..."))


# ============================================
# FTP管理模块
# ============================================
class FTPManager:
    """FTP管理类"""
    
    def __init__(self):
        self.ftp_obj = ftp.ftp()

    def get_ftp_status(slef):
        if not os.path.exists("/www/server/pure-ftpd/bin/pure-pw"):
            return False
        result = public.ExecShell("ps -ef|grep pure-ftpd|grep -v grep")[0].strip()
        if not "pure-ftpd" in result:
            return False
        else:
            return True
    
    def list_ftp(self):
        """显示FTP列表"""
        try:
            result = public.M('ftps').field('id,name,path,status,ps,addtime').select()
            
            if not result:
                print(Colors.warning("暂无FTP账户"))
                return
            
            headers = ["ID", "FTP用户名", "状态", "路径", "备注", "创建时间"]
            rows = []
            
            for ftp_user in result:
                status = Colors.success("正常") if ftp_user['status'] == '1' else Colors.error("已禁用")
                rows.append([
                    ftp_user['id'],
                    ftp_user['name'],
                    status,
                    ftp_user['path'][:40] + "..." if len(ftp_user['path']) > 40 else ftp_user['path'],
                    ftp_user.get('ps', '-')[:20],
                    ftp_user['addtime']
                ])
            
            TablePrinter.print_table(headers, rows, f"FTP账户列表 (共 {len(rows)} 个)")
            
        except Exception as e:
            print(Colors.error(f"获取FTP列表失败: {str(e)}"))
    
    def add_ftp(self, username: str, password: str, path: str, **kwargs):
        """
        添加FTP账户
        
        Args:
            username: FTP用户名
            password: 密码
            path: FTP根目录
            **kwargs: 其他参数
        """
        try:
            # 构造参数
            args = public.dict_obj()
            args.ftp_username = username
            args.ftp_password = password
            args.path = path
            args.ps = kwargs.get('ps', username)
            
            result = self.ftp_obj.AddUser(args)
            
            if result.get('status'):
                print(Colors.success(f"✓ FTP账户创建成功: {username}"))
                print(f"  路径: {path}")
            else:
                print(Colors.error(f"✗ FTP账户创建失败: {result.get('msg', '未知错误')}"))
                
        except Exception as e:
            print(Colors.error(f"添加FTP账户失败: {str(e)}"))
    
    def delete_ftp(self, ftp_id: int = None, ftp_username: str = None):
        """
        删除FTP账户
        
        Args:
            ftp_id: FTP ID
            ftp_username: FTP用户名
        """
        try:
            # 如果提供的是用户名，查询ID
            if ftp_username and not ftp_id:
                ftp_info = public.M('ftps').where('name=?', (ftp_username,)).find()
                if not ftp_info:
                    print(Colors.error(f"FTP账户不存在: {ftp_username}"))
                    return
                ftp_id = ftp_info['id']
            
            if not ftp_id:
                print(Colors.error("请提供FTP ID或用户名"))
                return
            
            # 确认删除
            confirm = input(Colors.warning(f"确认删除FTP账户 (ID: {ftp_id})? [y/N]: "))
            if confirm.lower() != 'y':
                print("已取消")
                return
            
            # 构造参数
            args = public.dict_obj()
            args.id = ftp_id
            args.username = ftp_username or ftp_id
            
            result = self.ftp_obj.DeleteUser(args)
            
            if result.get('status'):
                print(Colors.success(f"✓ FTP账户删除成功"))
            else:
                print(Colors.error(f"✗ FTP账户删除失败: {result.get('msg', '未知错误')}"))
                
        except Exception as e:
            print(Colors.error(f"删除FTP账户失败: {str(e)}"))
    
    # ============ 预留功能接口 ============
    
    def change_password(self, ftp_id: int, new_password: str):
        """修改FTP密码（预留）"""
        print(Colors.warning("功能开发中..."))
    
    def set_status(self, ftp_id: int, status: bool):
        """启用/禁用FTP账户（预留）"""
        print(Colors.warning("功能开发中..."))


# ============================================
# 交互式菜单
# ============================================
class InteractiveMenu:
    """交互式菜单"""
    
    def __init__(self):
        self.site_mgr = SiteManager()
        self.db_mgr = DatabaseManager()
        self.ftp_mgr = FTPManager()
    
    def show_main_menu(self):
        """显示主菜单"""
        while True:
            print("\n" + "="*60)
            print(Colors.header("     BT-CLI 宝塔面板命令行管理工具 v1.0.0"))
            print("="*60)
            print()
            print(Colors.info("  [ 操作说明 ]"))
            print("  " + "-" * 56)
            print("     * 输入对应数字选择功能")
            print("     * 按回车键(Enter)确认并执行操作")
            print("     * 按Ctrl+BackSpace删除上一个字符")
            print("     * 按Ctrl+D可退出程序")
            print("  " + "-" * 56)
            print(Colors.info("  [ 功能菜单 ]"))
            print("  " + "-" * 56)
            
            if os.path.exists("/www/server/nginx/sbin/nginx"):
                print("     [1] 网站管理      - 创建/删除网站、配置反向代理")
            else:
                print("     [X] 网站管理      - 未安装Nginx，请先登录面板安装")
            if os.path.exists("/www/server/mysql/bin/mysql"):
                print("     [2] 数据库管理    - 添加/删除MySQL数据库")
            else:
                print("     [X] 数据库管理    - 未安装MySQL，请先登录面板安装")
            if os.path.exists("/www/server/pure-ftpd/bin/pure-pw"):
                print("     [3] FTP管理       - 创建/删除FTP账户")
            else:
                print("     [X] FTP管理       - 未安装FTP，请先登录面板安装")
            print()
            print("     [0] 退出程序")
            print("  " + "-" * 56)
            print("="*60)
            
            choice = input("\n请选择操作类型 [0-3]: ").strip()
            
            if choice == '1':
                self.site_menu()
            elif choice == '2':
                self.database_menu()
            elif choice == '3':
                self.ftp_menu()
            elif choice == '0':
                print(Colors.success("再见 :-)"))
                break
            else:
                print(Colors.error("无效的选择，请重新输入"))
    
    def site_menu(self):
        """网站管理菜单"""
        while True:
            print("\n" + "-"*50)
            print(Colors.info("  网站管理"))
            print("-"*50)
            print("  1. 显示网站列表")
            print("  2. 添加网站[PHP项目]")
            print("  3. 添加网站[反代项目]")
            print("  4. 删除网站")
            print("  0. 返回上级")
            print("-"*50)
            
            choice = input("\n请选择操作 [0-4]: ").strip()
            
            if choice == '1':
                self.site_mgr.list_sites()
            elif choice == '2':
                print(Colors.info("\n=== 添加网站[PHP项目] ==="))
                domains =  input("域名 (必填，如有多个域名请用空格隔开): ").strip()

                if not domains:
                    print(Colors.error("域名不能为空"))
                    continue

                domain_list = domains.split(" ")
                domain = domain_list[0]
                domain_list = domain_list[1:]
                domain_count = len(domain_list)
            
                webname={}
                webname["domain"] = domain
                webname["domainlist"] = domain_list
                webname["count"] = domain_count

                path = input(f"网站路径 (回车使用默认：/www/wwwroot/{domain}):").strip()
                if not path:
                    path = f"/www/wwwroot/{domain}"
                
                print("\nPHP版本选择:")

                print("  00 - 纯静态")
                php_version_list = [
                    "00",
                    "52",
                    "53",
                    "54",
                    "55",
                    "56",
                    "70",
                    "71",
                    "72",
                    "73",
                    "74",
                    "80",
                    "81",
                    "82",
                    "83"
                    "84",
                    "85",
                    "86"
                ]
                for php_version in php_version_list:
                    if os.path.exists(f"/www/server/php/{php_version}/bin/php"):
                        print(f"  {php_version} - PHP {php_version}")
                php_version = input("PHP版本 (请输入数字，如70即PHP7.0): ").strip() or "00"
                
                if self.ftp_mgr.get_ftp_status():
                    create_ftp = input("是否创建FTP账户? [y/N]: ").strip().lower()
                    ftp_username = ""
                    ftp_password = ""
                    if create_ftp == 'y':
                        ftp_username = input("  FTP用户名: ").strip()
                        ftp_password = input("  FTP密码: ").strip()
                else:
                    create_ftp = 'N'
                    ftp_username = ""
                    ftp_password = ""
                
                if self.db_mgr.get_mysql_status():
                    create_db = input("是否创建数据库? [y/N]: ").strip().lower()
                    db_name = ""
                    db_password = ""
                    if create_db == 'y':
                        db_name = input("  数据库名: ").strip()
                        db_password = input("  数据库密码 (留空自动生成): ").strip()
                else:
                    db_name = ""
                    db_password = ""
                    create_db = 'N'
                
                ps = input("备注 (默认: 域名): ").strip() or domain
                
                # 构造参数
                kwargs = {
                    'ps': ps,
                    'ftp': 'true' if create_ftp == 'y' else 'false',
                    'ftp_username': ftp_username,
                    'ftp_password': ftp_password,
                    'sql': 'true' if create_db == 'y' else 'false',
                    'datauser': db_name,
                    'datapassword': db_password,
                }
                
                self.site_mgr.add_site(webname, path, php_version, **kwargs)
            elif choice == '3':
                print(Colors.info("\n=== 添加网站[反代项目] ==="))
                print("请输入域名（每行一个，空行结束）:")

                domains =  input("域名 (必填，如有多个域名请用空格隔开): ").strip()
                if not domains:
                    print(Colors.error("域名不能为空"))
                    continue
                domain_list = domains.split(" ")
                domains = "\n".join(domains.split())

                # lines = []
                # domain_list = []
                # while True:
                #     line = input().strip()
                #     if not line:   # 空行结束输入
                #         break
                #     lines.append(line)
                #     domain_list.append(line)
                # domains = "\n".join(lines) + "\n" if lines else ""
                
                first_domain = domain_list[0]

                print("反代地址(proxy_pass), http://或https://开头 ")
                proxy_pass=input("开始输入: ").strip()
                if not proxy_pass:
                    print(Colors.error("反代地址不能为空"))
                    continue
                if not proxy_pass.startswith("http://") and not proxy_pass.startswith("https://"):
                    print(Colors.error("反代地址必须以http://或https://开头"))
                    continue
              
                print("发送域名(proxy_host), 默认$http_host " )
                proxy_host=input("开始输入: ").strip() or "$http_host"
                proxy_type="http"
                remark=input(f"备注(默认 {first_domain}): ").strip() or first_domain

                self.site_mgr.add_proxy_site(domains=domains, proxy_pass=proxy_pass, proxy_host=proxy_host, proxy_type=proxy_type, remark=remark)
                
            
            elif choice == '4':
                site_name = input("请输入网站名称或ID: ").strip()
                if site_name:
                    if site_name.isdigit():
                        self.site_mgr.delete_site(site_id=int(site_name))
                    else:
                        self.site_mgr.delete_site(site_name=site_name)
            elif choice == '0':
                break
            else:
                print(Colors.error("无效的选择"))
    
    def database_menu(self):
        """数据库管理菜单"""
        while True: 
            print("\n" + "-"*50)
            print(Colors.info("  数据库管理"))
            print("-"*50)
            print("  1. 显示数据库列表")
            print("  2. 添加数据库")
            print("  3. 删除数据库")
            print("  4. 获取数据库密码")
            print("  5. 获取root密码")
            print("  0. 返回上级")
            print("-"*50)
            
            choice = input("\n请选择操作 [0-3]: ").strip()
            
            if choice == '1':
                self.db_mgr.list_databases()
            elif choice == '2':
                mysql_status = self.db_mgr.get_mysql_status()
                if not mysql_status:
                    print(Colors.error("MySQL服务未启动,请先登录面板开启MySQL服务后再执行操作"))
                    print(Colors.error("或手动执行 /etc/init.d/mysqld start 启动后再尝试"))
                    continue
                print(Colors.info("\n=== 添加数据库 ==="))
                db_name = input("数据库名 (必填): ").strip()
                if not db_name:
                    print(Colors.error("数据库名不能为空"))
                    continue
                
                db_user = input(f"数据库用户名 (默认: {db_name}): ").strip() or db_name

                default_password = public.GetRandomString(16)
                password = input(f"数据库密码 (留空自动生成: {default_password}) : ").strip() or default_password
                
                print("\n字符编码选择:")
                print("  1. utf8mb4 (推荐，支持emoji)")
                print("  2. utf8")
                print("  3. gbk")
                print("  4. latin1")
                coding_choice = input("编码 (默认: 1): ").strip() or "1"
                codeing_map = {"1": "utf8mb4", "2": "utf8", "3": "gbk", "4": "latin1"}
                codeing = codeing_map.get(coding_choice, "utf8mb4")
                
                address = input("访问权限 (默认: 127.0.0.1, 本地访问): ").strip() or "127.0.0.1"
                ps = input("备注 (默认: 数据库名): ").strip() or db_name
                
                # 构造参数
                kwargs = {
                    'db_user': db_user,
                    'codeing': codeing,
                    'address': address,
                    'ps': ps,
                }
                print(db_name, password, kwargs)
                self.db_mgr.add_database(db_name, password, **kwargs)
                
            elif choice == '3':
                mysql_status = self.db_mgr.get_mysql_status()
                if not mysql_status:
                    print(Colors.error("MySQL服务未启动,请先登录面板开启MySQL服务后再执行操作"))
                    print(Colors.error("或手动执行 /etc/init.d/mysqld start 启动后再尝试"))
                    continue
                db_name = input("请输入数据库名称或ID: ").strip()
                if db_name:
                    if db_name.isdigit():
                        self.db_mgr.delete_database(db_id=int(db_name))
                    else:
                        self.db_mgr.delete_database(db_name=db_name)
            elif choice == '4':
                db_name = input("请输入数据库名称或ID: ").strip()
                if db_name:
                    if db_name.isdigit():
                        self.db_mgr.get_database_password(db_id=int(db_name))
                    else:
                        self.db_mgr.get_database_password(db_name=db_name)
            elif choice == '5':
                import data
                args = public.dict_obj()
                args.table="config"
                args.id  = 1
                args.key="mysql_root"
                mysql_info = data.data().getKey(args)
                print("")
                print(Colors.success(f"✓ root密码获取成功"))
                print(f"  密码: {mysql_info}")
            elif choice == '0':
                break
            else:
                print(Colors.error("无效的选择"))
    
    def ftp_menu(self):
        """FTP管理菜单"""
        while True:
            print("\n" + "-"*50)
            print(Colors.info("  FTP管理"))
            print("-"*50)
            print("  1. 显示FTP列表")
            print("  2. 添加FTP账户")
            print("  3. 删除FTP账户")
            print("  0. 返回上级")
            print("-"*50)
            
            choice = input("\n请选择操作 [0-3]: ").strip()
            
            if choice == '1':
                self.ftp_mgr.list_ftp()
            elif choice == '2':
                ftp_status = self.ftp_mgr.get_ftp_status()
                if not ftp_status:
                    print(Colors.error("FTP服务未启动,请先登录面板开启FTP服务后再执行操作"))
                    print(Colors.error("或手动执行 /etc/init.d/pure-ftpd start 启动后再尝试"))
                    continue

                print(Colors.info("\n=== 添加FTP账户 ==="))
                username = input("FTP用户名 (必填): ").strip()
                if not username:
                    print(Colors.error("FTP用户名不能为空"))
                    continue
                
                password = input("FTP密码 (必填): ").strip()
                if not password:
                    print(Colors.error("FTP密码不能为空"))
                    continue
                
                if len(password) < 6:
                    print(Colors.error("FTP密码长度不能少于6位"))
                    continue
                
                path = input(f"FTP根目录 (回车使用默认：/www/wwwroot/{username}): ").strip() or f"/www/wwwroot/{username}"
                # if not path:
                #     print(Colors.error("FTP根目录不能为空"))
                #     continue
                
                ps = input("备注 (默认: 用户名): ").strip() or username
                
                # 构造参数
                kwargs = {'ps': ps}
                
                self.ftp_mgr.add_ftp(username, password, path, **kwargs)
                
            elif choice == '3':
                ftp_status = self.ftp_mgr.get_ftp_status()
                if not ftp_status:
                    print(Colors.error("FTP服务未启动,请先登录面板开启FTP服务后再执行操作"))
                    print(Colors.error("或手动执行 /etc/init.d/pure-ftpd start 启动后再尝试"))
                    continue
                ftp_user = input("请输入FTP用户名或ID: ").strip()
                if ftp_user:
                    if ftp_user.isdigit():
                        self.ftp_mgr.delete_ftp(ftp_id=int(ftp_user))
                    else:
                        self.ftp_mgr.delete_ftp(ftp_username=ftp_user)
            elif choice == '0':
                break
            else:
                print(Colors.error("无效的选择"))


# ============================================
# 命令行解析器
# ============================================
def create_parser():
    """创建命令行参数解析器"""
    parser = argparse.ArgumentParser(
        description='BT-CLI - 宝塔面板命令行管理工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  交互模式:
    bt-cli
  
  网站管理:
    bt-cli site show                                    # 显示网站列表
    bt-cli site add example.com                         # 添加纯静态网站
    bt-cli site add example.com --php 74                # 添加PHP 7.4网站
    bt-cli site add example.com --path /data/www        # 指定网站路径
    bt-cli site add example.com --ftp-user ftpuser --ftp-pass pass123  # 同时创建FTP
    bt-cli site add example.com --db-name mydb --db-pass dbpass123      # 同时创建数据库
    bt-cli site del 1                                   # 删除网站(ID)
    bt-cli site del example.com                         # 删除网站(名称)
  
  数据库管理:
    bt-cli database show                                # 显示数据库列表
    bt-cli database add mydb                            # 添加数据库(自动生成密码)
    bt-cli database add mydb --password pass123         # 添加数据库(指定密码)
    bt-cli database add mydb --user dbuser --encoding utf8  # 指定用户名和编码
    bt-cli database del mydb                            # 删除数据库
  
  FTP管理:
    bt-cli ftp show                                     # 显示FTP列表
    bt-cli ftp add user1 pass123 /www/wwwroot           # 添加FTP账户
    bt-cli ftp add user1 pass123 /www/wwwroot --ps "测试FTP"  # 添加FTP并备注
    bt-cli ftp del user1                                # 删除FTP账户
        """
    )
    
    subparsers = parser.add_subparsers(dest='module', help='管理模块')
    
    # 网站管理子命令
    site_parser = subparsers.add_parser('site', help='网站管理')
    site_subparsers = site_parser.add_subparsers(dest='action', help='操作类型')
    
    site_subparsers.add_parser('show', help='显示网站列表')
    site_add = site_subparsers.add_parser('add', help='添加网站')
    site_add.add_argument('domain', help='域名')
    site_add.add_argument('--path', help='网站路径 (默认: /www/wwwroot/域名)')
    site_add.add_argument('--php', default='00', help='PHP版本 (默认: 00 纯静态)')
    site_add.add_argument('--ps', help='备注')
    site_add.add_argument('--ftp-user', help='创建FTP用户名')
    site_add.add_argument('--ftp-pass', help='创建FTP密码')
    site_add.add_argument('--db-name', help='创建数据库名称')
    site_add.add_argument('--db-pass', help='创建数据库密码')
    
    site_del = site_subparsers.add_parser('del', help='删除网站')
    site_del.add_argument('site', help='网站ID或名称')
    
    # 数据库管理子命令
    db_parser = subparsers.add_parser('database', help='数据库管理')
    db_subparsers = db_parser.add_subparsers(dest='action', help='操作类型')
    
    db_subparsers.add_parser('show', help='显示数据库列表')
    db_add = db_subparsers.add_parser('add', help='添加数据库')
    db_add.add_argument('name', help='数据库名')
    db_add.add_argument('--password', help='密码 (不指定则自动生成)')
    db_add.add_argument('--user', help='数据库用户名 (默认: 数据库名)')
    db_add.add_argument('--encoding', default='utf8mb4', help='字符编码 (默认: utf8mb4)')
    db_add.add_argument('--address', default='127.0.0.1', help='访问权限 (默认: 127.0.0.1)')
    db_add.add_argument('--ps', help='备注')
    
    db_del = db_subparsers.add_parser('del', help='删除数据库')
    db_del.add_argument('database', help='数据库ID或名称')
    
    # FTP管理子命令
    ftp_parser = subparsers.add_parser('ftp', help='FTP管理')
    ftp_subparsers = ftp_parser.add_subparsers(dest='action', help='操作类型')
    
    ftp_subparsers.add_parser('show', help='显示FTP列表')
    ftp_add = ftp_subparsers.add_parser('add', help='添加FTP账户')
    ftp_add.add_argument('username', help='FTP用户名')
    ftp_add.add_argument('password', help='FTP密码')
    ftp_add.add_argument('path', help='FTP根目录')
    ftp_add.add_argument('--ps', help='备注')
    
    ftp_del = ftp_subparsers.add_parser('del', help='删除FTP账户')
    ftp_del.add_argument('ftp', help='FTP ID或用户名')
    
    return parser


# ============================================
# 主程序
# ============================================
def main():
    """主程序入口"""
    parser = create_parser()
    args = parser.parse_args()
    
    # 检查是否为root用户
    if os.geteuid() != 0:
        print(Colors.error("错误: 此工具需要root权限运行"))
        print("请使用: sudo bt-cli")
        sys.exit(1)
    
    # 如果没有参数，进入交互模式
    if not args.module:
        try:
            menu = InteractiveMenu()
            menu.show_main_menu()
        except KeyboardInterrupt:
            print("\n")
            print(Colors.info("再见 :-)"))
            sys.exit(0)
        except Exception as e:
            print(Colors.error(f"错误: {e}"))
            sys.exit(1)
        return
    
    # 命令行模式
    site_mgr = SiteManager()
    db_mgr = DatabaseManager()
    ftp_mgr = FTPManager()
    
    try:
        if args.module == 'site':
            if args.action == 'show':
                site_mgr.list_sites()
            elif args.action == 'add':
                # 构造参数
                kwargs = {}
                if args.ps:
                    kwargs['ps'] = args.ps
                
                # 处理FTP创建
                if args.ftp_user and args.ftp_pass:
                    kwargs['ftp'] = 'true'
                    kwargs['ftp_username'] = args.ftp_user
                    kwargs['ftp_password'] = args.ftp_pass
                else:
                    kwargs['ftp'] = 'false'
                
                # 处理数据库创建
                if args.db_name:
                    kwargs['sql'] = 'true'
                    kwargs['datauser'] = args.db_name
                    kwargs['datapassword'] = args.db_pass or ''
                else:
                    kwargs['sql'] = 'false'
                
                site_mgr.add_site(args.domain, args.path, args.php, **kwargs)
            elif args.action == 'del':
                if args.site.isdigit():
                    site_mgr.delete_site(site_id=int(args.site))
                else:
                    site_mgr.delete_site(site_name=args.site)
        
        elif args.module == 'database':
            if args.action == 'show':
                db_mgr.list_databases()
            elif args.action == 'add':
                # 构造参数
                kwargs = {}
                if args.user:
                    kwargs['db_user'] = args.user
                if args.encoding:
                    kwargs['codeing'] = args.encoding
                if args.address:
                    kwargs['address'] = args.address
                if args.ps:
                    kwargs['ps'] = args.ps
                
                db_mgr.add_database(args.name, args.password, **kwargs)
            elif args.action == 'del':
                if args.database.isdigit():
                    db_mgr.delete_database(db_id=int(args.database))
                else:
                    db_mgr.delete_database(db_name=args.database)
        
        elif args.module == 'ftp':
            if args.action == 'show':
                ftp_mgr.list_ftp()
            elif args.action == 'add':
                # 构造参数
                kwargs = {}
                if args.ps:
                    kwargs['ps'] = args.ps
                
                ftp_mgr.add_ftp(args.username, args.password, args.path, **kwargs)
            elif args.action == 'del':
                if args.ftp.isdigit():
                    ftp_mgr.delete_ftp(ftp_id=int(args.ftp))
                else:
                    ftp_mgr.delete_ftp(ftp_username=args.ftp)
    
    except KeyboardInterrupt:
        print(Colors.warning("\n\n操作已取消"))
        sys.exit(0)
    except Exception as e:
        print(Colors.error(f"\n执行出错: {str(e)}"))
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()