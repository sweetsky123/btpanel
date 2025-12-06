# coding: utf-8
# +-------------------------------------------------------------------
# | 宝塔Linux面板
# +-------------------------------------------------------------------
# | Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
# +-------------------------------------------------------------------
# | Author: lwh <2023-07-24>
# +-------------------------------------------------------------------
# 首页安全风险导出检测报告
# ------------------------------
import datetime
import json
import os
import sys

from safeModel.base import safeBase

os.chdir("/www/server/panel")
sys.path.append("class/")
import os, public, config, time
try:
    from docxtpl import DocxTemplate
    from docxtpl import RichText
except:
    public.ExecShell("btpip install docxtpl")
    time.sleep(2)
    from docxtpl import DocxTemplate
    from docxtpl import RichText


class main(safeBase):
    __path = '/www/server/panel/data/warning_report'
    __img = __path + '/img'
    __tpl = '/www/server/panel/class/safeModel/tpl.docx'
    __data = __path + '/data.json'
    new_result = "/www/server/panel/data/warning/resultresult.json"
    all_cve = 0
    cve_num = 0
    high_cve = 0
    mid_cve = 0
    low_cve = 0
    cve_list = []
    high_warn = 0
    mid_warn = 0
    low_warn = 0
    high_warn_list = []
    mid_warn_list = []
    low_warn_list = []
    auto_fix = []  # 自动修复列表
    final_obj = {}  # 文档数据填充
    def __init__(self):
        self.configs = config.config()
        if not os.path.exists(self.__path):
            os.makedirs(self.__path, 384)

    def validate_input_data(data, required_keys):
        """
            验证参数正确性：验证输入数据是否包含必需的字段，减少生成报告异常问题情况发生
        """
        if not isinstance(data, dict):
            return False
        for key in required_keys:
            if key not in data:
                return False
        return True

    def get_pdf(self, get):
        """
        @description 加载数据 -> 统计数据 -> 生成报告
        """
        public.set_module_logs("exportreport", "get_pdf")
        self.cve_list = []
        self.high_warn_list = []
        self.mid_warn_list = []
        self.low_warn_list = []
        # 加载扫描结果
        if not os.path.exists(self.new_result):
            return public.returnMsg(False, '导出失败，未发现扫描结果')
        try:
            data = json.loads(public.readFile(self.new_result))
        except Exception as e:
            return public.returnMsg(False, f"解析扫描结果失败: {e}")
        if "risk" not in data:
            return public.returnMsg(False, "未找到risk字段")
        # 加载目录和填充数据
        tpl = DocxTemplate(self.__tpl)
        long_date = data["check_time"]  # 带有时间的检测日期
        self.final_obj["host"] = public.get_hostname()  # 主机名
        self.final_obj["ip"] = public.get_server_ip()  # 外网IP
        self.final_obj["local_ip"] = public.GetLocalIp()  # 内网IP
        date_obj = datetime.datetime.strptime(long_date, "%Y/%m/%d %H:%M:%S")
        self.final_obj["date"] = date_obj.strftime("%Y/%m/%d")
        self.final_obj["last_date"] = (date_obj - datetime.timedelta(days=6)).strftime("%Y/%m/%d")
        self.total(data)  # 整体安全评级
        self.secondPage(date_obj)  # 安全态势-持续服务
        self.thirdPage()  # 风险概览
        self.focusPage(data)  # 重点关注风险
        self.lowPage(data)  # 潜在风险
        # 生成 Word 文档
        try:
            tpl.render(self.final_obj)
            tpl.save(self.__path + '/堡塔安全风险检测报告.docx')
        except KeyError as e:
            return public.returnMsg(False, f"导出失败：{e}")

        return {"status": True, "msg": "导出成功", "path": self.__path + '/堡塔安全风险检测报告.docx'}


    def get_level_reason(self, level):
        """
        根据等级返回描述信息
        """
        reasons = {
            "差": "服务器存在高危安全风险或系统漏洞，可能会导致黑客入侵，请尽快修复！",
            "良": "服务器发现潜在的安全风险，建议尽快修复！",
            "优": "服务器未发现较大的安全风险，继续保持！"
        }
        return reasons.get(level, "未知状态")

    def total(self, cve_result):
        """
        @name 整体安全评级-数据填充
        @authore lwh<2024-01-30>
        """
        for risk in cve_result["risk"]:
            # 若为漏洞
            if risk["title"].startswith("CVE") or risk["title"].startswith("RH"):
                self.cve_list.append(risk)
                self.cve_num += 1
                if risk["level"] == 3:
                    self.high_cve += 1
                elif risk["level"] == 2:
                    self.mid_cve += 1
                elif risk["level"] == 1:
                    self.low_cve += 1
                else:
                    self.cve_num -= 1
                    continue
            # 其余为风险
            else:
                if risk["level"] == 3:
                    self.high_warn += 1
                    self.high_warn_list.append(risk)
                elif risk["level"] == 2:
                    self.mid_warn += 1
                    self.mid_warn_list.append(risk)
                elif risk["level"] == 1:
                    self.low_warn += 1
                    self.low_warn_list.append(risk)
                else:
                    continue
        # 更新最终的统计结果和颜色等级
        if self.high_warn + self.high_cve > 1:
            total_level = '差'
            level_color = RichText('差', font='Microsoft YaHei', color='ff0000', size=120, bold=True)
        elif self.mid_warn + self.mid_cve > 10 or self.high_warn + self.high_cve == 1:
            total_level = '良'
            level_color = RichText('良', font='Microsoft YaHei', color='6d9eeb', size=120, bold=True)
        else:
            total_level = '优'
            level_color = RichText('优', font='Microsoft YaHei', color='6aa84f', size=120, bold=True)

        self.cve_num = self.high_cve + self.mid_cve + self.low_cve
        level_reason = "服务器未发现较大的安全风险，继续保持！"
        if total_level == "差":
            level_reason = "服务器存在高危安全风险或系统漏洞，可能会导致黑客入侵，请尽快修复！"
        if total_level == "良":
            level_reason = "服务器发现潜在的安全风险，建议尽快修复！"
        warn_level = RichText('优', color='6aa84f', font='微软雅黑', size=34)
        first_warn = ""
        if self.high_warn > 0:
            warn_level = RichText('差', color='ff0000', font='微软雅黑', size=34)
            first_warn = "发现高危安全风险{}个".format(self.high_warn)
        elif self.mid_warn > 5:
            warn_level = RichText('良', color='6d9eeb', font='微软雅黑', size=34)
            first_warn = "发现较多中危安全风险"
        else:
            first_warn = "未发现较大的安全风险"
        cve_level = RichText('优', color='6aa84f', font='微软雅黑', size=34)
        first_cve = ""
        if self.cve_num > 1:
            cve_level = RichText('差', color='ff0000', font='微软雅黑', size=34)
            first_cve = "发现较多系统漏洞{}个".format(self.cve_num)
        elif self.cve_num == 1:
            cve_level = RichText('良', color='6d9eeb', font='微软雅黑', size=34)
            first_cve = "发现少量系统漏洞"
        else:
            first_cve = "未发现存在系统漏洞"
        self.final_obj["level_color"] = level_color
        self.final_obj["total_level"] = total_level
        self.final_obj["level_reason"] = level_reason
        self.final_obj["warn_level"] = warn_level
        self.final_obj["first_warn"] = first_warn
        self.final_obj["cve_level"] = cve_level
        self.final_obj["first_cve"] = first_cve

    def secondPage(self, date_obj):
        """
        @description 安全态势-持续服务 数据填充
        @param null
        @return
        """
        with open(self.__path + "/record.json", "r") as f:
            record = json.load(f)
        warn_times = 0
        repair_times = 0
        for r in record["scan"]:
            warn_times += r["times"]
        for r in record["repair"]:
            repair_times += r["times"]
        self.final_obj["warn_times"] = warn_times
        self.final_obj["cve_times"] = warn_times
        self.final_obj["repair_times"] = repair_times
        self.final_obj["last_month"] = (date_obj - datetime.timedelta(days=6)).strftime("%m")
        self.final_obj["last_day"] = (date_obj - datetime.timedelta(days=6)).strftime("%d")
        self.final_obj["month"] = date_obj.strftime("%m")
        self.final_obj["day"] = date_obj.strftime("%d")
        self.final_obj["second_warn"] = "每日登陆面板，例行服务器安全风险检测。"
        if self.cve_num > 0:
            self.final_obj["second_cve"] = "对系统内核版本以及流行应用进行漏洞扫描，发现存在漏洞风险。"
        else:
            self.final_obj["second_cve"] = "对系统内核版本以及流行应用进行漏洞扫描，未发现漏洞风险。"
        self.final_obj["repair"] = "执行一键修复，解决安全问题。"

    def thirdPage(self):
        """
        @description 风险概览-数据填充
        """
        self.final_obj["warn_num"] = len(self.high_warn_list)
        self.final_obj["cve_num"] = self.cve_num
        self.final_obj["web_num"] = 41
        self.final_obj["sys_num"] = 29
        self.final_obj["cve_num"] = 5599
        self.final_obj["kernel_num"] = 5

        self.final_obj["high_cve"] = RichText(str(self.high_cve) + "个", font='Microsoft YaHei', color='ff0000',
                                              size=41)
        if self.high_cve == 0:
            self.final_obj["high_cve"] = "未发现"
        self.final_obj["mid_cve"] = RichText(str(self.mid_cve) + "个", font='Microsoft YaHei', color='ff9900', size=41)
        if self.mid_cve == 0:
            self.final_obj["mid_cve"] = "未发现"
        self.final_obj["low_cve"] = RichText(str(self.low_cve) + "个", font='Microsoft YaHei', color='ecec39', size=41)
        if self.low_cve == 0:
            self.final_obj["low_cve"] = "未发现"
        self.final_obj["high_warn"] = RichText(str(self.high_warn) + "个", font='Microsoft YaHei', color='ff0000',
                                               size=41)
        if self.high_warn == 0:
            self.final_obj["high_warn"] = "无"
        self.final_obj["mid_warn"] = RichText(str(self.mid_warn) + "个", font='Microsoft YaHei', color='ff9900',
                                              size=41)
        if self.mid_warn == 0:
            self.final_obj["mid_warn"] = "无"
        self.final_obj["low_warn"] = RichText(str(int(self.low_warn)) + "个", font='Microsoft YaHei', color='ecec39',
                                              size=41)
        if self.low_warn == 0:
            self.final_obj["low_warn"] = "无"

    def focusPage(self, data):
        """
        @description 重点关注风险-数据填充
        """
        num = 1  # 序号
        focus_high_list = []
        for hwl in self.high_warn_list:
            focus_high_list.append(
                {
                    "num": str(num),
                    "name": str(hwl["msg"]),
                    "level": "高危",
                    "ps": str(hwl["ps"]),
                    "tips": '\n'.join(hwl["tips"]),
                    "auto": self.is_autofix1(hwl["m_name"])
                }
            )
            num += 1
        self.final_obj["focus_high_list"] = focus_high_list
        focus_mid_list = []
        for mwl in self.mid_warn_list:
            focus_mid_list.append(
                {
                    "num": num,
                    "name": mwl["msg"],
                    "level": "中危",
                    "ps": mwl["ps"],
                    "tips": '\n'.join(mwl["tips"]),
                    "auto": self.is_autofix1(mwl["m_name"])
                }
            )
            num += 1
        self.final_obj["focus_mid_list"] = focus_mid_list
        focus_cve_list = []
        for cl in self.cve_list:
            tmp_cve = {
                "num": num,
                "name": cl["m_name"],
                "level": "高危",
                "ps": cl["ps"],
                "tips": '\n'.join(cl["tips"]),
                "auto": "支持"
            }
            if cl["level"] == 2:
                tmp_cve["name"] = cl["m_name"]
                tmp_cve["level"] = "中危"
            elif cl["level"] == 1:
                tmp_cve["name"] = cl["m_name"]
                tmp_cve["level"] = "低危"
            focus_cve_list.append(tmp_cve)
            num += 1
        self.final_obj["focus_cve_list"] = focus_cve_list

    def is_autofix(self, warn):
        """
        @description 判断指定的安全警告是否支持自动修复。
        @param warn<dict>: 包含安全警告信息的字典对象
            "title" 和 "m_name"，表示常规模块警告。
            "cve_id" 和 "soft_name"，表示漏洞相关警告
        @return
        """
        data = json.loads(public.readFile(self.__data))
        if "title" in warn:
            if warn["m_name"] in data["is_autofix"]:
                return "支持"
            else:
                return "不支持"
        if "cve_id" in warn:
            if list(warn["soft_name"].keys())[0] == "kernel":
                return "不支持"
            else:
                return "支持"

    def is_autofix1(self, name):
        """
        @name 判断是否可以自动修复
        """
        if name in self.auto_fix:
            return "支持"
        else:
            return "不支持"

    def format_ignore_item(self, num, item, level, tips, auto):
        """格式化数据"""
        return {
            "num": str(num),
            "name": item.get("msg", item.get("cve_id", "")),
            "level": level,
            "ps": item.get("ps", item.get("vuln_name", "")),
            "tips": tips,
            "auto": auto
        }

    def lowPage(self, data):
        """
        @description 潜在风险-数据填充
        @param null
        """
        num = 1  # 序号
        low_warn_list = []
        for lwl in self.low_warn_list:
            low_warn_list.append(self.format_ignore_item(
                num, lwl, "低危", '\n'.join(lwl.get("tips", [])), self.is_autofix1(lwl["m_name"])
            ))
            num += 1
        self.final_obj["low_warn_list"] = low_warn_list
        ignore_list = []
        for ig in data["ignore"]:
            if "title" in ig:
                ignore_list.append(self.format_ignore_item(
                    num, ig, "忽略项", '\n'.join(ig.get("tips", [])), self.is_autofix1(ig["m_name"])
                ))
            elif "cve_id" in ig:
                tips = "将【{}】版本升级至{}或更高版本。".format('、'.join(ig.get("soft_name", [])),
                                                              ig.get("vuln_version", ""))
                ignore_list.append(self.format_ignore_item(num, ig, "忽略项", tips, self.is_autofix(ig)))
            num += 1
        self.final_obj["ignore_list"] = ignore_list
