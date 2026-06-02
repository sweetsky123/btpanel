#!/usr/bin/env btpython

import os,sys;
os.chdir('/www/server/panel/'); 
sys.path.insert(0, 'class/'); 
sys.path.insert(0, '/www/server/panel/'); 
import public;
import PluginLoader


def RunWafFunc(func_name,args):
    """
    运行waf插件函数
    所有参数值转为str,因为controller层会对get参数调用.strip()
    """
    str_args = {k: str(v) for k, v in args.items()}
    return PluginLoader.plugin_run('btwaf', func_name, public.to_dict_obj(str_args))

def _is_error(result):
    """检测接口是否返回错误"""
    if isinstance(result, dict) and result.get('status') == False:
        return True
    return False


def _unwrap(result):
    """
    统一解包接口返回数据,提取有效内容
    public.returnMsg 返回 {status: True/False, msg: data}
    部分函数直接返回 dict/list,无 status 包裹
    """
    if isinstance(result, dict):
        if 'msg' in result and result.get('status', True):
            return result['msg']
        return result
    return result


def _match_type_cn(rule_name):
    """
    攻击类型映射为中文名
    """
    type_map = {
        'sql': 'SQL注入',
        'xss': 'XSS跨站脚本',
        'cc': 'CC攻击',
        'user_agent': '恶意爬虫(User-Agent)',
        'cookie': 'Cookie渗透',
        'scan': '恶意扫描',
        'upload': '文件上传',
        'path_php': '禁止PHP脚本',
        'download': '恶意下载',
        'smart_cc': '智能CC',
        'drop_abroad': '禁国外访问',
        'file': '目录遍历',
        'get': 'GET型攻击',
        'args': '参数攻击',
        'url': 'URL攻击',
        'post': 'POST攻击',
        'backdoor': '后门检测',
        'webshell': 'Webshell上传',
        'webshell_fake': '伪装Webshell',
        'try_upload': '尝试上传',
        'header': '请求头注入',
        'private': '目录保护',
        'bot': 'Bot机器人',
        'cc_rule': 'CC规则',
        'ip_black': 'IP黑名单',
        'ip_white': 'IP白名单',
        'url_black': 'URL黑名单',
        'url_white': 'URL白名单',
        'ua_black': 'UA黑名单',
        'ua_white': 'UA白名单',
        'region_limit': '地区限制',
        'malicious_ip': '云端恶意IP库',
        'captcha': '人机验证',
        'content_replace': '内容替换',
        'renji': '人机验证',
        'flow_limit': '流量限制',
        'blocking': '封锁拦截',
        'retry': '攻击次数拦截',
        'cgi': '通用网关',
    }
    if rule_name is None:
        return '未知类型'
    return type_map.get(rule_name, rule_name)


def _format_ip_location(ip, ip_country, ip_subdivisions, ip_city):
    """
    格式化IP归属地信息
    """
    parts = []
    if ip_country:
        parts.append(ip_country)
    if ip_subdivisions:
        parts.append(ip_subdivisions)
    if ip_city:
        parts.append(ip_city)
    location = '-'.join(parts) if parts else '未知地区'
    return "{} ({})".format(ip, location)


def _format_item(item, known_fields=None):
    """
    将一个数据条目格式化为可读文本，保留全部字段
    known_fields 为需要特殊格式化的关键字段列表
    """
    lines = []
    for key, value in item.items():
        if value is None:
            value = ''
        lines.append('{}: {}'.format(key, value))
    return '\n'.join(lines)


# ===================== WAF拦截记录 =====================

def get_attack_report_log(limit=10, p=1, keyword='', start_time='', end_time=''):
    """
    搜索WAF拦截记录
    """
    import json
    args = {'limit': limit, 'p': p}
    if keyword:
        args['keyword'] = keyword
    if start_time:
        args['start_time'] = start_time
    if end_time:
        args['end_time'] = end_time

    result = RunWafFunc('attack_report_log', args)
    if _is_error(result):
        return json.dumps(result, ensure_ascii=False)

    data = _unwrap(result)
    total = data.get('total', 0)
    data_list = data.get('data', [])
    page_info = data.get('page', '')

    lines = ['WAF拦截记录查询结果（共{}条记录）:'.format(total), '']
    if page_info:
        lines.append('分页信息: {}'.format(page_info))
        lines.append('')

    for idx, item in enumerate(data_list, 1):
        time_str = item.get('time_localtime', '')
        server = item.get('server_name', '')
        ip = item.get('ip', '')
        ip_city = item.get('ip_city', '')
        ip_country = item.get('ip_country', '')
        ip_subdivisions = item.get('ip_subdivisions', '')
        rule_type = item.get('type', '')
        rule_name = item.get('filter_rule', '')
        uri = item.get('uri', '')

        location = _format_ip_location(ip, ip_country, ip_subdivisions, ip_city)
        cn_type = _match_type_cn(rule_name) or _match_type_cn(rule_type)

        lines.append('{}. [{}] 站点: {}'.format(idx, time_str, server))
        lines.append('   攻击IP: {} | 攻击类型: {}'.format(location, cn_type))
        lines.append('   请求路径: {}'.format(uri))
        # 输出所有剩余字段
        skip_keys = {'time_localtime', 'server_name', 'ip', 'ip_city', 'ip_country', 'ip_subdivisions', 'type', 'filter_rule', 'uri'}
        for k, v in item.items():
            if k not in skip_keys and v is not None and v != '':
                lines.append('   {}: {}'.format(k, v))
        lines.append('')

    return '\n'.join(lines)


# ===================== 站点拦截日志 =====================

def get_site_safe_logs(site_name, limit=10, p=1, start_time='', end_time=''):
    """
    搜索某个网站的WAF拦截记录，需指定网站名
    """
    import json
    if not site_name:
        return '请指定要查询的网站名称(site_name)。'

    args = {'siteName': site_name, 'limit': limit, 'p': p}
    if start_time:
        args['start_time'] = start_time
    if end_time:
        args['end_time'] = end_time

    result = RunWafFunc('get_site_safe_logs', args)
    if _is_error(result):
        return json.dumps(result, ensure_ascii=False)

    data = _unwrap(result)
    count = data.get('count', 0)
    data_list = data.get('data', [])
    page_info = data.get('page', '')

    lines = ['网站 [{}] WAF拦截记录（共{}条）:'.format(site_name, count), '']
    if page_info:
        lines.append('分页信息: {}'.format(page_info))
        lines.append('')

    for idx, item in enumerate(data_list, 1):
        time_str = item.get('time_localtime', '')
        ip = item.get('ip', '')
        ip_city = item.get('ip_city', '')
        ip_country = item.get('ip_country', '')
        ip_subdivisions = item.get('ip_subdivisions', '')
        rule_type = item.get('type', '')
        rule_name = item.get('filter_rule', '')
        uri = item.get('uri', '')
        user_agent = item.get('user_agent', '')

        location = _format_ip_location(ip, ip_country, ip_subdivisions, ip_city)
        cn_type = _match_type_cn(rule_name) or _match_type_cn(rule_type)

        lines.append('{}. [{}] 攻击类型: {}'.format(idx, time_str, cn_type))
        lines.append('   来源IP: {}'.format(location))
        lines.append('   请求路径: {}'.format(uri))
        if user_agent:
            lines.append('   UA: {}'.format(user_agent[:80]))
        # 输出所有剩余字段
        skip_keys = {'time_localtime', 'ip', 'ip_city', 'ip_country', 'ip_subdivisions', 'type', 'filter_rule', 'uri', 'user_agent'}
        for k, v in item.items():
            if k not in skip_keys and v is not None and v != '':
                lines.append('   {}: {}'.format(k, v))
        lines.append('')

    return '\n'.join(lines)


# ===================== 站点防护信息 =====================

def get_search_sites(search):
    """
    搜索某个网站的防护信息，需指定网站名
    """
    import json
    if not search:
        return '请指定要搜索的网站名称(search)。'

    result = RunWafFunc('get_search_sites', {'search': search})
    if _is_error(result):
        return json.dumps(result, ensure_ascii=False)

    data = _unwrap(result)
    data_list = data.get('data', [])
    page_info = data.get('page', '')

    lines = ['网站 [{}] 防护信息查询结果:'.format(search), '']
    if page_info:
        lines.append('分页信息: {}'.format(page_info))
        lines.append('')

    for site in data_list:
        site_name_val = site.get('siteName', '')
        total = site.get('total', {})
        log_size = site.get('log_size', 0)
        is_open = site.get('open', False)
        cc_config = site.get('cc', {})

        lines.append('--- 站点: {} ---'.format(site_name_val))
        lines.append('防护状态: {} | 日志总条数: {}'.format(
            '已开启' if is_open else '已关闭', log_size))

        if total:
            lines.append('拦截统计:')
            attack_items = []
            for k, v in total.items():
                if isinstance(v, (int, float)) and v > 0:
                    cn = _match_type_cn(k)
                    attack_items.append('{}: {}次'.format(cn, int(v)))
            if attack_items:
                lines.append('  ' + '，'.join(attack_items))
            else:
                lines.append('  暂无拦截记录')

        if cc_config and isinstance(cc_config, dict):
            if cc_config.get('open'):
                cycle = cc_config.get('cycle', 0)
                cc_limit = cc_config.get('limit', 0)
                lines.append('CC防御: 已开启（{}秒内{}次触发封锁）'.format(cycle, cc_limit))
            else:
                lines.append('CC防御: 未开启')

        # 输出所有剩余字段
        skip_keys = {'siteName', 'total', 'log_size', 'open', 'cc'}
        for k, v in site.items():
            if k not in skip_keys and v is not None and v != '':
                if isinstance(v, (dict, list)):
                    lines.append('{}: {}'.format(k, json.dumps(v, ensure_ascii=False)))
                else:
                    lines.append('{}: {}'.format(k, v))
        lines.append('')

    return '\n'.join(lines)


# ===================== IP临时黑名单(封锁列表) =====================

def get_safe_logs_sql(limit=10, p=1, keyword='', start_time='', end_time=''):
    """
    IP临时拉黑记录（封锁历史）
    """
    import json
    args = {'limit': limit, 'p': p}
    if keyword:
        args['keyword'] = keyword
    if start_time:
        args['start_time'] = start_time
    if end_time:
        args['end_time'] = end_time

    result = RunWafFunc('get_safe_logs_sql', args)
    if _is_error(result):
        return json.dumps(result, ensure_ascii=False)

    data = _unwrap(result)
    count = data.get('count', 0)
    data_list = data.get('data', [])
    page_info = data.get('page', '')

    lines = ['IP临时拉黑记录（共{}条）:'.format(count), '']
    if page_info:
        lines.append('分页信息: {}'.format(page_info))
        lines.append('')

    for idx, item in enumerate(data_list, 1):
        time_str = item.get('time_localtime', '')
        server = item.get('server_name', '')
        ip = item.get('ip', '')
        ip_city = item.get('ip_city', '')
        ip_country = item.get('ip_country', '')
        ip_subdivisions = item.get('ip_subdivisions', '')
        rule_type = item.get('type', '')
        rule_name = item.get('filter_rule', '')
        uri = item.get('uri', '')
        blocking_time = item.get('blocking_time', '')
        is_status = item.get('is_status', 1)

        location = _format_ip_location(ip, ip_country, ip_subdivisions, ip_city)
        cn_type = _match_type_cn(rule_name) or _match_type_cn(rule_type)
        status_text = '封锁中' if is_status == 1 else '已解封'

        lines.append('{}. [{}] 状态: {}'.format(idx, time_str, status_text))
        lines.append('   IP: {} | 站点: {}'.format(location, server))
        lines.append('   攻击类型: {} | 请求路径: {}'.format(cn_type, uri))
        if blocking_time:
            lines.append('   封锁时长: {}秒'.format(blocking_time))
        # 输出所有剩余字段
        skip_keys = {'time_localtime', 'server_name', 'ip', 'ip_city', 'ip_country', 'ip_subdivisions', 'type', 'filter_rule', 'uri', 'blocking_time', 'is_status'}
        for k, v in item.items():
            if k not in skip_keys and v is not None and v != '':
                lines.append('   {}: {}'.format(k, v))
        lines.append('')

    return '\n'.join(lines)


# ===================== 规则命中记录 =====================

def get_rule_hit_list(limit=10, p=1, filter_mode='all', keyword=''):
    """
    规则命中记录
    filter_mode: all(全部), accept(放行), refuse(拦截)
    """
    import json
    args = {'limit': limit, 'p': p, 'filter': filter_mode}
    if keyword:
        args['keyword'] = keyword

    result = RunWafFunc('get_rule_hit_list', args)
    if _is_error(result):
        return json.dumps(result, ensure_ascii=False)

    data = _unwrap(result)
    data_list = data.get('list', [])
    total = data.get('total', len(data_list))

    filter_label = {'all': '全部', 'accept': '放行', 'refuse': '拦截'}.get(filter_mode, filter_mode)
    lines = ['规则命中记录（{}，共{}条）:'.format(filter_label, total), '']

    for idx, item in enumerate(data_list, 1):
        status = item.get('status', '')
        server = item.get('server_name', '')
        uri = item.get('uri', '')
        rule_name = item.get('rule_name', '')
        rule_type = item.get('rule_type', '')
        rule_ps = item.get('rule_ps', '')
        ip = item.get('ip', '')
        ip_country = item.get('ip_country', '')
        ip_province = item.get('ip_province', '')
        ip_city = item.get('ip_city', '')

        location = _format_ip_location(ip, ip_country, ip_province, ip_city)
        cn_type = _match_type_cn(rule_type)

        lines.append('{}. 处理结果: {} | 站点: {}'.format(idx, status, server))
        lines.append('   触发规则: {} | 规则类型: {}'.format(rule_name, cn_type))
        lines.append('   请求路径: {}'.format(uri))
        lines.append('   来源IP: {}'.format(location))
        if rule_ps:
            lines.append('   规则说明: {}'.format(rule_ps))
        # 输出所有剩余字段
        skip_keys = {'status', 'server_name', 'uri', 'rule_name', 'rule_type', 'rule_ps', 'ip', 'ip_country', 'ip_province', 'ip_city'}
        for k, v in item.items():
            if k not in skip_keys and v is not None and v != '':
                lines.append('   {}: {}'.format(k, v))
        lines.append('')

    return '\n'.join(lines)


# ===================== WAF概览 =====================

def overview(start_time=''):
    """
    获取WAF概览，可指定日期(格式: YYYY-MM-DD)，默认当天
    """
    import json
    args = {}
    if start_time:
        args['start_time'] = start_time

    result = RunWafFunc('overview', args)
    if _is_error(result):
        return json.dumps(result, ensure_ascii=False)

    data = _unwrap(result)
    count = data.get('count', {})

    date_str = start_time or '当天'
    lines = ['【宝塔Nginx防火墙(WAF)概览 - {}】'.format(date_str), '']

    lines.append('--- 请求统计 ---')
    lines.append('今日总请求数: {}次'.format(count.get('today_request', 0)))
    lines.append('恶意请求数: {}次'.format(count.get('malicious_request', 0)))
    if count.get('yesterday_request_total', 0) > 0:
        lines.append('昨日同时段请求数: {}次'.format(count.get('yesterday_request_total', 0)))
    if count.get('yesterday_malicious_request', 0) > 0:
        lines.append('昨日同时段恶意请求数: {}次'.format(count.get('yesterday_malicious_request', 0)))

    lines.append('')
    lines.append('--- 防护状态 ---')
    lines.append('木马隔离文件数: {}个'.format(count.get('webshell', 0)))
    lines.append('未开启防护站点数: {}个'.format(count.get('unprotected_site', 0)))
    if count.get('unprotected_site_list'):
        lines.append('未防护站点列表: {}'.format(', '.join(count['unprotected_site_list'])))

    lines.append('')
    qps = data.get('qps', 0)
    lines.append('--- 性能指标 ---')
    lines.append('当前QPS: {}'.format(qps))

    proxy_time = data.get('proxy_time', 0)
    if proxy_time:
        lines.append('平均代理响应时间: {}ms'.format(proxy_time))

    traffic = data.get('traffic', 0)
    if traffic:
        lines.append('流量: {}'.format(traffic))

    # 攻击类型分布
    attack_types = data.get('type', [])
    if attack_types:
        lines.append('')
        lines.append('--- 攻击类型分布(Top10) ---')
        for item in attack_types[:10]:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                type_name, type_count = item
                cn = _match_type_cn(type_name)
                lines.append('{}: {}次'.format(cn, type_count))
            elif isinstance(item, dict):
                for k, v in item.items():
                    lines.append('{}: {}次'.format(_match_type_cn(k), v))

    # 被攻击站点Top
    server_top = data.get('server_name_top', [])
    if server_top:
        lines.append('')
        lines.append('--- 被攻击站点Top10 ---')
        for item in server_top[:10]:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                lines.append('{}: {}次'.format(item[0], item[1]))

    # CC设置异常提醒
    if count.get('maybe_err_cc', 0) > 0:
        lines.append('')
        lines.append('--- CC防护设置异常提醒（共{}项）---'.format(count['maybe_err_cc']))
        for warn in count.get('maybe_err_cc_list', []):
            lines.append('  {}'.format(warn))

    # 攻击详情 (attack_details)
    attack_details = data.get('attack_details', [])
    if attack_details:
        lines.append('')
        lines.append('--- 攻击详情(Top100) ---')
        for item in attack_details:
            lines.append(json.dumps(item, ensure_ascii=False))

    # 流量过滤
    traffic_filter = data.get('traffic_filter', [])
    if traffic_filter:
        lines.append('')
        lines.append('--- 流量过滤 ---')
        for item in traffic_filter:
            lines.append(json.dumps(item, ensure_ascii=False))

    # 输出所有剩余顶层字段
    skip_keys = {'count', 'qps', 'proxy_time', 'traffic', 'type', 'server_name_top', 'attack_details', 'traffic_filter', 'map'}
    for k, v in data.items():
        if k not in skip_keys:
            if isinstance(v, (dict, list)):
                lines.append('')
                lines.append('--- {} ---'.format(k))
                lines.append(json.dumps(v, ensure_ascii=False))
            elif v is not None and v != '':
                lines.append('{}: {}'.format(k, v))

    return '\n'.join(lines)


# ===================== 攻击报表 =====================

def get_report(start_time='', end_time='', server_name=''):
    """
    攻击报表总结，可指定日期和站点
    """
    import json
    args = {}
    if start_time:
        args['start_time'] = start_time
    if end_time:
        args['end_time'] = end_time
    if server_name:
        args['server_name'] = server_name

    result = RunWafFunc('get_report', args)
    if _is_error(result):
        return json.dumps(result, ensure_ascii=False)

    data = _unwrap(result)

    date_str = start_time or '当天'
    scope = '全站' if not server_name else server_name
    lines = ['【攻击报表 - {} - {}】'.format(date_str, scope), '']

    # 攻击类型分布
    attack_types = data.get('type', {})
    if attack_types:
        lines.append('--- 攻击类型分布 ---')
        if isinstance(attack_types, dict):
            sorted_types = sorted(attack_types.items(), key=lambda x: x[1], reverse=True)
            total_attacks = sum(v for _, v in sorted_types)
            for type_name, type_count in sorted_types:
                cn = _match_type_cn(type_name)
                lines.append('{}: {}次'.format(cn, type_count))
            lines.append('')
            lines.append('合计拦截: {}次'.format(total_attacks))
        elif isinstance(attack_types, list):
            for item in attack_types:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    cn = _match_type_cn(item[0])
                    lines.append('{}: {}次'.format(cn, item[1]))
                else:
                    lines.append(json.dumps(item, ensure_ascii=False))

    # Top攻击IP
    ip_list = data.get('ip', [])
    if ip_list:
        lines.append('')
        lines.append('--- 攻击IP Top10 ---')
        for item in ip_list[:10]:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                ip, ip_count = item[0], item[1]
                ip_info = data.get('ip_list', {}).get(ip, {})
                country = ip_info.get('ip_country', '') if isinstance(ip_info, dict) else ''
                city = ip_info.get('ip_city', '') if isinstance(ip_info, dict) else ''
                location = ' ({}{})'.format(country, '-' + city if city else '') if country else ''
                lines.append('{}: {}次{}'.format(ip, ip_count, location))
            else:
                lines.append(json.dumps(item, ensure_ascii=False))

    # 完整IP列表
    ip_list_raw = data.get('ip_list', {})
    if ip_list_raw:
        lines.append('')
        lines.append('--- 完整IP列表 ---')
        for ip_key, ip_val in ip_list_raw.items():
            if isinstance(ip_val, dict):
                lines.append('{}: {}'.format(ip_key, json.dumps(ip_val, ensure_ascii=False)))
            else:
                lines.append('{}: {}'.format(ip_key, ip_val))

    # Top被攻击URL
    uri_data = data.get('uri', {})
    if uri_data:
        lines.append('')
        lines.append('--- 被攻击URL Top10 ---')
        if isinstance(uri_data, dict):
            sorted_uris = sorted(uri_data.items(), key=lambda x: x[1], reverse=True)
            for uri_name, uri_count in sorted_uris[:10]:
                lines.append('{}: {}次'.format(uri_name, uri_count))

    # 完整URI列表
    uri_list = data.get('uri_list', {})
    if uri_list:
        lines.append('')
        lines.append('--- 完整URI列表 ---')
        for uri_key, uri_val in uri_list.items():
            if isinstance(uri_val, dict):
                lines.append('{}: {}'.format(uri_key, json.dumps(uri_val, ensure_ascii=False)))
            else:
                lines.append('{}: {}'.format(uri_key, uri_val))

    # 输出所有剩余顶层字段
    skip_keys = {'type', 'ip', 'ip_list', 'uri', 'uri_list'}
    for k, v in data.items():
        if k not in skip_keys:
            if isinstance(v, (dict, list)):
                lines.append('')
                lines.append('--- {} ---'.format(k))
                lines.append(json.dumps(v, ensure_ascii=False))
            elif v is not None and v != '':
                lines.append('{}: {}'.format(k, v))

    return '\n'.join(lines)


# ===================== 全局配置 =====================

def get_global_config():
    """
    获取WAF防火墙全局配置
    """
    import json
    result = RunWafFunc('get_config', {})
    if _is_error(result):
        return json.dumps(result, ensure_ascii=False)

    data = _unwrap(result)

    lines = ['【宝塔WAF全局配置】', '']

    # 总开关
    lines.append('--- 总开关 ---')
    lines.append('WAF总开关: {}'.format('已开启' if data.get('open') else '已关闭'))
    lines.append('日志开关: {}'.format('已开启' if data.get('log') else '已关闭'))
    lines.append('日志保存天数: {}天'.format(data.get('log_save', '')))
    lines.append('日志路径: {}'.format(data.get('logs_path', '')))

    # CC防御
    cc = data.get('cc', {})
    if cc:
        lines.append('')
        lines.append('--- CC防御 ---')
        lines.append('状态: {}'.format('已开启' if cc.get('open') else '已关闭'))
        lines.append('状态码: {}'.format(cc.get('status', '')))
        lines.append('周期: {}秒'.format(cc.get('cycle', '')))
        lines.append('触发次数: {}次'.format(cc.get('limit', '')))
        lines.append('封锁时长: {}秒'.format(cc.get('endtime', '')))
        lines.append('自动开启CC: {}'.format('是' if data.get('cc_automatic') else '否'))
        lines.append('CC重试周期: {}秒'.format(data.get('cc_retry_cycle', '')))
        lines.append('CC持续时间: {}秒'.format(data.get('cc_time', '')))

    # 攻击次数拦截
    lines.append('')
    lines.append('--- 攻击次数拦截 ---')
    lines.append('周期: {}秒'.format(data.get('retry_cycle', '')))
    lines.append('触发次数: {}次'.format(data.get('retry', '')))
    lines.append('封锁时长: {}秒'.format(data.get('retry_time', '')))

    # SQL注入
    sql = data.get('sql_injection', {})
    if sql:
        lines.append('')
        lines.append('--- SQL注入防御 ---')
        lines.append('状态: {}'.format('已开启' if sql.get('open') else '已关闭'))
        lines.append('状态码: {}'.format(sql.get('status', '')))
        lines.append('模式: {}'.format(sql.get('mode', '')))
        lines.append('GET参数检测: {}'.format('是' if sql.get('get_sql') else '否'))
        lines.append('POST参数检测: {}'.format('是' if sql.get('post_sql') else '否'))

    # XSS
    xss = data.get('xss_injection', {})
    if xss:
        lines.append('')
        lines.append('--- XSS跨站脚本防御 ---')
        lines.append('状态: {}'.format('已开启' if xss.get('open') else '已关闭'))
        lines.append('状态码: {}'.format(xss.get('status', '')))
        lines.append('模式: {}'.format(xss.get('mode', '')))
        lines.append('GET参数检测: {}'.format('是' if xss.get('get_xss') else '否'))
        lines.append('POST参数检测: {}'.format('是' if xss.get('post_xss') else '否'))

    # 文件上传
    upload = data.get('file_upload', {})
    if upload:
        lines.append('')
        lines.append('--- 文件上传防御 ---')
        lines.append('状态: {}'.format('已开启' if upload.get('open') else '已关闭'))
        lines.append('状态码: {}'.format(upload.get('status', '')))
        lines.append('模式: {}'.format(upload.get('mode', '')))

    # GET/POST/COOKIE/UA/扫描
    for key, label in [('get', 'GET参数过滤'), ('post', 'POST参数过滤'),
                        ('cookie', 'Cookie渗透防御'), ('user-agent', 'User-Agent过滤'),
                        ('scan', '恶意扫描防御'), ('other', '其他过滤')]:
        cfg = data.get(key, {})
        if cfg:
            lines.append('')
            lines.append('--- {} ---'.format(label))
            lines.append('状态: {}'.format('已开启' if cfg.get('open') else '已关闭'))
            lines.append('状态码: {}'.format(cfg.get('status', '')))
            lines.append('描述: {}'.format(cfg.get('ps', '')))

    # 禁国外/禁国内
    lines.append('')
    lines.append('--- 地区限制 ---')
    drop_abroad = data.get('drop_abroad', {})
    lines.append('禁国外: {} (状态码:{})'.format('已开启' if drop_abroad.get('open') else '已关闭', drop_abroad.get('status', '')))
    drop_china = data.get('drop_china', {})
    lines.append('禁国内: {} (状态码:{})'.format('已开启' if drop_china.get('open') else '已关闭', drop_china.get('status', '')))
    lines.append('开启禁国外站点数: {}'.format(data.get('drop_abroad_count', 0)))

    # RCE注入
    rce = data.get('rce_injection', {})
    if rce:
        lines.append('')
        lines.append('--- RCE命令注入防御 ---')
        lines.append('状态: {}'.format('已开启' if rce.get('open') else '已关闭'))
        lines.append('状态码: {}'.format(rce.get('status', '')))
        lines.append('模式: {}'.format(rce.get('mode', '')))

    # CMS规则
    lines.append('')
    lines.append('--- CMS规则 ---')
    lines.append('CMS规则: {}'.format('已开启' if data.get('cms_rule_open') else '已关闭'))

    # 消息通知
    msg = data.get('msg_send', {})
    if msg:
        lines.append('')
        lines.append('--- 消息通知 ---')
        lines.append('通知开关: {}'.format('已开启' if msg.get('open') else '已关闭'))
        lines.append('攻击通知: {}'.format('是' if msg.get('attack') else '否'))
        lines.append('超时通知: {}'.format('是' if msg.get('timeout') else '否'))
        lines.append('CC通知: {}'.format('是' if msg.get('cc') else '否'))
        lines.append('恶意IP通知: {}'.format('是' if msg.get('malicious_ip') else '否'))
        lines.append('自定义通知: {}'.format('是' if msg.get('customize') else '否'))
        lines.append('通知方式: {}'.format(msg.get('send_type', '')))
        lines.append('保留天数: {}'.format(msg.get('reserve', '')))

    # 输出所有剩余顶层字段
    skip_keys = {'open', 'log', 'log_save', 'logs_path', 'cc', 'cc_automatic', 'cc_retry_cycle', 'cc_time',
                 'retry_cycle', 'retry', 'retry_time', 'sql_injection', 'xss_injection', 'file_upload',
                 'get', 'post', 'cookie', 'user-agent', 'scan', 'other', 'drop_abroad', 'drop_china',
                 'drop_abroad_count', 'rce_injection', 'cms_rule_open', 'msg_send',
                 'uri_find', 'body_regular', 'body_character_string', 'body_intercept',
                 'start_time', 'ua_white', 'ua_black', 'reqfile_path', 'cc_ip_max'}
    remaining = {}
    for k, v in data.items():
        if k not in skip_keys:
            remaining[k] = v
    if remaining:
        lines.append('')
        lines.append('--- 其他配置 ---')
        lines.append(json.dumps(remaining, ensure_ascii=False))

    return '\n'.join(lines)


# ===================== 站点配置 =====================

def get_site_config(site_name):
    """
    获取指定网站的WAF防护配置，需指定网站名
    注意：get_site_config_byname 依赖 Flask session 上下文，
    CLI调用会报 RuntimeError，因此改用 get_site_config 获取全部站点后过滤。
    """
    import json
    if not site_name:
        return '请指定要查询的网站名称(site_name)。'

    # get_site_config(self,get) 在 get 为空时返回 dict，有参数时返回 list
    # 传入空dict_obj 会因为 dict_obj 实例非空而走 list 分支，
    # 因此做兼容：list 则按 siteName 匹配，dict 则按 key 匹配
    result = RunWafFunc('get_site_config', {})
    if _is_error(result):
        return json.dumps(result, ensure_ascii=False)

    raw = _unwrap(result)
    if isinstance(raw, list):
        data = None
        for site_info in raw:
            if site_info.get('siteName') == site_name:
                data = site_info
                break
        if data is None:
            return '未找到网站 [{}] 的WAF防护配置。'.format(site_name)
    elif isinstance(raw, dict):
        if site_name not in raw:
            return '未找到网站 [{}] 的WAF防护配置。'.format(site_name)
        data = raw[site_name]
        data['siteName'] = site_name
    else:
        return '未找到网站 [{}] 的WAF防护配置：接口返回格式异常。'.format(site_name)

    # 补充 top 字段（get_site_config_byname 原本会补这个）
    top_result = RunWafFunc('get_config', {})
    if not _is_error(top_result):
        data['top'] = _unwrap(top_result)
    else:
        data['top'] = {}

    lines = ['【网站 [{}] WAF防护配置】'.format(site_name), '']

    # 基本状态
    lines.append('--- 基本状态 ---')
    lines.append('防护开关: {}'.format('已开启' if data.get('open') else '已关闭'))
    lines.append('CDN选项: {}'.format('已开启' if data.get('cdn') else '已关闭'))
    lines.append('日志记录: {}'.format(data.get('log_size', '')))
    start_time_val = data.get('start_time', 0)
    if start_time_val:
        import time
        lines.append('启用时间: {}'.format(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time_val))))

    # 网站CC配置
    cc = data.get('cc', {})
    if cc:
        lines.append('')
        lines.append('--- CC防御 ---')
        lines.append('状态: {}'.format('已开启' if cc.get('open') else '已关闭'))
        if cc.get('open'):
            lines.append('周期: {}秒'.format(cc.get('cycle', '')))
            lines.append('触发次数: {}次'.format(cc.get('limit', '')))
            lines.append('封锁时长: {}秒'.format(cc.get('endtime', '')))

    # 网站攻击次数拦截
    lines.append('')
    lines.append('--- 攻击次数拦截 ---')
    lines.append('周期: {}秒'.format(data.get('retry_cycle', '')))
    lines.append('触发次数: {}次'.format(data.get('retry', '')))
    lines.append('封锁时长: {}秒'.format(data.get('retry_time', '')))

    # 蜘蛛池
    lines.append('')
    lines.append('--- 蜘蛛池 ---')
    lines.append('蜘蛛池: {}'.format('已开启' if data.get('spider_status') else '已关闭'))
    spider_data = data.get('spider', [])
    if spider_data:
        for s in spider_data:
            if isinstance(s, dict):
                lines.append('  {}: {} (状态码:{})'.format(
                    s.get('name', ''), '启用' if s.get('status') else '禁用', s.get('return', '')))

    # 地区限制
    lines.append('')
    lines.append('--- 地区限制 ---')
    lines.append('禁国外: {}'.format('已开启' if data.get('drop_abroad') else '已关闭'))
    lines.append('禁国内: {}'.format('已开启' if data.get('drop_china') else '已关闭'))

    # IP黑白名单
    ip_black = data.get('ip_black', [])
    ip_white = data.get('ip_white', [])
    if ip_black:
        lines.append('')
        lines.append('--- IP黑名单（{}条）---'.format(len(ip_black)))
        for ip_item in ip_black[:10]:
            lines.append('  {}'.format(ip_item))
        if len(ip_black) > 10:
            lines.append('  ... 共{}条，仅显示前10条'.format(len(ip_black)))
    if ip_white:
        lines.append('')
        lines.append('--- IP白名单（{}条）---'.format(len(ip_white)))
        for ip_item in ip_white[:10]:
            lines.append('  {}'.format(ip_item))
        if len(ip_white) > 10:
            lines.append('  ... 共{}条，仅显示前10条'.format(len(ip_white)))

    # URL黑白名单
    url_white = data.get('url_white', [])
    url_black = data.get('url_black', [])
    if url_white:
        lines.append('')
        lines.append('--- URL白名单（{}条）---'.format(len(url_white)))
        for url_item in url_white[:10]:
            if isinstance(url_item, dict):
                lines.append('  {}'.format(url_item.get('url', url_item)))
            else:
                lines.append('  {}'.format(url_item))
        if len(url_white) > 10:
            lines.append('  ... 共{}条'.format(len(url_white)))
    if url_black:
        lines.append('')
        lines.append('--- URL黑名单（{}条）---'.format(len(url_black)))
        for url_item in url_black[:10]:
            if isinstance(url_item, dict):
                lines.append('  {}'.format(url_item.get('url', url_item)))
            else:
                lines.append('  {}'.format(url_item))
        if len(url_black) > 10:
            lines.append('  ... 共{}条'.format(len(url_black)))

    # UA黑白名单
    ua_white = data.get('ua_white', [])
    ua_black = data.get('ua_black', [])
    if ua_white:
        lines.append('')
        lines.append('--- UA白名单（{}条）---'.format(len(ua_white)))
        for ua in ua_white[:10]:
            lines.append('  {}'.format(ua))
    if ua_black:
        lines.append('')
        lines.append('--- UA黑名单（{}条）---'.format(len(ua_black)))
        for ua in ua_black[:10]:
            lines.append('  {}'.format(ua))

    # 恶意文件上传防御
    lines.append('')
    lines.append('--- 恶意文件上传防御 ---')
    lines.append('状态: {}'.format('已开启' if data.get('disable_upload_ext') else '已关闭'))

    # 禁止PHP脚本
    lines.append('')
    lines.append('--- 禁止PHP脚本 ---')
    php_paths = data.get('disable_php_path', [])
    lines.append('状态: {}'.format('已开启' if php_paths else '已关闭'))
    if php_paths:
        for p in php_paths[:10]:
            lines.append('  {}'.format(p))

    # totla统计
    total = data.get('total', [])
    if total:
        lines.append('')
        lines.append('--- 拦截统计 ---')
        for item in total:
            if isinstance(item, dict):
                name = item.get('name', '')
                key = item.get('key', '')
                val = item.get('value', 0)
                if isinstance(val, (int, float)) and val > 0:
                    cn = _match_type_cn(key) or name
                    lines.append('  {}: {}次'.format(cn, int(val)))
            elif isinstance(item, (list, tuple)) and len(item) == 2:
                cn = _match_type_cn(item[0])
                lines.append('  {}: {}次'.format(cn, item[1]))

    # 输出所有剩余字段
    skip_keys = {'open', 'cdn', 'log_size', 'start_time', 'cc', 'retry_cycle', 'retry', 'retry_time',
                 'spider_status', 'spider', 'drop_abroad', 'drop_china', 'ip_black', 'ip_white',
                 'url_white', 'url_black', 'ua_white', 'ua_black', 'disable_upload_ext',
                 'disable_php_path', 'total', 'siteName', 'top', 'domains', 'site'}
    lines.append('')
    lines.append('--- 其他配置 ---')
    remaining = {}
    for k, v in data.items():
        if k not in skip_keys:
            remaining[k] = v
    if remaining:
        lines.append(json.dumps(remaining, ensure_ascii=False))

    return '\n'.join(lines)


if __name__ == '__main__':
    import json
    func_name = sys.argv[1]
    args = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    func = globals()[func_name]
    print(func(**args))
