#coding: utf-8
#-------------------------------------------------------------------
# 宝塔Linux面板
#-------------------------------------------------------------------
# Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
#-------------------------------------------------------------------
# Author: cjxin <cjxin@bt.cn>
#-------------------------------------------------------------------

#
#------------------------------

import os,sys,re
from filesModel.base import filesBase
import public,json
import zipfile,shutil
try:
    from unrar import rarfile
except:
    os.system('btpip install unrar')
    from unrar import rarfile


class main(filesBase):

    def __init__(self):
        pass


    def __check_zipfile(self,sfile,is_close = False):
        '''
        @name 检查文件是否为zip文件
        @param sfile 文件路径
        @return bool
        '''

        zip_file = None
        try:
            zip_file =  rarfile.RarFile(sfile)
        except:pass

        if is_close and zip_file:
            zip_file.close()

        return zip_file

    def get_zip_files(self,args):
        '''
        @name 获取压缩包内文件列表
        @param args['path'] 压缩包路径
        @return list
        '''
        sfile = args.sfile
        if not os.path.exists(sfile):
            return public.returnMsg(False,'FILE_NOT_EXISTS')

        zip_file = self.__check_zipfile(sfile)
        if not zip_file:
            return public.returnMsg(False,'NOT_ZIP_FILE')

        data = {}
        for item in zip_file.infolist():

            sub_data = data
            f_name = self.__get_zip_filename(item)

            f_dirs = f_name.split('/')
            for d in f_dirs:
                if not d: continue
                if not d in sub_data:
                    if d == f_name[-len(d):]:
                        tmps = item.date_time

                        sub_data[d] = {
                            'file_size': item.file_size,
                            'compress_size': item.compress_size,
                            'filename':d,
                            'fullpath':f_name,
                            'date_time': public.to_date(times = '{}-{}-{} {}:{}:{}'.format(tmps[0],tmps[1],tmps[2],tmps[3],tmps[4],tmps[5])),
                            'is_dir': 0
                        }
                        if item.flag_bits == 32:
                            sub_data[d]['is_dir'] = 1
                    else:
                        sub_data[d] = {}
                sub_data = sub_data[d]

        return data


    def get_fileinfo_by(self,args):
        '''
        @name 获取压缩包内文件信息
        @param args['path'] 压缩包路径
        @param args['filename'] 文件名
        @return dict
        '''

        sfile = args.sfile
        filename = args.filename
        if not os.path.exists(sfile):
            return public.returnMsg(False,'FILE_NOT_EXISTS')

        result = {}
        result['status'] = True
        result['data'] = ''
        with rarfile.RarFile(sfile,'r') as zip_file:
            for item in zip_file.infolist():
                z_filename = self.__get_zip_filename(item)
                if z_filename == filename:

                    buff = zip_file.read(item.filename)
                    encoding,srcBody = public.decode_data(buff)
                    result['encoding'] = encoding
                    result['data'] = srcBody
                    break
        return result

    def delete_zip_file(self,args):
        '''
        @name 删除压缩包内文件
        @param args['path'] 压缩包路径
        @param args['filenames'] 文件名列表，数组格式
        @return dict
        '''
        sfile = args.sfile
        filenames = args.filenames

        return public.returnMsg(False,'RAR压缩包文件不支持删除文件')

    def write_zip_file(self,args):
        '''
        @name 写入压缩包内文件
        @param args['path'] 压缩包路径
        @param args['filename'] 文件名
        @param args['data'] 写入数据
        @return dict
        '''

        sfile = args.sfile
        filename = args.filename
        data = args.data
        return public.returnMsg(False,'RAR压缩包不支持此功能!')

    def extract_byfiles(self,args):
        """
        @name 解压部分文件
        @param args['path'] 压缩包路径
        @param args['extract_path'] 解压路径
        @param args['filenames'] 文件名列表，数组格式
        """
        sfile = args.sfile
        filenames = args.filenames
        extract_path = args.extract_path
        if not os.path.exists(sfile):
            return public.returnMsg(False,'FILE_NOT_EXISTS')

        if not os.path.exists(extract_path):
            os.makedirs(extract_path,384)

        if self.__check_tamper(sfile) is True and self.__check_tamper_white() is False:
            return public.returnMsg(False, "该文件已开启防篡改！无法解压！")

        tmp_path = '{}/tmp/{}'.format(public.get_soft_path(),public.md5(public.GetRandomString(32)))
        if not os.path.exists(tmp_path):
            os.makedirs(tmp_path,384)

        with rarfile.RarFile(sfile) as zip_file:
            try:
                file_dict = {}

                f_infos = zip_file.infolist()
                f_infos = sorted(f_infos,key=lambda x:x.filename)
                for item in f_infos:
                    filename = self.__get_zip_filename(item)

                    if filename not in filenames: continue
                    filename = filename.rstrip("/")
                    spath = os.path.join(tmp_path, filename)
                    dir_key = os.path.dirname(spath)
                    name = os.path.basename(filename)

                    if item.flag_bits == 32:
                        if file_dict.get(dir_key) is not None:
                            file_dict[spath] = os.path.join(file_dict.get(dir_key), name) + "/"
                        else:
                            file_dict[spath] = name + "/"
                    else:
                        if file_dict.get(dir_key) is not None:
                            file_dict[spath] = os.path.join(file_dict.get(dir_key), name)
                        else:
                            file_dict[spath] = os.path.join(extract_path, name)

                    zip_file.extract(filename, tmp_path)
                for path, unzip_path in file_dict.items():
                    if unzip_path is None: continue
                    result_path = os.path.join(extract_path, unzip_path)
                    if not os.path.exists(os.path.dirname(result_path)):
                        os.makedirs(os.path.dirname(result_path), 384)
                    try:
                        shutil.copyfile(path, result_path)
                    except:
                        pass

                shutil.rmtree(tmp_path, True)
            except:
                shutil.rmtree(tmp_path, True)
                return public.returnMsg(False,'解压失败,error:' + public.get_error_info())
        return public.returnMsg(True,'文件解压成功')

    def add_zip_file(self,args):
        '''
        @name 添加文件到压缩包
        @param args['r_path'] 跟路径
        @param args['filename'] 文件名
        @param args['f_list'] 写入数据
        @return dict
        '''

        sfile = args.sfile
        r_path = args.r_path
        f_list = args.f_list
        return public.returnMsg(False,'RAR压缩包不支持此功能!')



    def __get_zip_filename(self,item):
        '''
        @name 获取压缩包文件名
        @param item 压缩包文件对象
        @return string
        '''
        filename = item.filename
        try:
            filename = item.filename.encode('cp437').decode('gbk')
        except:pass
        if item.flag_bits == 32:
            filename  += '/'

        return filename.replace('\\','/')

    # 防篡改：获取文件是否在保护列表中
    def __check_tamper(self, sfile) -> bool:
        import PluginLoader
        args = public.dict_obj()
        args.client_ip = public.GetClientIp()
        args.fun = "check_dir_safe"
        args.s = "check_dir_safe"
        args.file_data = {
            "base_path": os.path.dirname(sfile),
            "dirs": [],
            "files": [os.path.basename(sfile)]
        }
        tamper_data = PluginLoader.plugin_run("tamper_core", "check_dir_safe", args)
        tamper_status = tamper_data.get("files", [])
        if len(tamper_status) != 0:
            if str(tamper_status[0]).startswith("1"):
                return True
        return False

    # 防篡改：检查进程白名单，是否允许面板编辑
    def __check_tamper_white(self) -> bool:
        tamper = "/www/server/tamper/tamper.conf"
        if not os.path.isfile(tamper):
            return False
        try:
            tamper_info = json.loads(public.readFile(tamper))
        except:
            return False
        if "BT-Panel" in tamper_info["process_names"]:
            return True
        return False







