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

import os
import json
import shutil
import datetime
import zipfile

from filesModel.base import filesBase
import public

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
            zip_file = zipfile.ZipFile(sfile)
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
            file_name = self.__get_zip_filename(item)

            temp_list = file_name.lstrip("./").split("/")

            sub_data = data
            for name in temp_list:
                if not name: continue
                if name not in sub_data:
                    if file_name.endswith(name):
                        sub_data[name] = {
                            'file_size': item.file_size,
                            'compress_size': item.compress_size,
                            'compress_type': item.compress_type,
                            'filename': name,
                            'fullpath': file_name,
                            'date_time': datetime.datetime(*item.date_time).strftime("%Y-%m-%d %H:%M:%S"),
                            'is_dir': 1 if item.is_dir() else 0
                        }
                    else:
                        sub_data[name] = {}
                sub_data = sub_data[name]

        zip_file.close()
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
        with zipfile.ZipFile(sfile,'r') as zip_file:
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
        if not os.path.exists(sfile):
            return public.returnMsg(False,'FILE_NOT_EXISTS')

        with zipfile.ZipFile(sfile,'r') as zip_file:
            with zipfile.ZipFile(sfile + '.tmp','w',zipfile.ZIP_DEFLATED) as new_zfile:
                for item in zip_file.infolist():
                    filename = self.__get_zip_filename(item)

                    if filename in filenames:
                        continue
                    src_name = item.filename
                    item.filename = filename
                    new_zfile.writestr(item,zip_file.read(src_name))
        shutil.move(sfile + '.tmp',sfile)
        return public.returnMsg(True,'文件删除成功')

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
        if not os.path.exists(sfile):
            return public.returnMsg(False,'FILE_NOT_EXISTS')

        if self.__check_tamper(sfile) is True and self.__check_tamper_white() is False:
            return public.returnMsg(False, "该文件已开启防篡改！无法解压！")

        with zipfile.ZipFile(sfile,'r') as zip_file:
            with zipfile.ZipFile(sfile + '.tmp','w',zipfile.ZIP_DEFLATED) as new_zfile:
                for item in zip_file.infolist():
                    z_filename = self.__get_zip_filename(item)
                    if z_filename == filename:
                        continue

                    new_zfile.writestr(item,zip_file.read(item.filename))
                new_zfile.writestr(filename, data=data, compress_type=zipfile.ZIP_DEFLATED)

        shutil.move(sfile + '.tmp',sfile)
        return public.returnMsg(True,'文件写入成功')


    def extract_byfiles(self,args):
        """
        @name 解压部分文件
        @param args['path'] 压缩包路径
        @param args['extract_path'] 解压路径
        @param args['filenames'] 文件名列表，数组格式
        """

        zip_path = ''
        if 'zip_path' in args: zip_path = args.zip_path
        sfile = args.sfile
        filenames = args.filenames
        extract_path = args.extract_path
        if not os.path.exists(sfile):
            return public.returnMsg(False,'FILE_NOT_EXISTS')

        if self.__check_tamper(sfile) is True and self.__check_tamper_white() is False:
            return public.returnMsg(False, "该文件已开启防篡改！无法解压！")

        if not os.path.exists(extract_path):
            os.makedirs(extract_path,384)

        tmp_path = '{}/tmp/{}'.format(public.get_soft_path(),public.md5(public.GetRandomString(32)))
        if not os.path.exists(tmp_path):
            os.makedirs(tmp_path,384)

        try:
            with zipfile.ZipFile(sfile) as zip_file:
                exists_list = []

                for item in zip_file.infolist():
                    filename = self.__get_zip_filename(item)
                    if item.filename != filename:
                        item.filename = filename

                    unzip_path = None
                    for unzip_item in filenames:
                        if isinstance(unzip_item, dict):
                            # file_name = unzip_item["zip_file_path"]
                            unzip_path = unzip_item["file_path"]
                            if unzip_item['zip_file_path'] == filename:
                                break
                        elif unzip_item == filename:
                            if item.is_dir():
                                unzip_path = os.path.join(extract_path, filename)
                            else:
                                unzip_path = os.path.join(extract_path, os.path.basename(filename))
                            break
                        elif unzip_item[-1] == "/" and filename.startswith(unzip_item):
                            unzip_path = os.path.join(extract_path, filename)
                            break
                    else:
                        continue
                    
                    temp_unzip_path = os.path.join(tmp_path, filename)
                    if os.path.exists(unzip_path): # 存在重名文件
                        if item.is_dir(): continue
                        if not hasattr(args, "type"):
                            exists_file = {
                                # 文件信息
                                "name": os.path.basename(unzip_path),
                                "file_path": unzip_path,
                                "file_size": os.path.getsize(unzip_path),
                                "file_mtime": datetime.datetime.fromtimestamp(os.path.getmtime(unzip_path)).strftime("%Y-%m-%d %H:%M:%S"),
                                # 压缩包内信息
                                "zip_file_path": filename,
                                "zip_file_size": item.file_size,
                                "zip_file_mtime": datetime.datetime(*item.date_time).strftime("%Y-%m-%d %H:%M:%S"),
                            }
                            exists_list.append(exists_file)
                            continue

                        if str(getattr(args, "type", "0")) == "1": # 覆盖
                            zip_file.extract(item, tmp_path, pwd=getattr(args, "password", None))
                        elif str(getattr(args, "type", "0")) == "2": # 重命名源文件
                            zip_file.extract(item, tmp_path, pwd=getattr(args, "password", None))
                            base_name = os.path.basename(unzip_path)
                            dir_name = os.path.dirname(unzip_path)

                            idx = 1
                            name,ext = os.path.splitext(base_name)
                            new_name = name + "({})".format(idx) + ext
                            unzip_path = os.path.join(dir_name, new_name)
                            idx += 1
                            while os.path.exists(unzip_path):
                                new_name = name + "({})".format(idx) + ext
                                unzip_path = os.path.join(dir_name, new_name)
                                idx += 1
                            if os.path.exists(temp_unzip_path):
                                new_temp_unzip_path = os.path.join(os.path.dirname(temp_unzip_path), new_name)
                                os.rename(temp_unzip_path, new_temp_unzip_path)
                                temp_unzip_path = new_temp_unzip_path
                        else: # 跳过
                            continue
                    else:
                        zip_file.extract(item, tmp_path, pwd=getattr(args, "password", None))

                    dir_name = os.path.dirname(unzip_path)
                    if not os.path.exists(dir_name):
                        os.makedirs(dir_name)
                        
                    shutil.move(temp_unzip_path, unzip_path)
                if len(exists_list) != 0:
                    return {"status": True, "msg": "文件已存在是否覆盖?", "data" : exists_list, "type": 1}
        except zipfile.BadZipfile:
            return public.returnMsg(False, "请解压 zip 压缩文件！")
        except RuntimeError as err:
            if str(err).find("is encrypted"):
                return public.returnMsg(False, '解压密码错误！')
            else:
                return public.returnMsg(False, '解压失败,error:' + public.get_error_info())
        finally:
            shutil.rmtree(tmp_path, True)
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
        if not os.path.exists(sfile):
            return public.returnMsg(False,'FILE_NOT_EXISTS')

        #追加原路径
        src_list = {}
        for fname in f_list:
            if os.path.isdir(fname):
                s_list = []
                public.get_file_list(fname,s_list)

                for f in s_list:
                    if os.path.isdir(f):
                        continue
                    src_file = '{}/{}{}'.format(r_path,os.path.basename(fname),f.replace(fname,''))
                    src_list[src_file] = f
            else:
                src_file = r_path + '/' + os.path.basename(fname)
                src_list[src_file] = fname

        tmp_path = sfile + '.tmp'
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

        with zipfile.ZipFile(sfile,'r') as zip_file:
            with zipfile.ZipFile(tmp_path,'w',zipfile.ZIP_DEFLATED) as new_zfile:
                try:
                    #过滤旧文件
                    for item in zip_file.infolist():
                        if item in src_list:
                            continue
                        new_zfile.writestr(item,zip_file.read(item))

                    #追加新文件
                    for src_file in src_list:
                        new_zfile.write(src_list[src_file],src_file)
                except:
                    return public.returnMsg(False,'添加文件失败,error:' + public.get_error_info())

        shutil.move(tmp_path,sfile)
        return public.returnMsg(True,'压缩包文件修改成功')

    def __get_zip_filename(self, item):
        '''
        @name 获取压缩包文件名
        @param item 压缩包文件对象
        @return string
        '''
        path = item.filename
        try:
            path_name = path.encode('cp437').decode('utf-8')
        except:
            try:
                path_name = path.encode('cp437').decode('gbk')
                path_name = path_name.encode('utf-8').decode('utf-8')
            except:
                path_name = path

        return path_name


    # def __get_zip_filename(self,item) -> str:
    #     '''
    #     @name 获取压缩包文件名
    #     @param item 压缩包文件对象
    #     @return string
    #     '''
    #
    #
    #     filename = item.filename
    #     try:
    #         filename = item.filename.encode('cp437').decode('utf-8')
    #     except:pass
    #     return filename

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



