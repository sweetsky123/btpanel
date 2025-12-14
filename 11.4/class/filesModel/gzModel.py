# coding: utf-8
# -------------------------------------------------------------------
# 宝塔Linux面板
# -------------------------------------------------------------------
# Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
# -------------------------------------------------------------------
# Author: cjxin <cjxin@bt.cn>
# -------------------------------------------------------------------

#
# ------------------------------

import os
import json
import shutil
import datetime
import tarfile

from filesModel.base import filesBase
import public


class main(filesBase):

    def __init__(self):
        pass

    def __check_zipfile(self, sfile, is_close=False):
        '''
        @name 检查文件是否为zip文件
        @param sfile 文件路径
        @return bool
        '''

        pass

    def get_zip_files(self, args):
        '''
        @name 获取压缩包内文件列表
        @param args['path'] 压缩包路径
        @return list
        '''
        sfile = args.sfile
        if not os.path.exists(sfile):
            return public.returnMsg(False, 'FILE_NOT_EXISTS')

        if not tarfile.is_tarfile(sfile):
            if sfile[-3:] == ".gz":
                return public.returnMsg(False, '这不是tar.gz压缩包文件, gz压缩包文件不支持预览,仅支持解压')
            return public.returnMsg(False, '不是有效的tar.gz压缩包文件')

        zip_file = tarfile.open(sfile)
        data = {}
        for item in zip_file.getmembers():
            file_name = self.__get_zip_filename(item)

            # temp_list = file_name.lstrip("./").split("/")
            temp_list = file_name.split("/")

            sub_data = data
            for name in temp_list:
                if not name: continue
                if name not in sub_data:
                    if file_name.endswith(name) and not ".{}".format(name) in file_name:
                        sub_data[name] = {
                            'file_size': item.size,
                            'filename': name,
                            'fullpath': file_name,
                            'date_time': public.format_date(times=item.mtime),
                            'is_dir': 1 if item.isdir() else 0
                        }
                    else:
                        sub_data[name] = {}
                sub_data = sub_data[name]

        return data

    def get_fileinfo_by(self, args):
        '''
        @name 获取压缩包内文件信息
        @param args['path'] 压缩包路径
        @param args['filename'] 文件名
        @return dict
        '''

        sfile = args.sfile
        filename = args.filename
        if not os.path.exists(sfile):
            return public.returnMsg(False, 'FILE_NOT_EXISTS')

        tmp_path = '{}/tmp/{}'.format(public.get_panel_path(), public.md5(sfile + filename))
        result = {}
        result['status'] = True
        result['data'] = ''
        with tarfile.open(sfile, 'r') as zip_file:
            try:
                zip_file.extract(filename, tmp_path)
                result['data'] = public.readFile('{}/{}'.format(tmp_path, filename))
            except:
                pass
        try:
            public.rmdir(tmp_path)
        except:
            pass
        return result

    def delete_zip_file(self, args):
        '''
        @name 删除压缩包内文件
        @param args['path'] 压缩包路径
        @param args['filenames'] 文件名列表，数组格式
        @return dict
        '''
        sfile = args.sfile
        filenames = args.filenames

        if not tarfile.is_tarfile(sfile):
            return public.returnMsg(False, '不是有效的tar.gz压缩包文件')

        tmp_path = self.__unzip_tmp_path(sfile)
        if not tmp_path: return public.returnMsg(False, '修改失败!')

        # 组装原有的文件
        s_list = []
        src_list = {}
        public.get_file_list(tmp_path, s_list)
        for f in s_list:
            if not os.path.isfile(f): continue
            src_file = f.replace(tmp_path, '').strip('/')
            if src_file in filenames:
                continue
            src_list[src_file] = f

        with tarfile.open(sfile, 'w') as new_zfile:
            try:
                for src_file in src_list:
                    new_zfile.add(src_list[src_file], src_file)
            except:
                shutil.rmtree(tmp_path, True)
                return public.returnMsg(False, '删除文件失败,error:' + public.get_error_info())

        shutil.rmtree(tmp_path, True)
        return public.returnMsg(True, '压缩包文件修改成功')

    def write_zip_file(self, args):
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
            return public.returnMsg(False, 'FILE_NOT_EXISTS')

        if self.__check_tamper(sfile) is True and self.__check_tamper_white() is False:
            return public.returnMsg(False, "该文件已开启防篡改！无法解压！")

        tmp_path = self.__unzip_tmp_path(sfile)
        if not tmp_path: return public.returnMsg(False, '修改失败!')
        public.writeFile('{}/{}'.format(tmp_path, filename), data)

        # 组装原有的文件
        s_list = []
        src_list = {}
        public.get_file_list(tmp_path, s_list)
        for f in s_list:
            if os.path.isdir(f):
                continue
            src_file = f.replace(tmp_path, '').strip('/')
            if src_file in src_list:
                continue
            src_list[src_file] = f

        with tarfile.open(sfile, 'w') as new_zfile:
            try:
                for src_file in src_list:
                    new_zfile.add(src_list[src_file], src_file)
            except:
                shutil.rmtree(tmp_path, True)
                return public.returnMsg(False, '修改文件失败,error:' + public.get_error_info())

        shutil.rmtree(tmp_path, True)
        return public.returnMsg(True, '压缩包文件修改成功')

    def extract_byfiles(self, args):
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
            return public.returnMsg(False, 'FILE_NOT_EXISTS')

        if not tarfile.is_tarfile(sfile):
            if sfile[-3:] == ".gz":
                return public.returnMsg(False, '这不是tar.gz压缩包文件, gz压缩包文件不支持预览,仅支持解压')
            return public.returnMsg(False, '不是有效的tar.gz压缩包文件')

        if not os.path.exists(extract_path) or not os.path.isdir(extract_path):
            public.ExecShell("mkdir -p {}".format(extract_path))

        if self.__check_tamper(sfile) is True and self.__check_tamper_white() is False:
            return public.returnMsg(False, "该文件已开启防篡改！无法解压！")

        tmp_path = '{}/tmp/{}'.format(public.get_panel_path(), public.md5(public.GetRandomString(32)))
        if not os.path.exists(tmp_path) or not os.path.isdir(tmp_path):
            public.ExecShell("mkdir -p {}".format(tmp_path))
        try:
            with tarfile.open(sfile) as zip_file:
                exists_list = []

                for item in zip_file.getmembers():
                    dddir = ""
                    filename = self.__get_zip_filename(item)
                    if item.name != filename:
                        item.name = filename

                    unzip_path = None
                    for unzip_item in filenames:
                        if isinstance(unzip_item, str):
                            dddir = ""
                            if "/dddir" in unzip_item:
                                dddir = "/{}/".format(unzip_item.replace("/dddir", ""))
                                unzip_item = unzip_item.replace("/dddir", "")

                            if args.zip_path != "":
                                unzip_item = args.zip_path + "/" + unzip_item

                        if isinstance(unzip_item, dict):
                            # file_name = unzip_item["zip_file_path"]
                            unzip_path = unzip_item["file_path"]
                            if unzip_item["zip_file_path"] == filename:
                                break
                        elif unzip_item == filename:
                            if item.isdir():
                                unzip_path = os.path.join(extract_path, filename)
                            else:
                                unzip_path = os.path.join(extract_path, os.path.basename(filename))
                            break
                        elif dddir != "" and filename.startswith("{}/".format(unzip_item)):
                            unzip_path = os.path.join(extract_path, filename)
                            break

                    if unzip_path is None:
                        continue
                    
                    temp_unzip_path = os.path.join(tmp_path, filename)
                    if os.path.exists(unzip_path):  # 存在重名文件
                        if args.get("zip_path") != os.path.dirname(filename) or os.path.basename(unzip_path) != os.path.basename(filename): continue
                        if item.isdir(): continue
                        if not hasattr(args, "type"):
                            exists_file = {
                                # 文件信息
                                "name": os.path.basename(unzip_path),
                                "file_path": unzip_path,
                                "file_size": os.path.getsize(unzip_path),
                                "file_mtime": datetime.datetime.fromtimestamp(os.path.getmtime(unzip_path)).strftime("%Y-%m-%d %H:%M:%S"),
                                # 压缩包内信息
                                "zip_file_path": filename,
                                "zip_file_size": item.size,
                                "zip_file_mtime": datetime.datetime.fromtimestamp(item.mtime).strftime("%Y-%m-%d %H:%M:%S"),
                            }
                            exists_list.append(exists_file)
                            continue

                        if str(getattr(args, "type", "0")) == "1":  # 覆盖
                            zip_file.extract(item, tmp_path)
                        elif str(getattr(args, "type", "0")) == "2":  # 重命名源文件
                            zip_file.extract(item, tmp_path)
                            base_name = os.path.basename(unzip_path)
                            dir_name = os.path.dirname(unzip_path)

                            idx = 1
                            name, ext = os.path.splitext(base_name)
                            new_name = name + "({})".format(idx) + ext
                            unzip_path = os.path.join(dir_name, new_name)
                            while os.path.exists(unzip_path):
                                new_name = name + "({})".format(idx) + ext
                                unzip_path = os.path.join(dir_name, new_name)
                                idx += 1
                            if os.path.exists(temp_unzip_path):
                                new_temp_unzip_path = os.path.join(os.path.dirname(temp_unzip_path), new_name)
                                os.rename(temp_unzip_path, new_temp_unzip_path)
                                temp_unzip_path = new_temp_unzip_path
                        else:  # 跳过
                            continue
                    else:
                        zip_file.extract(item, tmp_path)

                    dir_name = os.path.dirname(unzip_path)
                    if args.get("type") or not dddir:
                        if not os.path.exists(dir_name) or not os.path.isdir(dir_name):
                            public.ExecShell("mkdir -p {}".format(dir_name))
                        if not item.isdir():
                            shutil.move(temp_unzip_path, unzip_path)
                    else:
                        shutil.move(temp_unzip_path, unzip_path)
                if not args.get("type") and dddir:
                    for i in os.listdir(tmp_path):
                        shutil.move("{}/{}".format(tmp_path, str(i)), extract_path)

                if len(exists_list) != 0:
                    return {"status": True, "msg": "文件已存在是否覆盖?", "data": exists_list, "type": 1}
        except RuntimeError as err:
            return public.returnMsg(False, '解压失败,error:' + public.get_error_info())
        finally:
            shutil.rmtree(tmp_path, True)
        return public.returnMsg(True, '文件解压成功')

    def __unzip_tmp_path(self, sfile):
        '''
        @name 获取临时解压路径
        @param sfile 压缩包路径
        @return str
        '''
        tmp_path = '{}/tmp/{}'.format(public.get_soft_path(), public.md5(public.GetRandomString(32)))
        with tarfile.open(sfile) as zip_file:
            try:
                zip_file.extractall(tmp_path)
            except:
                return False

        return tmp_path

    def add_zip_file(self, args):
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
            return public.returnMsg(False, 'FILE_NOT_EXISTS')

        tmp_path = self.__unzip_tmp_path(sfile)
        if not tmp_path: return public.returnMsg(False, '修改失败!')

        # 组装新添加的文件
        src_list = {}
        for fname in f_list:
            if os.path.isdir(fname):
                s_list = []
                public.get_file_list(fname, s_list)

                for f in s_list:
                    if os.path.isdir(f):
                        continue
                    src_file = '{}/{}{}'.format(r_path, os.path.basename(fname), f.replace(fname, '')).replace('//', '/')
                    src_list[src_file] = f
            else:
                src_file = '{}/{}'.format(r_path, os.path.basename(fname)).replace('//', '/')
                src_list[src_file] = fname

        # 组装原有的文件
        s_list = []
        public.get_file_list(tmp_path, s_list)
        for f in s_list:
            if os.path.isdir(f):
                continue
            src_file = f.replace(tmp_path, '').strip('/')
            if src_file in src_list:
                continue
            src_list[src_file] = f

        with tarfile.open(sfile, 'w') as new_zfile:
            try:
                for src_file in src_list:
                    new_zfile.add(src_list[src_file], src_file)
            except:
                shutil.rmtree(tmp_path, True)
                return public.returnMsg(False, '添加文件失败,error:' + public.get_error_info())

        shutil.rmtree(tmp_path, True)
        return public.returnMsg(True, '压缩包文件修改成功')

    def __get_zip_filename(self, item) -> str:
        '''
        @name 获取压缩包文件名
        @param item 压缩包文件对象
        @return string
        '''
        filename = item.name
        try:
            filename = item.name.encode('cp437').decode('gbk')
        except:
            pass
        if item.isdir():
            filename += '/'
        return filename

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
