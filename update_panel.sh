#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
pyenv_bin=/www/server/panel/pyenv/bin
rep_path=${pyenv_bin}:$PATH
if [ -d "$pyenv_bin" ];then
	PATH=$rep_path
fi
export PATH
LANG=en_US.UTF-8

Font_Yellow='\033[1;33m'
Font_Suffix='\033[0m'

setup_path=/www
is64bit=$(getconf LONG_BIT)
if [ "${is64bit}" != '64' ];then
	echo "抱歉, 面板新版本不再支持32位系统, 无法进行升级";
	echo "退出、不做任何操作"
	exit 1
fi
Centos6Check=$(cat /etc/redhat-release | grep ' 6.' | grep -iE 'centos|Red Hat')
if [ "${Centos6Check}" ];then
	echo "Centos6不支持升级宝塔面板，建议备份数据重装更换Centos7/8安装宝塔面板"
	exit 1
fi 


up_plugin=0

download_file(){
    dst_file=$1
    tmp_file=/tmp/bt_tmp_file.temp
    if [ -f $tmp_file ];then
        rm -f $tmp_file
    fi
    wget -O ${tmp_file} $2 -T 20
    tmp_size=$(du -b $tmp_file|awk '{print $1}')
    if [ $tmp_size -lt 10 ];then
        echo "|-文件下载失败 $dst_file"
        return
    fi

    if [ -f $dst_file ];then
        rm -f $dst_file
    fi

    mv -f $tmp_file $dst_file

    if [ -f $tmp_file ];then
        rm -f $tmp_file
    fi
}

Red_Error(){
	echo '=================================================';
	printf '\033[1;31;40m%b\033[0m\n' "$1";
	exit 0;
}

check_panel(){
    if [ ! -d /www/server/panel/BTPanel ];then
        up_plugin=1
    fi
}

select_node(){
    public_file=/www/server/panel/install/public.sh
    if [ ! -f $public_file ];then
        download_file $public_file https://io.bt.sb/install/public.sh
    fi

    publicFileMd5=$(md5sum ${public_file}|awk '{print $1}')
    md5check="db0bc4ee0d73c3772aa403338553ff77"
    if [ "${publicFileMd5}" != "${md5check}"  ]; then
        download_file $public_file https://io.bt.sb/install/public.sh
    fi

    . $public_file

    download_Url=$NODE_URL
	downloads_Url=http://io.bt.sb
}

get_version(){
    if [ -n "$version" ]; then
        return
    fi
    version=$(curl -Ss --connect-timeout 5 -m 2 https://api.bt.sb/api/panel/get_version)
    if [ "$version" = '' ];then
        version='7.6.0'
    fi
}

if [ "$1" ];then
	version=$1
fi

install_pack(){
	if [ -f /usr/bin/yum ];then
		yum install libcurl-devel libffi-devel zlib-devel bzip2-devel openssl-devel ncurses-devel sqlite-devel readline-devel tk-devel gdbm-devel db4-devel libpcap-devel xz-devel -y
	else
		apt install libcurl4-openssl-dev net-tools swig build-essential libffi-dev zlib1g-dev libbz2-dev libssl-dev libncurses-dev libsqlite3-dev libreadline-dev tk-dev libgdbm-dev libdb-dev libdb++-dev libpcap-dev xz-utils -y
	fi
}

install_python(){
	curl -Ss --connect-timeout 3 -m 60 $download_Url/install/pip_select.sh|bash
	pyenv_path="/www/server/panel"
    python_bin=$pyenv_path/pyenv/bin/python
	if [ -f $pyenv_path/pyenv/bin/python ];then
		is_err=$($pyenv_path/pyenv/bin/python3.7 -V 2>&1|grep 'Could not find platform')
		if [ "$is_err" = "" ];then
			chmod -R 700 $pyenv_path/pyenv/bin
			is_package=$($python_bin -m psutil 2>&1|grep package)
			if [ "$is_package" = "" ];then
				wget -O $pyenv_path/pyenv/pip.txt $download_Url/install/pyenv/pip.txt -T 5
				$pyenv_path/pyenv/bin/pip install -U pip
				$pyenv_path/pyenv/bin/pip install -U setuptools
				$pyenv_path/pyenv/bin/pip install -r $pyenv_path/pyenv/pip.txt
			fi
			source $pyenv_path/pyenv/bin/activate
			return
		else
			rm -rf $pyenv_path/pyenv
		fi
	fi
    install_pack
	py_version="3.7.9"
	mkdir -p $pyenv_path
	os_type='el'
	os_version='7'
	is_export_openssl=0
	Get_Versions
	Centos6_Openssl
	Other_Openssl
	echo "OS: $os_type - $os_version"
	is_aarch64=$(uname -a|grep aarch64)
	if [ "$is_aarch64" != "" ];then
		os_version="aarch64"
	fi
	up_plugin=1

	if [ -f "/www/server/panel/pymake.pl" ];then
		os_version=""
		rm -f /www/server/panel/pymake.pl
	fi

	if [ "${os_version}" != "" ];then
		pyenv_file="/www/pyenv.tar.gz"
		wget -O $pyenv_file $download_Url/install/pyenv/pyenv-${os_type}${os_version}-x${is64bit}.tar.gz -T 10
		tmp_size=$(du -b $pyenv_file|awk '{print $1}')
		if [ $tmp_size -lt 703460 ];then
			rm -f $pyenv_file
			echo "ERROR: Download python env fielded."
		else
			echo "Install python env..."
			tar zxvf $pyenv_file -C $pyenv_path/ &> /dev/null
			chmod -R 700 $pyenv_path/pyenv/bin
			if [ ! -f $pyenv_path/pyenv/bin/python ];then
				rm -f $pyenv_file
				Red_Error "ERROR: Install python env fielded."
			fi
			is_err=$($pyenv_path/pyenv/bin/python3.7 -V 2>&1|grep 'Could not find platform')
			if [ "$is_err" = "" ];then
				rm -f $pyenv_file
				ln -sf $pyenv_path/pyenv/bin/pip3.7 /usr/bin/btpip
				ln -sf $pyenv_path/pyenv/bin/python3.7 /usr/bin/btpython
				sync_python_lib
				source $pyenv_path/pyenv/bin/activate
				return
			else
				rm -rf $pyenv_path/pyenv
			fi
		fi
	fi
	if [ -f /usr/local/openssl/lib/libssl.so ];then
		export LDFLAGS="-L/usr/local/openssl/lib"
		export CPPFLAGS="-I/usr/local/openssl/include"
		export PKG_CONFIG_PATH="/usr/local/openssl/lib/pkgconfig"
        echo "export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/openssl/lib" >> /etc/profile
		source /etc/profile
	fi
	cd /www
	python_src='/www/python_src.tar.xz'
	python_src_path="/www/Python-${py_version}"
	wget -O $python_src $download_Url/src/Python-${py_version}.tar.xz -T 5
	tmp_size=$(du -b $python_src|awk '{print $1}')
	if [ $tmp_size -lt 10703460 ];then
		rm -f $python_src
		Red_Error "ERROR: Download python source code fielded."
	fi
	tar xvf $python_src
	rm -f $python_src
	cd $python_src_path
	./configure --prefix=$pyenv_path/pyenv
	make -j$cpu_cpunt
	make install
	if [ ! -f $pyenv_path/pyenv/bin/python3.7 ];then
		rm -rf $python_src_path
		Red_Error "ERROR: Make python env fielded."
	fi
	cd ~
	rm -rf $python_src_path
	wget -O $pyenv_path/pyenv/bin/activate $download_Url/install/pyenv/activate.panel -T 5
	wget -O $pyenv_path/pyenv/pip.txt $download_Url/install/pyenv/pip.txt -T 5
	ln -sf $pyenv_path/pyenv/bin/pip3.7 $pyenv_path/pyenv/bin/pip
	ln -sf $pyenv_path/pyenv/bin/python3.7 $pyenv_path/pyenv/bin/python
    ln -sf $pyenv_path/pyenv/bin/pip3.7 /usr/bin/btpip
	ln -sf $pyenv_path/pyenv/bin/python3.7 /usr/bin/btpython
	chmod -R 700 $pyenv_path/pyenv/bin
	$pyenv_path/pyenv/bin/pip install -U pip
	$pyenv_path/pyenv/bin/pip install -U setuptools
	$pyenv_path/pyenv/bin/pip install -r $pyenv_path/pyenv/pip.txt
    sync_python_lib
	source $pyenv_path/pyenv/bin/activate
}

sync_python_lib(){
    pip_list=$(pip list 2>/dev/null|grep -v Package|grep -v '\-\-\-\-\-\-'|awk '{print $1}'|xargs)
    $pyenv_path/pyenv/bin/pip install -U pip setuptools
    $pyenv_path/pyenv/bin/pip install $pip_list
}

Other_Openssl(){
	openssl_version=$(openssl version|grep -Eo '[0-9]\.[0-9]\.[0-9]')
	if [ "$openssl_version" = '1.0.1' ] || [ "$openssl_version" = '1.0.0' ];then	
		opensslVersion="1.0.2r"
		if [ ! -f "/usr/local/openssl/lib/libssl.so" ];then
			cd /www
			openssl_src_file=/www/openssl.tar.gz
			wget -O $openssl_src_file ${download_Url}/src/openssl-${opensslVersion}.tar.gz
			tmp_size=$(du -b $openssl_src_file|awk '{print $1}')
			if [ $tmp_size -lt 703460 ];then
				rm -f $openssl_src_file
				Red_Error "ERROR: Download openssl-1.0.2 source code fielded."
			fi
			tar -zxf $openssl_src_file
			rm -f $openssl_src_file
			cd openssl-${opensslVersion}
			./config --openssldir=/usr/local/openssl zlib-dynamic shared
			make -j${cpuCore} 
			make install
			echo  "/usr/local/openssl/lib" > /etc/ld.so.conf.d/zopenssl.conf
			ldconfig
			cd ..
			rm -rf openssl-${opensslVersion}
			is_export_openssl=1
			cd ~
		fi
	fi
}

Insatll_Libressl(){
	openssl_version=$(openssl version|grep -Eo '[0-9]\.[0-9]\.[0-9]')
	if [ "$openssl_version" = '1.0.1' ] || [ "$openssl_version" = '1.0.0' ];then	
		opensslVersion="3.0.2"
		cd /www
		openssl_src_file=/www/openssl.tar.gz
		wget -O $openssl_src_file ${download_Url}/install/pyenv/libressl-${opensslVersion}.tar.gz
		tmp_size=$(du -b $openssl_src_file|awk '{print $1}')
		if [ $tmp_size -lt 703460 ];then
			rm -f $openssl_src_file
			Red_Error "ERROR: Download libressl-$opensslVersion source code fielded."
		fi
		tar -zxf $openssl_src_file
		rm -f $openssl_src_file
		cd libressl-${opensslVersion}
		./config –prefix=/usr/local/lib
		make -j${cpuCore}
		make install
		ldconfig
		ldconfig -v
		cd ..
		rm -rf libressl-${opensslVersion}
		is_export_openssl=1
		cd ~
	fi
}

Centos6_Openssl(){
	if [ "$os_type" != 'el' ];then
		return
	fi
	if [ "$os_version" != '6' ];then
		return
	fi
	echo 'Centos6 install openssl-1.0.2...'
	openssl_rpm_file="/www/openssl.rpm"
	wget -O $openssl_rpm_file $download_Url/rpm/centos6/${is64bit}/bt-openssl102.rpm -T 10
	tmp_size=$(du -b $openssl_rpm_file|awk '{print $1}')
	if [ $tmp_size -lt 102400 ];then
		rm -f $openssl_rpm_file
		Red_Error "ERROR: Download python env fielded."
	fi
	rpm -ivh $openssl_rpm_file
	rm -f $openssl_rpm_file
	is_export_openssl=1
}

Get_Versions(){
	redhat_version_file="/etc/redhat-release"
	deb_version_file="/etc/issue"
	if [ -f $redhat_version_file ];then
		os_type='el'
		is_aliyunos=$(cat $redhat_version_file|grep Aliyun)
		if [ "$is_aliyunos" != "" ];then
			return
		fi
		os_version=$(cat $redhat_version_file|grep CentOS|grep -Eo '([0-9]+\.)+[0-9]+'|grep -Eo '^[0-9]')
		if [ "${os_version}" = "5" ];then
			os_version=""
		fi
	else
		os_type='ubuntu'
		os_version=$(cat $deb_version_file|grep Ubuntu|grep -Eo '([0-9]+\.)+[0-9]+'|grep -Eo '^[0-9]+')
		if [ "${os_version}" = "" ];then
			os_type='debian'
			os_version=$(cat $deb_version_file|grep Debian|grep -Eo '([0-9]+\.)+[0-9]+'|grep -Eo '[0-9]+')
			if [ "${os_version}" = "" ];then
				os_version=$(cat $deb_version_file|grep Debian|grep -Eo '[0-9]+')
			fi
			if [ "${os_version}" = "8" ];then
				os_version=""
			fi
			if [ "${is64bit}" = '32' ];then
				os_version=""
			fi
		fi
	fi
}

update_panel(){
    wget -T 5 -O /tmp/panel.zip $downloads_Url/install/update/LinuxPanel-${version}.zip
    chattr -i /www/server/panel/data/userInfo.json
    dsize=$(du -b /tmp/panel.zip|awk '{print $1}')
    if [ $dsize -lt 10240 ];then
        echo "获取更新包失败，请及时联系 TG群组：@rsakuras 或者 QQ群组：1042692095 进行反馈！"
        exit;
    fi
    unzip -o /tmp/panel.zip -d $setup_path/server/ > /dev/null 2>&1
    rm -f /tmp/panel.zip
	sed -i 's/[0-9\.]\+[ ]\+www.bt.cn//g' /etc/hosts
	sed -i 's/[0-9\.]\+[ ]\+api.bt.sb//g' /etc/hosts
	#wget -O /www/server/panel/data/softList.conf ${download_Url}/install/conf/softListtls10.conf
    if [ "$version" = "11.0.0" ]; then
        echo "检测到指定版本为11.0.0，正在下载新版 softList 配置..."
        wget -O /www/server/panel/data/softList.conf ${download_Url}/install/conf/softListtls10.conf
    fi	
	cd $setup_path/server/panel/
    check_bt=`cat /etc/init.d/bt|grep BT-Task`
    if [ "${check_bt}" = "" ];then
        rm -f /etc/init.d/bt
        wget -O /etc/init.d/bt $download_Url/install/src/bt7.init -T 20
        chmod +x /etc/init.d/bt
    fi
    rm -f /www/server/panel/*.pyc
    rm -f /www/server/panel/class/*.pyc
    if [ ! -f $setup_path/server/panel/config/config.json ];then
        wget -T 5 -O $setup_path/server/panel/config/config.json $download_Url/install/pyenv/config/config.json
        wget -T 5 -O $setup_path/server/panel/config/dns_api.json $download_Url/install/pyenv/config/dns_api.json
    fi

    chattr -i /etc/init.d/bt
    chmod +x /etc/init.d/bt
    # if [ $up_plugin = 1 ];then
    #     $pyenv_bin/python /www/server/panel/tools.py update_to6
    # fi
}

update_start(){
    echo "====================================="
    echo "开始升级宝塔Linux面板，请稍候..."
    echo "====================================="
}


update_end(){
    echo "====================================="

    rm -f /dev/shm/bt_sql_tips.pl
    #echo > /www/server/panel/data/bind.pl
    rm -rf /www/server/panel/data/bind.pl

    rm -rf /www/server/panel/class/pluginAuth.cpython-37m-aarch64-linux-gnu.so
    rm -rf /www/server/panel/class/pluginAuth.cpython-37m-i386-linux-gnu.so
    rm -rf /www/server/panel/class/pluginAuth.cpython-37m-loongarch64-linux-gnu.so
    rm -rf /www/server/panel/class/pluginAuth.cpython-37m-x86_64-linux-gnu.so
    rm -rf /www/server/panel/class/pluginAuth.cpython-310-aarch64-linux-gnu.so
    rm -rf /www/server/panel/class/pluginAuth.cpython-310-x86_64-linux-gnu.so
    rm -rf /www/server/panel/class/pluginAuth.so
    #rm -rf /www/server/panel/class/pluginAuth.py

    rm -rf /www/server/panel/class/libAuth.aarch64.so
    rm -rf /www/server/panel/class/libAuth.glibc-2.14.x86_64.so
    rm -rf /www/server/panel/class/libAuth.loongarch64.so
    rm -rf /www/server/panel/class/libAuth.x86-64.so
    rm -rf /www/server/panel/class/libAuth.x86.so

    #rm -rf /www/server/panel/class/PluginLoader.aarch64.Python3.7.so
    #rm -rf /www/server/panel/class/PluginLoader.i686.Python3.7.so
    #rm -rf /www/server/panel/class/PluginLoader.loongarch64.Python3.7.so
    #rm -rf /www/server/panel/class/PluginLoader.so
    rm -rf /www/server/panel/class/PluginLoader.s390x.Python3.7.so
    #rm -rf /www/server/panel/class/PluginLoader.x86_64.glibc214.Python3.7.so
    #rm -rf /www/server/panel/class/PluginLoader.x86_64.Python3.7.so

    rm -f /dev/shm/bt_sql_tips.pl
    kill $(ps aux|grep -E "task.py|main.py"|grep -v grep|awk '{print $2}') &>/dev/null
    bash /www/server/panel/init.sh start
    echo 'True' > /www/server/panel/data/restart.pl
    pkill -9 gunicorn &>/dev/null &
    
    echo -e "\033[32m=================================="
    echo -e "            赞助商广告              "
    echo -e "==================================\n"

    # DreamCloud 广告 托管商
    echo -e "\033[36mDreamCloud \033[31m★【亚太推荐】★\033[34m"
    echo -e "日本高防中国优化服务器，低至\$12.75 USD/月，海外 2Tbps+ 中国 100Gbps"
    echo -e "https://whmcs.as211392.com/LiteCore-EPYC-NEW?aff=1\n"

    # KURUN CLOUD 广告 托管商
    echo -e "\033[35mKURUN CLOUD \033[31m★【欧美推荐】★\033[35m"
    echo -e "美国洛杉矶 CN2GIA+CUPM9929+CMIN2 三网精品回国线路服务器 ★★★ 特价促销中 ★★★ KURUN CLOUD机房直销 最快回国线路 超稳定"
    echo -e "https://www.kurun.com/aff/HRZUXBJP"
    echo -e "TG: https://t.me/kuruncloud\n"

    # 金盾高防CDN 广告 永久
    echo -e "\033[32m金盾高防CDN 亚太及全球加速节点 被打死三天内无法处理则全部退款"
    echo -e "https://www.jinduncdn.com"
    echo -e "TG: @boos40\n"

    # 不死鸟CDN 广告（绿色） 2026 8.25 到期
    echo -e "\033[32m不死鸟CDN ★【CDN推荐】★"
    echo -e "不死鸟CDN•香港日本高防CDN，免实名/免备案，攻击打不死，专接扛不住！"
    echo -e "https://www.bsncdn.org"
    echo -e "TG频道: https://t.me/bsncdn001\n"

    # 广告投放价格说明
    echo -e "\n\033[31m脚本/官网 或 群组/频道广告 投放价格：300U /月、2500U /年、5000U /长期\033[0m\n"

    # 注意事项
    echo -e "\033[32m注意：我们不接受面板插入广告，只接受脚本、群组、频道、论坛官网 等广告投放！\033[0m\n"

    # 转账地址
    echo -e "\033[33m需要广告位 转账 TRC20：\033[95mTCYL5ZKJhkXyCNvy3bnbiCHuAa7yKWLDWc\033[0m\n"

    # 联系方式
    echo -e "\033[32m转完之后联系 @pingping_520 发送需要投放的广告内容\033[0m\n"

    echo -e "\033[32m==================================\033[0m\n"

    echo -e "\033[36m已成功升级到 [$version]企业版\033[0m";

# 调用接口获取统计信息
response=$(curl -s --connect-timeout 5 --max-time 10 "https://tj.bt.sb/api/count?param=bt&token=6920626369b1f05844f5e3d6f93b5f6e" 2>/dev/null)

# 检查curl请求是否成功
if [ $? -eq 0 ] && [ -n "$response" ]; then
    # 检查 Python 版本
    if command -v python3 &>/dev/null; then
        # 使用 Python 3 解析 JSON
        TodayRunTimes=$(echo "$response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('today_count', 'N/A'))
except (json.JSONDecodeError, KeyError, Exception):
    print('N/A')
" 2>/dev/null)
        TotalRunTimes=$(echo "$response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('total_count', 'N/A'))
except (json.JSONDecodeError, KeyError, Exception):
    print('N/A')
" 2>/dev/null)
    elif command -v python &>/dev/null; then
        # 使用 Python 2 解析 JSON
        TodayRunTimes=$(echo "$response" | python -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print data.get('today_count', 'N/A')
except (ValueError, KeyError, Exception):
    print 'N/A'
" 2>/dev/null)
        TotalRunTimes=$(echo "$response" | python -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print data.get('total_count', 'N/A')
except (ValueError, KeyError, Exception):
    print 'N/A'
" 2>/dev/null)
    else
        TodayRunTimes="N/A"
        TotalRunTimes="N/A"
    fi

    if [ "$TodayRunTimes" != "N/A" ] && [ "$TotalRunTimes" != "N/A" ]; then
        echo ""
        echo -e "${Font_Yellow}脚本当天运行次数: ${TodayRunTimes}; 共计运行次数: ${TotalRunTimes} ${Font_Suffix}"
        echo ""
    fi
fi
}
rm -rf /www/server/phpmyadmin/pma
    
update_start
check_panel
select_node
install_python
get_version
update_panel
update_end


