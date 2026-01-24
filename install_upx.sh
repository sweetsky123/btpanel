#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
LANG=en_US.UTF-8

# UPX安装脚本
# Pyenv/Python-3.7.16/


# 通用下载链接
dlco=https://github.com/sweetsky123/btpanel/releases/download/common/
# ${dlco}
# 11.0下载链接
dl11=https://github.com/sweetsky123/btpanel/releases/download/11.0/
# ${dl11}
# lastest下载链接
dllt=https://github.com/sweetsky123/btpanel/releases/latest/download/
# ${dllt}
Font_Yellow='\033[1;33m'
Font_Suffix='\033[0m'

INSTALL_LOGFILE="/tmp/btpanel-install.log"
if [ -f "$INSTALL_LOGFILE" ];then
    rm -f $INSTALL_LOGFILE
fi
exec > >(tee -a "$INSTALL_LOGFILE") 2>&1 

CURL_CHECK=$(which curl)

signal_type=""
exit_msg() {
    case $signal_type in
        SIGINT)
            EXIT_MSG="捕获到Ctrl+C信号退出"
            ;;
        SIGTERM)
            EXIT_MSG="捕获到进程被杀死"
            ;;
        SIGHUP)
            EXIT_MSG="捕获到终端连接异常"
            ;;
        *)
            EXIT_MSG="未知信号"
            ;;
    esac

    local TIME=$(date "+%Y-%m-%d %H:%M:%S")
    if [ -s "/etc/redhat-release" ];then
		SYS_VERSION=$(cat /etc/redhat-release)
	elif [ -s "/etc/issue" ]; then
		SYS_VERSION=$(cat /etc/issue)
	fi
	SYS_INFO=$(uname -a)
	SYS_BIT=$(getconf LONG_BIT)
	MEM_TOTAL=$(free -m|grep Mem|awk '{print $2}')
	CPU_INFO=$(getconf _NPROCESSORS_ONLN)


    exit 1
}

trap 'signal_type=SIGINT; exit_msg' SIGINT
trap 'signal_type=SIGTERM; exit_msg' SIGTERM
trap 'signal_type=SIGHUP; exit_msg' SIGHUP


if [ $(whoami) != "root" ];then
	if [ -f "/usr/bin/curl" ];then
		DOWN_EXEC="curl -sSO"
	else
		DOWN_EXEC="wget -O install_panel.sh"
	fi 

	echo "====================================================="
	echo "检查到当前非root权限进行面板安装"
	IS_UBUNTU=$(cat /etc/issue|grep Ubuntu)
	IS_DEBIAN=$(cat /etc/issue|grep Debian)
	if [ "${IS_UBUNTU}" ];then
		echo "请使用下面命令重新执行安装面板"
		echo "sudo $DOWN_EXEC https://download.bt.cn/install/install_panel.sh;sudo bash install_panel.sh"
	elif [ "${IS_DEBIAN}" ];then
		echo "请执行su root命令切换为root账户后"
		echo "执行下面命令重新安装宝塔面板"
		echo "$DOWN_EXEC https://download.bt.cn/install/install_panel.sh;bash install_panel.sh"
	else
		if [ -f "/usr/bin/sudo" ];then
			echo "请使用下面命令使用root权限重新执行安装"
			echo "sudo $DOWN_EXEC https://download.bt.cn/install/install_panel.sh;sudo bash install_panel.sh"
		else
			echo "请执行su root命令切换为root账户后"
			echo "执行下面命令重新安装宝塔面板"
			echo "$DOWN_EXEC https://download.bt.cn/install/install_panel.sh;bash install_panel.sh"
		fi
	fi

	echo "-----------------------------------------------------"
	exit 1
fi


is64bit=$(getconf LONG_BIT)
if [ "${is64bit}" != '64' ];then
	echo "抱歉, 当前面板版本不支持32位系统, 请使用64位系统或安装宝塔5.9!";
	exit 1
fi

Centos6Check=$(cat /etc/redhat-release | grep ' 6.' | grep -iE 'centos|Red Hat')
if [ "${Centos6Check}" ];then
	echo "Centos6不支持安装宝塔面板，请更换Centos7/8安装宝塔面板"
	exit 1
fi 

UbuntuCheck=$(cat /etc/issue|grep Ubuntu|awk '{print $2}'|cut -f 1 -d '.')
if [ "${UbuntuCheck}" ] && [ "${UbuntuCheck}" -lt "16" ];then
	echo "Ubuntu ${UbuntuCheck}不支持安装宝塔面板，建议更换Ubuntu18/20安装宝塔面板"
	exit 1
fi
HOSTNAME_CHECK=$(cat /etc/hostname)
if [ -z "${HOSTNAME_CHECK}" ];then
	echo "localhost" > /etc/hostname 
	# echo "当前主机名hostname为空无法安装宝塔面板，请咨询服务器运营商设置好hostname后再重新安装"
	# exit 1
fi

UBUNTU_NO_LTS=$(cat /etc/issue|grep Ubuntu|grep -E "19|21|23|25")
if [ "${UBUNTU_NO_LTS}" ];then
	echo "当前您使用的非Ubuntu-lts版本，无法进行宝塔面板的安装"
	echo "请使用Ubuntu-20/20/22/24进行安装宝塔面板"
	exit 1
fi

DEBIAN_9_C=$(cat /etc/issue|grep Debian|grep -E "8 |9 ")
if [ "${DEBIAN_9_C}" ];then
	echo "当前您使用的Debian-8/9，官方已经停止支持、无法进行宝塔面板的安装"
	echo "请使用Debian-11/12进行安装宝塔面板"
	exit 1
fi

cd ~
setup_path="/www"
python_bin=$setup_path/server/panel/pyenv/bin/python
cpu_cpunt=$(cat /proc/cpuinfo|grep processor|wc -l)
panelPort=$(expr $RANDOM % 55535 + 10000)
# if [ "$1" ];then
# 	IDC_CODE=$1
# fi

Ready_Check(){
    WWW_DISK_SPACE=$(df |grep /www|awk '{print $4}')
    ROOT_DISK_SPACE=$(df |grep /$|awk '{print $4}')
	echo -e ""
	echo -e "============================================"
	echo -e "正在检查磁盘剩余空间"
	echo -e "============================================"
	echo -e ""
   if [ "${ROOT_DISK_SPACE}" -le 412000 ];then
	df -h
        echo -e "系统盘剩余空间不足400M 无法继续安装宝塔面板！"
        echo -e "请尝试清理磁盘空间后再重新进行安装"
        exit 1
    fi
    if [ "${WWW_DISK_SPACE}" ] && [ "${WWW_DISK_SPACE}" -le 412000 ] ;then
        echo -e "/www盘剩余空间不足400M 无法继续安装宝塔面板！"
        echo -e "请尝试清理磁盘空间后再重新进行安装"
        exit 1
    fi

    # ROOT_DISK_INODE=$(df -i|grep /$|awk '{print $2}')
	# if [ "${ROOT_DISK_INODE}" != "0" ];then
	# 	ROOT_DISK_INODE_FREE=$(df -i|grep /$|awk '{print $4}')
	# 	if [ "${ROOT_DISK_INODE_FREE}" -le 1000 ];then
	# 		echo -e "系统盘剩余inodes空间不足1000,无法继续安装！"
	# 		echo -e "请尝试清理磁盘空间后再重新进行安装"
	# 		exit 1
	# 	fi
	# fi

	# WWW_DISK_INODE==$(df -i|grep /www|awk '{print $2}')
	# if [ "${WWW_DISK_INODE}" ] && [ "${WWW_DISK_INODE}" != "0" ] ;then
	# 	WWW_DISK_INODE_FREE=$(df -i|grep /www|awk '{print $4}')
	# 	if [ "${WWW_DISK_INODE_FREE}" ] && [ "${WWW_DISK_INODE_FREE}" -le 1000 ] ;then
	# 		echo -e "/www盘剩余inodes空间不足1000, 无法继续安装！"
	# 		echo -e "请尝试清理磁盘空间后再重新进行安装"
	# 		exit 1
	# 	fi
	# fi
}

GetSysInfo(){
	if [ -s "/etc/redhat-release" ];then
		SYS_VERSION=$(cat /etc/redhat-release)
	elif [ -s "/etc/issue" ]; then
		SYS_VERSION=$(cat /etc/issue)
	fi
	SYS_INFO=$(uname -a)
	SYS_BIT=$(getconf LONG_BIT)
	MEM_TOTAL=$(free -m|grep Mem|awk '{print $2}')
	CPU_INFO=$(getconf _NPROCESSORS_ONLN)

	echo -e ${SYS_VERSION}
	echo -e Bit:${SYS_BIT} Mem:${MEM_TOTAL}M Core:${CPU_INFO}
	echo -e ${SYS_INFO}
	echo -e "============================================"
	echo -e "对不起，获取更新包失败！"
	echo -e "============================================"
	
	echo -e "============================================"
	echo -e "检查系统类别"
	echo -e "============================================"
	if [ -f "/etc/redhat-release" ];then
		Centos7Check=$(cat /etc/redhat-release | grep ' 7.' | grep -iE 'centos')
		echo -e "============================================"
		echo -e "Centos7/8官方已经停止支持"
		echo -e "如是新安装系统服务器建议更换至Debian-12/Ubuntu-22/Centos-9系统安装宝塔面板"
		echo -e "============================================"
	fi

	
	if [ -f "/usr/sbin/setstatus" ] || [ -f "/usr/sbin/setstatus" ];then
		echo -e "=================================================="
		echo -e "  检测到为麒麟系统，可能默认开启安全功能导致安装失败"
		echo -e "  请执行以下命令关闭安全加固后，再重新安装宝塔面板看是否正常"
		echo -e "  命令：sudo setstatus softmode -p"
		echo -e "=================================================="
	fi  

	SYS_SSL_LIBS=$(pkg-config --list-all | grep -q libssl)
	if [ -z "$SYS_SSL_LIBS" ];then
		echo "检测到缺少系统ssl相关依赖，可执行下面命令安装依赖后再重新安装宝塔看是否正常"
		echo "执行前请确保系统源正常"
		if [ -f "/usr/bin/yum" ];then
			echo "安装依赖命令: yum install openssl-devel -y"
		elif [ -f "/usr/bin/apt-get" ];then
			echo "安装依赖命令: apt-get install libssl-dev -y"
		fi
		rm -rf /www/server/panel/pyenv 
		echo -e "=================================================="
	fi

	if [ -f "/tmp/btpanel-install.log" ] && [ ! -f "/tmp/btpanel_err.pl" ];then
		local TIME=$(date "+%Y-%m-%d %H:%M:%S")
		INSTALL_USER=$(whoami)
		echo -e Bit:${SYS_BIT} Mem:${MEM_TOTAL}M Core:${CPU_INFO} >> ${INSTALL_LOGFILE}
		echo -e ${SYS_VERSION} ${SYS_INFO} >> ${INSTALL_LOGFILE}
		echo -e $INSTALL_USER >>  ${INSTALL_LOGFILE}
		OS_INFO=$(cat /etc/os-release |grep ID)
		echo $OS_INFO >> $INSTALL_LOGFILE
		PANEL_PORT_CHECK=$(lsof -i :${panelPort})
		echo ${PANEL_PORT_CHECK} >> $INSTALL_LOGFILE
		echo $LOCAL_CURL >> $INSTALL_LOGFILE
		ERR_MSG=$(tail -n 50 $INSTALL_LOGFILE)
		is_aarch64=$(uname -a|grep aarch64)
		if [ "${is_aarch64}" ];then
			PANEL_V="9.5.0"
		else
			PANEL_V="9.4.9"
		fi

	fi
	echo "True" > /tmp/btpanel_err.pl
# 	if [ -f "/usr/bin/qrencode" ];then
# 		echo -e "或微信扫码联系企业微信技术求助"
# 		echo -e "============================================"
# 		qrencode -t ANSIUTF8 "https://work.weixin.qq.com/kfid/kfc9072f0e29a53bd52"
# 		echo -e "============================================"
# 	else
# 		echo -e "或手机访问以下链接、扫码联系企业微信技术求助"
# 		echo -e "============================================"
# 		echo -e "联系链接:https://work.weixin.qq.com/kfid/kfc9072f0e29a53bd52"
# 		echo -e "============================================"
# 	fi
}
Red_Error(){
	echo '=================================================';
	printf '\033[1;31;40m%b\033[0m\n' "$@";
	GetSysInfo
	exit 1;
}
Lock_Clear(){
	if [ -f "/etc/bt_crack.pl" ];then
		chattr -R -ia /www
		chattr -ia /etc/init.d/bt
		\cp -rpa /www/backup/panel/vhost/* /www/server/panel/vhost/
		mv /www/server/panel/BTPanel/__init__.bak /www/server/panel/BTPanel/__init__.py
		rm -f /etc/bt_crack.pl
	fi
}
Install_Check(){
	if [ "${INSTALL_FORCE}" ];then
		return
	fi
	echo -e "----------------------------------------------------"
	echo -e "检查已有其他Web/mysql环境，安装宝塔可能影响现有站点及数据"
	echo -e "Web/mysql service is alreday installed,Can't install panel"
	echo -e "----------------------------------------------------"
	echo -e "已知风险/Enter yes to force installation"
	read -p "输入yes强制安装: " yes;
	if [ "$yes" != "yes" ];then
		echo -e "------------"
		echo "取消安装"
		exit;
	fi
	INSTALL_FORCE="true"
}
System_Check(){
	MYSQLD_CHECK=$(ps -ef |grep mysqld|grep -v grep|grep -v /www/server/mysql)
	PHP_CHECK=$(ps -ef|grep php-fpm|grep master|grep -v /www/server/php)
	NGINX_CHECK=$(ps -ef|grep nginx|grep master|grep -v /www/server/nginx)
	HTTPD_CHECK=$(ps -ef |grep -E 'httpd|apache'|grep -v /www/server/apache|grep -v grep)
	if [ "${PHP_CHECK}" ] || [ "${MYSQLD_CHECK}" ] || [ "${NGINX_CHECK}" ] || [ "${HTTPD_CHECK}" ];then
		Install_Check
	fi
}
Set_Ssl(){
    SET_SSL=true
    if [ "${SSL_PL}" ];then
    	SET_SSL=""
    fi
}
Add_lib_Install(){
	echo -e ""
	echo -e "============================================"
	echo -e "正在检测操作系统发行版本"
	echo -e "============================================"
	echo -e ""
	if [ -f "/etc/os-release" ];then
		. /etc/os-release
		OS_V=${VERSION_ID%%.*}
		if [ "${ID}" == "debian" ] && [[ "${OS_V}" =~ ^(11|12)$ ]];then
			OS_NAME=${ID}
		elif [ "${ID}" == "ubuntu" ] && [[ "${OS_V}" =~ ^(22|24)$ ]];then
			OS_NAME=${ID}
		elif [ "${ID}" == "centos" ] && [[ "${OS_V}" =~ ^(7)$ ]];then
			OS_NAME="el"
		elif [ "${ID}" == "opencloudos" ] && [[ "${OS_V}" =~ ^(9)$ ]];then
			OS_NAME=${ID}
		elif [ "${ID}" == "tencentos" ] && [[ "${OS_V}" =~ ^(4)$ ]];then
			OS_NAME=${ID}
		elif [ "${ID}" == "hce" ] && [[ "${OS_V}" =~ ^(2)$ ]];then
		    OS_NAME=${ID}
        elif { [ "${ID}" == "almalinux" ] || [ "${ID}" == "centos" ] || [ "${ID}" == "rocky" ]; } && [[ "${OS_V}" =~ ^(9)$ ]]; then
            OS_NAME="el"
		fi
	fi

	X86_CHECK=$(uname -m|grep x86_64)
	echo -e ""
	echo -e "============================================"
	echo -e "正在检测软件包管理系统版本"
	echo -e "============================================"
	echo -e ""
	if [ "${OS_NAME}" ] && [ "${X86_CHECK}" ];then
		if [ "${PM}" = "yum" ]; then
			mtype="1"
		elif [ "${PM}" = "apt-get" ]; then
			mtype="4"
		fi
		cd /www/server/panel/class
		btpython -c "import panelPlugin; plugin = panelPlugin.panelPlugin(); plugin.check_install_lib('${mtype}')"
		echo "True" > /tmp/panelTask.pl
		echo "True" > /www/server/panel/install/ins_lib.pl
	fi
}
Get_Pack_Manager(){
	if [ -f "/usr/bin/yum" ] && [ -d "/etc/yum.repos.d" ]; then
		PM="yum"
	elif [ -f "/usr/bin/apt-get" ] && [ -f "/usr/bin/dpkg" ]; then
		PM="apt-get"		
	fi
}
Set_Repo_Url(){
	# 自动检测当前APT源的速度和可用性，如果发现访问慢或是国外源，则替换为国内镜像源。
	echo -e ""
	echo -e "============================================"
	echo -e "检测更新源的速度和可用性"
	echo -e "============================================"
	echo -e ""
	# 只对使用apt-get包管理器的系统（Debian/Ubuntu）生效
	#if [ "${PM}"="apt-get" ];then  原条件判断语法有问题
	if [ "${PM}" = "apt-get" ];then
		# 检测是否在阿里云或腾讯云服务器上，如果是，直接返回（假设云服务器已有优化源）
		ALI_CLOUD_CHECK=$(grep Alibaba /etc/motd)
		Tencent_Cloud=$(cat /etc/hostname |grep -E VM-[0-9]+-[0-9]+)
		if [ "${ALI_CLOUD_CHECK}" ] || [ "${Tencent_Cloud}" ];then
			echo -e "检测到为阿里云或腾讯云机器，跳过优选"
			return
		fi


		if [ "${CN_CHECK}" != "True" ] && [ "${CN_CHECK}" != "False" ]; then
        	# 检测当前网络环境是否在中国大陆，如果是则使用国内节点列表
        	CN_CHECK=$(curl -sS --connect-timeout 10 -m 10 https://api.bt.cn/api/isCN)
		fi
		if [ "${CN_CHECK}" == "True" ];then
			SOURCE_URL_CHECK=$(grep -E 'security.ubuntu.com|archive.ubuntu.com|security.debian.org|deb.debian.org' /etc/apt/sources.list)
			# if [ -f "/etc/apt/sources.list.d/ubuntu.sources" ];then
			# 	SOURCE_URL_CHECK=$(grep -E 'security.ubuntu.com|archive.ubuntu.com|security.debian.org|deb.debian.org' /etc/apt/sources.list.d/ubuntu.sources)
			# fi
		fi
		
		# 从sources.list中提取第一个deb源的主机名
		GET_SOURCES_URL=$(cat /etc/apt/sources.list|grep ^deb|head -n 1|sed -E 's|^[^ ]+ https?://([^/]+).*|\1|')
		# 测试当前源的响应时间和HTTP状态码，超时3秒，连接超时3秒
		NODE_CHECK=$(curl --connect-timeout 3 -m 3 2>/dev/null -w "%{http_code} %{time_total}" ${GET_SOURCES_URL} -o /dev/null)
		NODE_STATUS=$(echo ${NODE_CHECK}|awk '{print $1}')
		TIME_TOTAL=$(echo ${NODE_CHECK}|awk '{print $2 * 1000}'|cut -d '.' -f 1)

		# 判断是否需要替换
		# 替换条件（满足任一即触发）：HTTP状态码不是200或301（访问失败）、响应时间≥150ms（太慢）、在国内且使用官方源
		if { [ "${NODE_STATUS}" != "200" ] && [ "${NODE_STATUS}" != "301" ]; } || [ "${TIME_TOTAL}" -ge "150" ] || [ "${SOURCE_URL_CHECK}" ]; then
			# 备份原更新源
			\cp -rpa /etc/apt/sources.list /etc/apt/sources.list.btbackup
			# 选择最佳镜像源
			apt_lists=(mirrors.sustech.edu.cn mirrors.cloud.tencent.com  mirrors.163.com repo.huaweicloud.com mirrors.tuna.tsinghua.edu.cn mirrors.aliyun.com mirrors.ustc.edu.cn )
			for list in ${apt_lists[@]};
			do
				NODE_CHECK=$(curl --connect-timeout 3 -m 3 2>/dev/null -w "%{http_code} %{time_total}" ${list} -o /dev/null)
				NODE_STATUS=$(echo ${NODE_CHECK}|awk '{print $1}')
				TIME_TOTAL=$(echo ${NODE_CHECK}|awk '{print $2 * 1000}'|cut -d '.' -f 1)
				if [ "${NODE_STATUS}" == "200" ] || [ "${NODE_STATUS}" == "301" ];then
					if [ "${TIME_TOTAL}" -le "150" ];then
						# 替换源
						if [ -f "/etc/apt/sources.list" ];then
							sed -i "s/${GET_SOURCES_URL}/${list}/g" /etc/apt/sources.list
							sed -i "s/cn.security.ubuntu.com/${list}/g" /etc/apt/sources.list
							sed -i "s/cn.archive.ubuntu.com/${list}/g" /etc/apt/sources.list
							sed -i "s/security.ubuntu.com/${list}/g" /etc/apt/sources.list
							sed -i "s/archive.ubuntu.com/${list}/g" /etc/apt/sources.list
							sed -i "s/security.debian.org/${list}/g" /etc/apt/sources.list
							sed -i "s/deb.debian.org/${list}/g" /etc/apt/sources.list
						fi
						break;
					fi
				fi
			done
		fi
	fi
}

# 自动设置虚拟内存函数 
Auto_Swap()
{
	# 检测当前系统是否已存在交换分区（Swap），如果已存在且大小大于1KB，则直接返回
	swap=$(free |grep Swap|awk '{print $2}')
	if [ "${swap}" -gt 1 ];then
		echo "Swap total sizse: $swap";
		return;
	fi

	# 如果/www目录不存在，则创建该目录，用于存放swap文件
	if [ ! -d /www ];then
		mkdir /www
	fi

	echo "正在设置虚拟内存，请稍等..........";
	echo '---------------------------------------------';

	# 设置swap文件路径
	swapFile="/www/swap"

	# 创建1GB的swap文件（1025MB，1M * 1025 = 1GB + 少量预留）
	dd if=/dev/zero of=$swapFile bs=1M count=1025

	# 将创建的文件格式化为swap分区
	mkswap -f $swapFile
	
	# 启用新创建的swap文件
	swapon $swapFile

	# 将swap文件配置添加到/etc/fstab，实现开机自动挂载
	echo "$swapFile    swap    swap    defaults    0 0" >> /etc/fstab

	# 再次检查swap是否成功启用
	swap=`free |grep Swap|awk '{print $2}'`
	if [ $swap -gt 1 ];then
		echo "Swap total sizse: $swap";
		return;
	fi
	# 如果swap启用失败，回滚操作：
	# 1. 从/etc/fstab中删除刚刚添加的swap配置
	sed -i "/\/www\/swap/d" /etc/fstab
	# 2. 删除已创建的swap文件
	rm -f $swapFile
}

# 配置服务自启动
Service_Add()
{
	# 判断包管理器类型为yum或dnf（RHEL/CentOS/Fedora系统）
	if [ "${PM}" == "yum" ] || [ "${PM}" == "dnf" ]; then
		# 将bt服务添加到chkconfig管理系统
		chkconfig --add bt
		# 设置运行级别2345下bt服务开机自启
		chkconfig --level 2345 bt on
		# 检测是否为CentOS 9系统（通过检查redhat-release文件内容）
		Centos9Check=$(cat /etc/redhat-release |grep ' 9')
		# 如果是CentOS 9系统，则额外配置systemd服务
		if [ "${Centos9Check}" ];then
            # 从远程下载btpanel的systemd服务配置文件到系统目录
            #wget -O /usr/lib/systemd/system/btpanel.service ${download_Url}/init/systemd/btpanel.service
			wget -O /usr/lib/systemd/system/btpanel.service ${dlco}/btpanel.service
			# 启用btpanel服务实现开机自启动
			systemctl enable btpanel
		fi		
	# 判断包管理器类型为apt-get（Debian/Ubuntu系统）
	elif [ "${PM}" == "apt-get" ]; then
		# 使用update-rc.d工具设置bt服务开机自启
		update-rc.d bt defaults
	fi 
}

# 设置 CentOS 7 系统软件源
Set_Centos7_Repo(){
	# 检查当前系统是否使用了官方的mirror.centos.org源（非注释行），且系统为64位
	MIRROR_CHECK=$(cat /etc/yum.repos.d/CentOS-Base.repo |grep "[^#]mirror.centos.org")
	if [ "${MIRROR_CHECK}" ] && [ "${is64bit}" == "64" ];then
		# 备份原yum源配置文件到/etc/yumBak目录
		\cp -rpa /etc/yum.repos.d/ /etc/yumBak
		# 注释掉所有CentOS repo文件中的mirrorlist配置行
		sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*.repo
		# 将注释中的vault.epel.cloud镜像源取消注释，设置为默认源
		sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.epel.cloud|g' /etc/yum.repos.d/CentOS-*.repo
	fi

	# 检查当前系统是否使用了清华大学镜像源
	TSU_MIRROR_CHECK=$(cat /etc/yum.repos.d/CentOS-Base.repo |grep "tuna.tsinghua.edu.cn")
	if [ "${TSU_MIRROR_CHECK}" ];then
		# 备份原yum源配置文件
		\cp -rpa /etc/yum.repos.d/ /etc/yumBak
		# 注释掉所有mirrorlist配置行
		sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*.repo
		# 将所有清华镜像源（包括http和https）替换为vault.epel.cloud源
		sed -i 's|#baseurl=https://mirrors.tuna.tsinghua.edu.cn|baseurl=http://vault.epel.cloud|g' /etc/yum.repos.d/CentOS-*.repo
		sed -i 's|#baseurl=http://mirrors.tuna.tsinghua.edu.cn|baseurl=http://vault.epel.cloud|g' /etc/yum.repos.d/CentOS-*.repo
		sed -i 's|baseurl=https://mirrors.tuna.tsinghua.edu.cn|baseurl=http://vault.epel.cloud|g' /etc/yum.repos.d/CentOS-*.repo
		sed -i 's|baseurl=http://mirrors.tuna.tsinghua.edu.cn|baseurl=http://vault.epel.cloud|g' /etc/yum.repos.d/CentOS-*.repo
	fi

	# 检查当前系统是否为阿里云或腾讯云环境
	ALI_CLOUD_CHECK=$(grep Alibaba /etc/motd)
	Tencent_Cloud=$(cat /etc/hostname |grep -E VM-[0-9]+-[0-9]+)
	# 如果是云服务器环境，直接返回，不修改软件源
	if [ "${ALI_CLOUD_CHECK}" ] || [ "${Tencent_Cloud}" ];then
		return
	fi

	# 尝试安装unzip工具测试yum是否可用
	yum install unzip -y
	# 如果安装失败（yum源不可用）
	if [ "$?" != "0" ] ;then
		# 检查系统是否安装了tar工具
		TAR_CHECK=$(which tar)
		if [ "$?" == "0" ] ;then
			# 备份原yum源配置文件
			\cp -rpa /etc/yum.repos.d/ /etc/yumBak
			# 如果download_Url变量未定义，设置默认下载地址
			if [ -z "${download_Url}" ];then
				download_Url="http://download.bt.cn"
			fi
			# 下载预配置的repo文件压缩包
			# 2025/12/14 06点35分 Release Common
			#curl -Ss --connect-timeout 5 -m 60 -O ${download_Url}/src/el7repo.tar.gz
			curl -Ss --connect-timeout 5 -m 60 -O ${dlco}/el7repo.tar.gz
			# 删除原有的repo配置文件
			rm -f /etc/yum.repos.d/*.repo
			# 解压预配置的repo文件到yum源目录
			tar -xvzf el7repo.tar.gz -C /etc/yum.repos.d/
		fi
	fi

	# 再次尝试安装unzip工具，检查新的yum源是否可用
	yum install unzip -y
	# 如果仍然失败，将vault.epel.cloud源替换为腾讯云镜像源
	if [ "$?" != "0" ] ;then
		sed -i "s/vault.epel.cloud/mirrors.cloud.tencent.com/g" /etc/yum.repos.d/*.repo
	fi
}

# 设置 CentOS 8 系统软件源
Set_Centos8_Repo(){
	# 检查是否为华为云环境（通过/etc/motd文件判断）
	HUAWEI_CHECK=$(cat /etc/motd |grep "Huawei Cloud")
	# 如果是华为云环境且系统为64位架构
	if [ "${HUAWEI_CHECK}" ] && [ "${is64bit}" == "64" ];then
		# 备份原有yum源配置文件目录到/etc/yumBak（使用\cp避免别名影响）
		\cp -rpa /etc/yum.repos.d/ /etc/yumBak
		# 注释所有CentOS repo文件中的mirrorlist行
		sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*.repo
		# 将baseurl指向vault.epel.cloud（CentOS Vault源）
		sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.epel.cloud|g' /etc/yum.repos.d/CentOS-*.repo
		# 删除epel源配置文件（避免冲突）
		rm -f /etc/yum.repos.d/epel.repo
		rm -f /etc/yum.repos.d/epel-*
	fi
	
	# 检查是否为阿里云环境
	ALIYUN_CHECK=$(cat /etc/motd|grep "Alibaba Cloud ")
	# 如果是阿里云环境、64位系统且未配置阿里云源
	if [  "${ALIYUN_CHECK}" ] && [ "${is64bit}" == "64" ] && [ ! -f "/etc/yum.repos.d/Centos-vault-8.5.2111.repo" ];then
		# 重命名所有现有repo文件为.bak备份
		rename '.repo' '.repo.bak' /etc/yum.repos.d/*.repo
		# 下载阿里云的CentOS 8.5.2111 vault源配置
		# 2025/12/13 11点38分 已上传Release Common
		#wget https://mirrors.aliyun.com/repo/Centos-vault-8.5.2111.repo -O /etc/yum.repos.d/Centos-vault-8.5.2111.repo
		curl -O --connect-timeout 5 -m 60 ${dlco}/Centos-vault-8.5.2111.repo -O /etc/yum.repos.d/Centos-vault-8.5.2111.repo
		
		# 下载阿里云的EPEL 8归档源配置
		#wget https://mirrors.aliyun.com/repo/epel-archive-8.repo -O /etc/yum.repos.d/epel-archive-8.repo
		curl -O --connect-timeout 5 -m 60 ${dlco}/epel-archive-8.repo -O /etc/yum.repos.d/epel-archive-8.repo
		# 替换源地址：将mirrors.cloud.aliyuncs.com临时替换，再替换aliyun.com，最后恢复临时标记
		sed -i 's/mirrors.cloud.aliyuncs.com/url_tmp/g'  /etc/yum.repos.d/Centos-vault-8.5.2111.repo &&  sed -i 's/mirrors.aliyun.com/mirrors.cloud.aliyuncs.com/g' /etc/yum.repos.d/Centos-vault-8.5.2111.repo && sed -i 's/url_tmp/mirrors.aliyun.com/g' /etc/yum.repos.d/Centos-vault-8.5.2111.repo
		# 替换EPEL源地址
		sed -i 's/mirrors.aliyun.com/mirrors.cloud.aliyuncs.com/g' /etc/yum.repos.d/epel-archive-8.repo
	fi
	
	# 检查当前源是否仍指向mirror.centos.org（原官方源已失效）
	MIRROR_CHECK=$(cat /etc/yum.repos.d/CentOS-Linux-AppStream.repo |grep "[^#]mirror.centos.org")
	# 如果检测到原官方源且为64位系统
	if [ "${MIRROR_CHECK}" ] && [ "${is64bit}" == "64" ];then
		# 备份现有yum源配置
		\cp -rpa /etc/yum.repos.d/ /etc/yumBak
		# 注释所有mirrorlist行
		sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*.repo
		# 将baseurl指向vault.epel.cloud（CentOS Vault源）
		sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.epel.cloud|g' /etc/yum.repos.d/CentOS-*.repo
	fi

	# 尝试安装基本工具unzip和tar
	yum install unzip tar -y
	# 如果安装失败（$?表示上一条命令的退出状态）
	if [ "$?" != "0" ] ;then
		# 如果download_Url变量未设置，使用默认值
		if [ -z "${download_Url}" ];then
			download_Url="http://download.bt.cn"
		fi
		# 如果tar命令不存在，下载并安装特定版本的tar包
		if [ ! -f "/usr/bin/tar" ] ;then
			# 2025年12/14 06点30分 已传至通用区
			#curl -Ss --connect-timeout 5 -m 60 -O ${download_Url}/src/tar-1.30-5.el8.x86_64.rpm
			curl -Ss --connect-timeout 5 -m 60 -O ${dlco}/tar-1.30-5.el8.x86_64.rpm
			yum install tar-1.30-5.el8.x86_64.rpm -y
		fi
		# 备份现有yum源配置
		\cp -rpa /etc/yum.repos.d/ /etc/yumBak
		# 下载预配置的yum源包
		# 2025年12/14 06点30分 已传至通用区
		#curl -Ss --connect-timeout 5 -m 60 -O ${download_Url}/src/el8repo.tar.gz
		curl -Ss --connect-timeout 5 -m 60 -O ${dlco}/el8repo.tar.gz
		# 删除所有现有repo文件
		rm -f /etc/yum.repos.d/*.repo
		# 解压预配置的repo文件到yum源目录
		tar -xvzf el8repo.tar.gz -C /etc/yum.repos.d/
	fi

	# 再次尝试安装unzip和tar
	yum install unzip tar -y
	# 如果仍然失败，将vault.epel.cloud替换为腾讯云镜像
	if [ "$?" != "0" ] ;then
		sed -i "s/vault.epel.cloud/mirrors.cloud.tencent.com/g" /etc/yum.repos.d/*.repo
	fi
}

# 获取下载节点URL函数
# 通过测试多个节点服务器的响应时间和下载速度，自动选择最优的下载节点
get_node_url(){
    # 如果包管理器是yum，则安装wget工具
    if [ "${PM}" = "yum" ]; then
        yum install wget -y
    fi
    
    # 检查curl命令是否存在，如果不存在则根据包管理器安装curl wget
    if [ ! -f /bin/curl ];then
        if [ "${PM}" = "yum" ]; then
            yum install curl -y
        elif [ "${PM}" = "apt-get" ]; then
            apt-get install curl -y
			apt-get install wget -y
        fi
    fi
	echo -e "============================================"
	echo -e "检查下载节点"
	echo -e "跳过选择节点"
	echo -e "============================================"
    # 如果存在预先配置的节点文件，则直接读取其中的节点URL并返回
    #if [ -f "/www/node.pl" ];then
        #download_Url=$(cat /www/node.pl)
        #echo "Download node: $download_Url";
        #echo '---------------------------------------------';
        #return
    #fi
    
    #echo '---------------------------------------------';
    #echo "Selected download node...";
    
    # 定义所有可用的下载节点数组
    #nodes=(https://dg2.bt.cn https://download.bt.cn https://ctcc1-node.bt.cn https://cmcc1-node.bt.cn https://ctcc2-node.bt.cn https://hk1-node.bt.cn https://na1-node.bt.cn https://jp1-node.bt.cn https://cf1-node.aapanel.com https://download.bt.cn);
    
    # 检查curl命令是否存在
    #CURL_CHECK=$(which curl)
    #if [ "$?" == "0" ];then
		# 检查CN_CHECK是否已预设为True或False，否则进行检测
		#if [ "${CN_CHECK}" != "True" ] && [ "${CN_CHECK}" != "False" ]; then
        	# 检测当前网络环境是否在中国大陆，如果是则使用国内节点列表
        	#CN_CHECK=$(curl -sS --connect-timeout 10 -m 10 https://api.bt.cn/api/isCN)
		#fi
	    #if [ "${CN_CHECK}" == "True" ];then
        #nodes=(https://dg2.bt.cn https://download.bt.cn https://ctcc1-node.bt.cn https://cmcc1-node.bt.cn https://ctcc2-node.bt.cn https://hk1-node.bt.cn);
		#fi
    #fi

    # 如果传入了参数$1，则从节点列表中排除该节点（用于避免使用某个特定节点）
    #if [ "$1" ];then
        #nodes=($(echo ${nodes[*]}|sed "s#${1}##"))
    #fi

    # 创建临时文件用于存储节点测试结果
    # tmp_file1：存储响应时间小于300ms的节点结果
    # tmp_file2：存储响应时间大于等于300ms的节点结果
    #tmp_file1=/dev/shm/net_test1.pl
    #tmp_file2=/dev/shm/net_test2.pl
    #[ -f "${tmp_file1}" ] && rm -f ${tmp_file1}
    #[ -f "${tmp_file2}" ] && rm -f ${tmp_file2}
    #touch $tmp_file1
    #touch $tmp_file2
    
    # 遍历所有节点进行网络测试
    #for node in ${nodes[@]};
    #do
        # 测试节点响应：发送请求到节点的net_test接口，获取HTTP状态码和总耗时
        #NODE_CHECK=$(curl --connect-timeout 3 -m 3 2>/dev/null -w "%{http_code} %{time_total}" ${node}/net_test|xargs)
        #RES=$(echo ${NODE_CHECK}|awk '{print $1}')
        #NODE_STATUS=$(echo ${NODE_CHECK}|awk '{print $2}')
        # 计算实际耗时（减去500ms的基础延迟，并转换为毫秒整数）
        #TIME_TOTAL=$(echo ${NODE_CHECK}|awk '{print $3 * 1000 - 500 }'|cut -d '.' -f 1)
        
        # 如果节点响应正常（HTTP状态码为200）
        #if [ "${NODE_STATUS}" == "200" ];then
            # 响应时间小于300ms的情况
            #if [ $TIME_TOTAL -lt 300 ];then
                #if [ $RES -ge 1500 ];then
                    # 将下载速度（RES）和节点URL记录到tmp_file1
                    #echo "$RES $node" >> $tmp_file1
                #fi
            # 响应时间大于等于300ms的情况
            #else
                #if [ $RES -ge 1500 ];then
                    # 将响应时间（TIME_TOTAL）和节点URL记录到tmp_file2
                    #echo "$TIME_TOTAL $node" >> $tmp_file2
                #fi
            #fi

            #i=$(($i+1))
            # 如果找到响应时间小于300ms且下载速度大于2390的优质节点，提前结束测试
            #if [ $TIME_TOTAL -lt 300 ];then
                #if [ $RES -ge 2390 ];then
                    #break;
                #fi
            #fi	
        #fi
    #done

    # 优先选择tmp_file1中下载速度最快的节点（按RES降序排序）
    #NODE_URL=$(cat $tmp_file1|sort -r -g -t " " -k 1|head -n 1|awk '{print $2}')
    
    # 如果没有找到响应时间小于300ms的节点，则从tmp_file2中选择响应时间最短的节点
    #if [ -z "$NODE_URL" ];then
        #NODE_URL=$(cat $tmp_file2|sort -g -t " " -k 1|head -n 1|awk '{print $2}')
        # 如果仍然没有找到合适的节点，则使用默认节点
        #if [ -z "$NODE_URL" ];then
            #NODE_URL='https://download.bt.cn';
        #fi
    #fi
    
    # 清理临时文件
    #rm -f $tmp_file1
    #rm -f $tmp_file2
    
    # 设置最终选择的下载节点URL
    #download_Url=$NODE_URL
    #downloads_Url=http://io.bt.sb
    
    #echo "Download node: $download_Url";
    #echo '---------------------------------------------';
}
# 卸载指定软件包
# 根据包管理器类型（yum或apt-get）卸载指定的软件包
Remove_Package(){
	# 获取要移除的软件包名称（修复原变量名拼写错误：PackageNmae → PackageName）
	local PackageName=$1
	
	# 根据系统包管理器类型执行不同的移除操作
	# 注：变量PM需在外部定义，值为"yum"或"apt-get"
	if [ "${PM}" == "yum" ];then
		# 对于yum系统：检查软件包是否已安装
		# rpm -q返回包信息，未安装时包含"not installed"
		isPackage=$(rpm -q ${PackageName}|grep "not installed")
		
		# 如果isPackage为空（即包已安装），则执行移除
		if [ -z "${isPackage}" ];then
			yum remove ${PackageName} -y
		fi
	elif [ "${PM}" == "apt-get" ];then
		# 对于apt-get系统：检查软件包是否已安装（修复原逻辑错误）
		# 原代码错误地判断变量是否为空，现改为准确检查包状态
		# dpkg -s对已安装包返回0，未安装返回非0
		if dpkg -s ${PackageName} >/dev/null 2>&1; then
			apt-get remove ${PackageName} -y
		fi
	fi
}

# 安装RPM软件包
Install_RPM_Pack(){
	yumPath=/etc/yum.conf

	# 检查是否为CentOS Stream 8系统
	CentosStream8Check=$(cat /etc/redhat-release |grep Stream|grep 8)
	if [ "${CentosStream8Check}" ];then
		# 检查镜像源配置中是否包含未注释的mirror.centos.org，并验证系统架构
		MIRROR_CHECK=$(cat /etc/yum.repos.d/CentOS-Stream-AppStream.repo|grep -v "^#"|grep "mirror.centos.org")
		if [ "${MIRROR_CHECK}" ] && [ "${is64bit}" == "64" ];then
			# 备份原始yum源配置目录
			\cp -rpa /etc/yum.repos.d/ /etc/yumBak
			# 禁用mirrorlist配置（所有CentOS源）
			sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*.repo
			# 将基础镜像源替换为vault.epel.cloud
			sed -i 's|#baseurl=http://mirror.centos.org |baseurl=http://vault.epel.cloud |g' /etc/yum.repos.d/CentOS-*.repo
		fi
	fi

	# 检查是否为CentOS 8或RHEL 8系统
	Centos8Check=$(cat /etc/redhat-release | grep ' 8.' | grep -iE 'centos|Red Hat')
	if [ "${Centos8Check}" ];then
		# 调用CentOS 8专用仓库配置函数
		Set_Centos8_Repo
	fi	
	# 检查是否为CentOS 7或RHEL 7系统
	Centos7Check=$(cat /etc/redhat-release | grep ' 7.' | grep -iE 'centos|Red Hat')
	if [ "${Centos7Check}" ];then
		# 调用CentOS 7专用仓库配置函数
		Set_Centos7_Repo
	fi
	# 检查yum配置中是否已包含httpd排除规则
	isExc=$(cat $yumPath|grep httpd)
	if [ "$isExc" = "" ];then
		# 添加软件包排除规则，防止宝塔面板组件与系统包冲突
		echo "exclude=httpd nginx php mysql mairadb python-psutil python2-psutil" >> $yumPath
	fi

	# 检查是否为EL8系统（RHEL/CentOS 8）
	if [ -f "/etc/redhat-release" ] && [ $(cat /etc/os-release|grep PLATFORM_ID|grep -oE "el8") ];then
		# 启用PowerTools仓库以获取更多开发工具和库
		yum config-manager --set-enabled powertools
		yum config-manager --set-enabled PowerTools
	fi

	# 检查是否为EL9系统（RHEL/CentOS 9）
	if [ -f "/etc/redhat-release" ] && [ $(cat /etc/os-release|grep PLATFORM_ID|grep -oE "el9") ];then
		# 启用CRB仓库（CodeReady Builder，替代PowerTools）
		dnf config-manager --set-enabled crb -y
	fi
	# 尝试从宝塔面板API获取标准时间
	echo 'Synchronizing system time...'
	getBtTime=$(curl -sS --connect-timeout 3 -m 60 http://www.bt.cn/api/index/get_time )
	if [ "${getBtTime}" ];then	
		# 设置系统时间为获取到的网络时间
		date -s "$(date -d @$getBtTime +"%Y-%m-%d %H:%M:%S")"
	fi

	# 针对非CentOS 8系统执行时间同步和SELinux配置
	if [ -z "${Centos8Check}" ]; then
		# 安装ntp时间同步服务
		yum install ntp -y
		# 删除旧时区链接并设置为亚洲/上海时区
		rm -rf /etc/localtime
		ln -s /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

		# 同步国际NTP服务器时间
		ntpdate 0.asia.pool.ntp.org
		# 临时关闭SELinux（立即生效）
		setenforce 0
	fi

	# 记录软件包安装开始时间（秒级时间戳）
	startTime=`date +%s`

	# 永久禁用SELinux（修改配置文件）
	sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
	# 定义需要安装的软件包列表（开发库、工具、组件等）
	yumPacks="libcurl-devel wget tar gcc make zip unzip openssl openssl-devel gcc libxml2 libxml2-devel libxslt* zlib zlib-devel libjpeg-devel libpng-devel libwebp libwebp-devel freetype freetype-devel lsof pcre pcre-devel vixie-cron crontabs icu libicu-devel c-ares libffi-devel bzip2-devel ncurses-devel sqlite-devel readline-devel tk-devel gdbm-devel db4-devel libpcap-devel xz-devel qrencode at mariadb rsyslog net-tools"
	# 执行批量安装所有定义的软件包
	yum install -y ${yumPacks}

	# 循环检查每个软件包的安装状态，对安装失败的包进行重试
	for yumPack in ${yumPacks}
	do
		# 查询软件包是否已安装
		rpmPack=$(rpm -q ${yumPack})
		# 检查返回结果是否包含"not"（表示未安装）
		packCheck=$(echo ${rpmPack}|grep not)
		if [ "${packCheck}" ]; then
			# 单独安装未成功的软件包
			yum install ${yumPack} -y
		fi
	done
	# 检查dnf命令是否存在，为EL8+系统安装redhat-rpm-config
	if [ -f "/usr/bin/dnf" ]; then
		dnf install -y redhat-rpm-config
	fi

	# 检查是否为阿里云Linux 3系统
	ALI_OS=$(cat /etc/redhat-release |grep "Alibaba Cloud Linux release 3")
	if [ -z "${ALI_OS}" ];then 
		# 非阿里云系统安装EPEL扩展仓库
		yum install epel-release -y
	fi
}

# 安装Debian/Ubuntu系统必备软件包
Install_Deb_Pack(){
	# 强制将/bin/sh链接到bash，确保脚本兼容性
	ln -sf bash /bin/sh
	
	# 检测当前系统是否为Ubuntu 22.04版本
	UBUNTU_22=$(cat /etc/issue|grep "Ubuntu 22")
	# 检测当前系统是否为Ubuntu 24.04版本
	UBUNTU_24=$(cat /etc/issue|grep "Ubuntu 24")
	# 如果是Ubuntu 22或24版本，卸载needrestart包（该包可能在某些场景下导致问题）
	if [ "${UBUNTU_22}" ] || [ "${UBUNTU_24}" ];then
		apt-get remove needrestart -y
	fi
	
	# 检测是否为阿里云服务器环境
	ALIYUN_CHECK=$(cat /etc/motd|grep "Alibaba Cloud ")
	# 如果是阿里云服务器且为Ubuntu 22版本，卸载libicu70包（解决特定环境下的兼容性问题）
	if [ "${ALIYUN_CHECK}" ] && [ "${UBUNTU_22}" ];then
		apt-get remove libicu70 -y
	fi
	
	# 更新apt软件包列表，确保获取最新的软件包信息
	apt-get update -y
	
	# 检测是否为fnOS系统（飞牛OS）
	FNOS_CHECK=$(cat /etc/issue|grep fnOS)
	# 如果是fnOS系统，强制安装libc6及其开发包（解决特定系统依赖问题）
	if [ "${FNOS_CHECK}" ];then
		apt-get install libc6 --allow-change-held-packages -y
		apt-get install libc6-dev --allow-change-held-packages -y
	fi
	
	# 安装bash解释器
	apt-get install bash -y
	# 如果bash安装在/usr/bin/bash路径，则重新建立符号链接
	if [ -f "/usr/bin/bash" ];then
		ln -sf /usr/bin/bash /bin/sh
	fi
	
	# 安装Ruby语言环境
	apt-get install ruby -y
	# 安装LSB（Linux标准基础）发行版信息工具
	apt-get install lsb-release -y
	
	# 获取当前libcurl4包的版本号
	LIBCURL_VER=$(dpkg -l|grep libcurl4|awk '{print $3}')
	# 如果版本为7.68.0-1ubuntu2.8（存在兼容性问题的版本），则卸载libcurl4并安装curl
	if [ "${LIBCURL_VER}" == "7.68.0-1ubuntu2.8" ];then
		apt-get remove libcurl4 -y
		apt-get install curl -y
	fi
	
	# 定义需要安装的软件包列表字符串（包含工具、库文件、开发包等）
	debPacks="wget curl libcurl4-openssl-dev gcc make zip unzip tar openssl libssl-dev gcc libxml2 libxml2-dev zlib1g zlib1g-dev libjpeg-dev libpng-dev lsof libpcre3 libpcre3-dev cron net-tools swig build-essential libffi-dev libbz2-dev libncurses-dev libsqlite3-dev libreadline-dev tk-dev libgdbm-dev libdb-dev libdb++-dev libpcap-dev xz-utils git qrencode sqlite3 at mariadb-client rsyslog net-tools cmake"
	# 批量安装所有软件包（使用--force-yes参数自动确认，注意：该参数已废弃，新版系统可能不支持）
	apt-get install -y $debPacks --force-yes
	
	# 循环检查每个软件包是否安装成功，若未安装则单独重新安装
	for debPack in ${debPacks}
	do
		packCheck=$(dpkg -l|grep ${debPack})
		if [ "$?" -ne "0" ] ;then
			apt-get install -y $debPack
		fi
	done
	
	# 检查SSL证书目录是否存在，不存在则创建（注意：letsencrypt拼写错误，应为letsencrypt）
	if [ ! -d '/etc/letsencrypt' ];then
		mkdir -p /etc/letsencryp
		# 创建cron定时任务目录
		mkdir -p /var/spool/cron
		# 如果root用户的cron文件不存在，则创建空文件并设置权限
		if [ ! -f '/var/spool/cron/crontabs/root' ];then
			echo '' > /var/spool/cron/crontabs/root
			chmod 600 /var/spool/cron/crontabs/root
		fi	
	fi
}
Get_Versions(){
	redhat_version_file="/etc/redhat-release"
	deb_version_file="/etc/issue"

	if [[ $(grep Anolis /etc/os-release) ]] && [[ $(grep VERSION /etc/os-release|grep 8.8) ]];then
		if [ -f "/usr/bin/yum" ];then
			os_type="anolis"
			os_version="8"
			return
		fi
	fi


	if [ -f "/etc/os-release" ];then
		. /etc/os-release
		OS_V=${VERSION_ID%%.*}
		if [ "${ID}" == "opencloudos" ] && [[ "${OS_V}" =~ ^(9)$ ]];then
			os_type="opencloudos"
			os_version="9"
			pyenv_tt="true"
		elif { [ "${ID}" == "almalinux" ] || [ "${ID}" == "centos" ] || [ "${ID}" == "rocky" ]; } && [[ "${OS_V}" =~ ^(9)$ ]]; then
			os_type="el"
			os_version="9"
			pyenv_tt="true"
		fi
		if [ "${pyenv_tt}" ];then
			return
		fi
	fi
    
	if [ -f $redhat_version_file ];then
		os_type='el'
		is_aliyunos=$(cat $redhat_version_file|grep Aliyun)
		if [ "$is_aliyunos" != "" ];then
			return
		fi

		if [[ $(grep "Alibaba Cloud" /etc/redhat-release) ]] && [[ $(grep al8 /etc/os-release) ]];then
			os_type="ali-linux-"
			os_version="al8"
			return
		fi

		if [[ $(grep "TencentOS Server" /etc/redhat-release|grep 3.1) ]];then
			os_type="TencentOS-"
			os_version="3.1"
			return
		fi

		os_version=$(cat $redhat_version_file|grep CentOS|grep -Eo '([0-9]+\.)+[0-9]+'|grep -Eo '^[0-9]')
		if [ "${os_version}" = "5" ];then
			os_version=""
		fi
		if [ -z "${os_version}" ];then
			os_version=$(cat /etc/redhat-release |grep Stream|grep -oE 8)
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
		else
			if [ "$os_version" = "14" ];then
				os_version=""
			fi
			if [ "$os_version" = "12" ];then
				os_version=""
			fi
			if [ "$os_version" = "19" ];then
				os_version=""
			fi
			if [ "$os_version" = "21" ];then
				os_version=""
			fi
			if [ "$os_version" = "20" ];then
				os_version2004=$(cat /etc/issue|grep 20.04)
				if [ -z "${os_version2004}" ];then
					os_version=""
				fi
			fi
		fi
	fi
}
Install_Python_Lib(){
	# 2025/12/14 14点20分 已上传Release Common
	#curl -Ss --connect-timeout 3 -m 60 $download_Url/install/pip_select.sh|bash
	curl -Ss --connect-timeout 3 -m 60 ${dlco}/pip_select.sh
	bash pip_select.sh
	pyenv_path="/www/server/panel"
	if [ -f $pyenv_path/pyenv/bin/python ];then
	 	is_ssl=$($python_bin -c "import ssl" 2>&1|grep cannot)
		$pyenv_path/pyenv/bin/python3.7 -V
		if [ $? -eq 0 ] && [ -z "${is_ssl}" ];then
			chmod -R 700 $pyenv_path/pyenv/bin
			is_package=$($python_bin -m psutil 2>&1|grep package)
			if [ "$is_package" = "" ];then
				# 2025/12/14 14点20分 已上传Release Common
				wget -O $pyenv_path/pyenv/pip.txt ${dlco}/pip.txt -T 15
				$pyenv_path/pyenv/bin/pip install -U pip
				$pyenv_path/pyenv/bin/pip install -U setuptools==65.5.0
				$pyenv_path/pyenv/bin/pip install -r $pyenv_path/pyenv/pip.txt
			fi
			source $pyenv_path/pyenv/bin/activate
			chmod -R 700 $pyenv_path/pyenv/bin
			return
		else
			rm -rf $pyenv_path/pyenv
		fi
	fi

	is_loongarch64=$(uname -a|grep loongarch64)
	if [ "$is_loongarch64" != "" ] && [ -f "/usr/bin/yum" ];then
		yumPacks="python3-devel python3-pip python3-psutil python3-gevent python3-pyOpenSSL python3-paramiko python3-flask python3-rsa python3-requests python3-six python3-websocket-client"
		yum install -y ${yumPacks}
		for yumPack in ${yumPacks}
		do
			rpmPack=$(rpm -q ${yumPack})
			packCheck=$(echo ${rpmPack}|grep not)
			if [ "${packCheck}" ]; then
				yum install ${yumPack} -y
			fi
		done

		pip3 install -U pip
		pip3 install Pillow psutil pyinotify pycryptodome upyun oss2 pymysql qrcode qiniu redis pymongo Cython configparser cos-python-sdk-v5 supervisor gevent-websocket pyopenssl
		pip3 install flask==1.1.4
		pip3 install Pillow -U

		pyenv_bin=/www/server/panel/pyenv/bin
		mkdir -p $pyenv_bin
		ln -sf /usr/local/bin/pip3 $pyenv_bin/pip
		ln -sf /usr/local/bin/pip3 $pyenv_bin/pip3
		ln -sf /usr/local/bin/pip3 $pyenv_bin/pip3.7

		if [ -f "/usr/bin/python3.7" ];then
			ln -sf /usr/bin/python3.7 $pyenv_bin/python
			ln -sf /usr/bin/python3.7 $pyenv_bin/python3
			ln -sf /usr/bin/python3.7 $pyenv_bin/python3.7
		elif [ -f "/usr/bin/python3.6"  ]; then
			ln -sf /usr/bin/python3.6 $pyenv_bin/python
			ln -sf /usr/bin/python3.6 $pyenv_bin/python3
			ln -sf /usr/bin/python3.6 $pyenv_bin/python3.7
		fi

		echo > $pyenv_bin/activate

		return
	fi

	py_version="3.7.16"
	mkdir -p $pyenv_path
	echo "True" > /www/disk.pl
	if [ ! -w /www/disk.pl ];then
		Red_Error "ERROR: Install python env fielded." "ERROR: /www目录无法写入，请检查目录/用户/磁盘权限！"
	fi
	os_type='el'
	os_version='7'
	is_export_openssl=0
	Get_Versions

	echo "OS: $os_type - $os_version"
	is_aarch64=$(uname -a|grep aarch64)
	if [ "$is_aarch64" != "" ];then
		is64bit="aarch64"
	fi
	
	if [ -f "/www/server/panel/pymake.pl" ];then
		os_version=""
		rm -f /www/server/panel/pymake.pl
	fi	
	echo "==============================================="
	echo "正在下载面板运行环境，请稍等..............."
	echo "==============================================="
	if [ "${os_version}" != "" ];then
		pyenv_file="/www/pyenv.tar.gz"
		
		# 可能的变量
		# os_type= anolis opencloudos el ali-linux- TencentOS- ubuntu debian
		#
		# os_version:
		#	el:7 8 9
		# 	ubuntu: 16 18 20 22 24
		#	debian: 10 11 12
		#	Anolis OS 8: 8
		#	OpenCloudOS: 9
		#	阿里云Linux al8: a18
		#	TencentOS 3.1: 3.1
		#
		# is64bit=64 非64系统无法正常安装，因此只有64
		#
		# 2025/12/12 17点36分 已上传至Release 通用区
		
		#wget -O $pyenv_file $download_Url/install/pyenv/pyenv-${os_type}${os_version}-x${is64bit}.tar.gz -T 20
		wget -O $pyenv_file ${dlco}/pyenv-${os_type}${os_version}-x64-upx.tar.gz -T 20
		if [ "$?" != "0" ];then
			#get_node_url $download_Url
			#wget -O $pyenv_file $download_Url/install/pyenv/pyenv-${os_type}${os_version}-x${is64bit}.tar.gz -T 20
			wget -O $pyenv_file ${dlco}/pyenv-${os_type}${os_version}-x64-upx.tar.gz -T 20
		fi
		tmp_size=$(du -b $pyenv_file|awk '{print $1}')
		if [ $tmp_size -lt 703460 ];then
			rm -f $pyenv_file
			echo "ERROR: Download python env fielded."
		else
			echo "Install python env..."
			tar zxvf $pyenv_file -C $pyenv_path/ > /dev/null
			chmod -R 700 $pyenv_path/pyenv/bin
			if [ ! -f $pyenv_path/pyenv/bin/python ];then
				rm -f $pyenv_file
				Red_Error "ERROR: Install python env fielded." "ERROR: 下载宝塔运行环境失败，请尝试重新安装！" 
			fi
			$pyenv_path/pyenv/bin/python3.7 -V
			if [ $? -eq 0 ];then
				rm -f $pyenv_file
				ln -sf $pyenv_path/pyenv/bin/pip3.7 /usr/bin/btpip
				ln -sf $pyenv_path/pyenv/bin/python3.7 /usr/bin/btpython
				source $pyenv_path/pyenv/bin/activate
				return
			else
				rm -f $pyenv_file
				rm -rf $pyenv_path/pyenv
			fi
		fi
	fi

	cd /www
	python_src='/www/python_src.tar.xz'
	# 上方已定义过py_version=3.7.16
	python_src_path="/www/Python-${py_version}"
	# 2025/12/14 已上传 Release Common
	# wget -O $python_src $download_Url/src/Python-${py_version}.tar.xz -T 15
	wget -O $python_src ${dlco}/Python-3.7.16-upx.tar.xz -T 15
	tmp_size=$(du -b $python_src|awk '{print $1}')
	if [ $tmp_size -lt 10703460 ];then
		rm -f $python_src
		Red_Error "ERROR: Download python source code fielded." "ERROR: 下载宝塔运行环境失败，请尝试重新安装！"
	fi
	tar xvf $python_src
	rm -f $python_src
	cd $python_src_path
	./configure --prefix=$pyenv_path/pyenv
	make -j$cpu_cpunt
	make install
	if [ ! -f $pyenv_path/pyenv/bin/python3.7 ];then
		rm -rf $python_src_path
		Red_Error "ERROR: Make python env fielded." "ERROR: 编译宝塔运行环境失败！"
	fi
	cd ~
	rm -rf $python_src_path
	# 2025/12/14 14点27分 已上传Release Commom
	#wget -O $pyenv_path/pyenv/bin/activate $download_Url/install/pyenv/activate.panel -T 5
	#wget -O $pyenv_path/pyenv/pip.txt $download_Url/install/pyenv/pip-3.7.16.txt -T 5
	wget -O $pyenv_path/pyenv/bin/activate ${dlco}/activate.panel -T 5
	wget -O $pyenv_path/pyenv/pip.txt ${dlco}/pip-3.7.16.txt -T 5
	ln -sf $pyenv_path/pyenv/bin/pip3.7 $pyenv_path/pyenv/bin/pip
	ln -sf $pyenv_path/pyenv/bin/python3.7 $pyenv_path/pyenv/bin/python
	ln -sf $pyenv_path/pyenv/bin/pip3.7 /usr/bin/btpip
	ln -sf $pyenv_path/pyenv/bin/python3.7 /usr/bin/btpython
	chmod -R 700 $pyenv_path/pyenv/bin
	$pyenv_path/pyenv/bin/pip install -U pip
	$pyenv_path/pyenv/bin/pip install -U setuptools==65.5.0
	$pyenv_path/pyenv/bin/pip install -U wheel==0.34.2 
	$pyenv_path/pyenv/bin/pip install -r $pyenv_path/pyenv/pip.txt

	# 2025/12/14 14点27分 已上传Release Commom
	#wget -O pip-packs.txt $download_Url/install/pyenv/pip-packs.txt
	wget -O pip-packs.txt ${dlco}/pip-packs.txt
	echo "正在后台安装pip依赖请稍等.........."
	PIP_PACKS=$(cat pip-packs.txt)
	for P_PACK in ${PIP_PACKS};
	do
		btpip show ${P_PACK} > /dev/null 2>&1
		if [ "$?" == "1" ];then
			btpip install ${P_PACK}
		fi 
	done

	rm -f pip-packs.txt

	source $pyenv_path/pyenv/bin/activate

	btpip install psutil
	btpip install gevent

	is_gevent=$($python_bin -m gevent 2>&1|grep -oE package)
	is_psutil=$($python_bin -m psutil 2>&1|grep -oE package)
	if [ "${is_gevent}" != "${is_psutil}" ];then
		Red_Error "ERROR: psutil/gevent install failed!"
	fi
}
Install_Bt(){
	if [ -f ${setup_path}/server/panel/data/port.pl ];then
		panelPort=$(cat ${setup_path}/server/panel/data/port.pl)
	fi
	if [ "${PANEL_PORT}" ];then
		panelPort=$PANEL_PORT
	fi
	mkdir -p ${setup_path}/server/panel/logs
	mkdir -p ${setup_path}/server/panel/vhost/apache
	mkdir -p ${setup_path}/server/panel/vhost/nginx
	mkdir -p ${setup_path}/server/panel/vhost/rewrite
	mkdir -p ${setup_path}/server/panel/install
	mkdir -p /www/server
	mkdir -p /www/wwwroot
	mkdir -p /www/wwwlogs
	mkdir -p /www/backup/database
	mkdir -p /www/backup/site

	if [ ! -d "/etc/init.d" ];then
		mkdir -p /etc/init.d
	fi

	if [ -f "/etc/init.d/bt" ]; then
		/etc/init.d/bt stop
		sleep 1
	fi

	# 2025/12/14 已上传 Release 11.0
	#wget -O /etc/init.d/bt ${download_Url}/install/src/bt6.init -T 15
	#wget -O /www/server/panel/install/public.sh ${downloads_Url}/install/public.sh -T 15
	wget  -O /etc/init.d/bt ${dl11}/src/bt6.init -T 15
	wget -O /www/server/panel/install/public.sh ${dlco}/public.sh -T 15
	echo "=============================================="
	echo "正在下载面板文件,请稍等..................."
	echo "=============================================="
	#wget -O panel.zip ${downloads_Url}/install/src/panel6_latest.zip -T 15
	wget -O panel.zip ${dl11}/panel6_latest.zip -T 15
	#wget -O panel.zip ${download_Url}/install/src/panel-lts.zip -T 15

	if [ -f "${setup_path}/server/panel/data/default.db" ];then
		if [ -d "/${setup_path}/server/panel/old_data" ];then
			rm -rf ${setup_path}/server/panel/old_data
		fi
		mkdir -p ${setup_path}/server/panel/old_data
		d_format=$(date +"%Y%m%d_%H%M%S")
		\cp -arf ${setup_path}/server/panel/data/default.db ${setup_path}/server/panel/data/default_backup_${d_format}.db
		mv -f ${setup_path}/server/panel/data/default.db ${setup_path}/server/panel/old_data/default.db
		mv -f ${setup_path}/server/panel/data/system.db ${setup_path}/server/panel/old_data/system.db
		mv -f ${setup_path}/server/panel/data/port.pl ${setup_path}/server/panel/old_data/port.pl
		mv -f ${setup_path}/server/panel/data/admin_path.pl ${setup_path}/server/panel/old_data/admin_path.pl
		
		if [ -d "${setup_path}/server/panel/data/db" ];then
			\cp -r ${setup_path}/server/panel/data/db ${setup_path}/server/panel/old_data/
		fi
		
	fi

	if [ ! -f "/usr/bin/unzip" ]; then
		if [ "${PM}" = "yum" ]; then
			yum install unzip -y
		elif [ "${PM}" = "apt-get" ]; then
			apt-get update
			apt-get install unzip -y 2>&1|tee /tmp/apt_install_log.log
			UNZIP_CHECK=$(which unzip)
			if [ "$?" != "0" ];then
				RECONFIGURE_CHECK=$(grep "dpkg --configure -a" /tmp/apt_install_log.log)
				if [ "${RECONFIGURE_CHECK}" ];then
					dpkg --configure -a
				fi
				APT_LOCK_CHECH=$(grep "/var/lib/dpkg/lock" /tmp/apt_install_log.log)
				if [ "${APT_LOCK_CHECH}" ];then
					pkill dpkg
					pkill apt-get
					pkill apt
					[ -e /var/lib/dpkg/lock-frontend ] && rm -f /var/lib/dpkg/lock-frontend
					[ -e /var/lib/dpkg/lock ] && rm -f /var/lib/dpkg/lock
					[ -e /var/lib/apt/lists/lock ] && rm -f /var/lib/apt/lists/lock
					[ -e /var/cache/apt/archives/lock ] && rm -f /var/cache/apt/archives/lock
					dpkg --configure -a
				fi
				sleep 5
				apt-get install unzip -y
			fi
		fi
	fi

	unzip -o panel.zip -d ${setup_path}/server/ > /dev/null 2>&1

	if [ -d "${setup_path}/server/panel/old_data" ];then
		mv -f ${setup_path}/server/panel/old_data/default.db ${setup_path}/server/panel/data/default.db
		mv -f ${setup_path}/server/panel/old_data/system.db ${setup_path}/server/panel/data/system.db
		mv -f ${setup_path}/server/panel/old_data/port.pl ${setup_path}/server/panel/data/port.pl
		mv -f ${setup_path}/server/panel/old_data/admin_path.pl ${setup_path}/server/panel/data/admin_path.pl
		
		if [ -d "${setup_path}/server/panel/old_data/db" ];then
			\cp -r ${setup_path}/server/panel/old_data/db ${setup_path}/server/panel/data/
		fi
		
		if [ -d "/${setup_path}/server/panel/old_data" ];then
			rm -rf ${setup_path}/server/panel/old_data
		fi
	fi

	if [ ! -f ${setup_path}/server/panel/tools.py ] || [ ! -f ${setup_path}/server/panel/BT-Panel ];then
		ls -lh panel.zip
		Red_Error "ERROR: Failed to download, please try install again!" "ERROR: 下载宝塔失败，请尝试重新安装！"
	fi
    
    SYS_LOG_CHECK=$(grep ^weekly /etc/logrotate.conf)
    if [ "${SYS_LOG_CHECK}" ];then
        sed -i 's/rotate [0-9]*/rotate 8/g' /etc/logrotate.conf 
    fi

	rm -f panel.zip
	# 2025/12/14 14点42分 已上传Release 11.0
	#wget -O /www/server/panel/data/userInfo.json http://io.bt.sy/install/userInfo.json
	wget -O /www/server/panel/data/userInfo.json ${dlco}/userInfo.json
	sed -i 's/[0-9\.]\+[ ]\+www.bt.cn//g' /etc/hosts
	sed -i 's/[0-9\.]\+[ ]\+api.bt.sb//g' /etc/hosts
	rm -f ${setup_path}/server/panel/class/*.pyc
	rm -f ${setup_path}/server/panel/*.pyc

	chmod +x /etc/init.d/bt
	chmod -R 600 ${setup_path}/server/panel
	chmod -R +x ${setup_path}/server/panel/script
	ln -sf /etc/init.d/bt /usr/bin/bt
	echo "${panelPort}" > ${setup_path}/server/panel/data/port.pl
	# 2025/12/14 14点42分 已上传Release 11.0
	#wget -O /etc/init.d/bt ${download_Url}/install/src/bt7.init -T 15
	#wget -O /www/server/panel/init.sh ${download_Url}/install/src/bt7.init -T 15
	#wget -O /www/server/panel/data/softList.conf ${download_Url}/install/conf/softListtls10.conf
	wget -O /etc/init.d/bt ${dl11}/bt7.init -T 15
	wget -O /www/server/panel/init.sh ${dl11}/bt7.init -T 15
	wget -O /www/server/panel/data/softList.conf ${dl11}/softListtls10.conf

  	if [ ! -f "${setup_path}/server/panel/data/installCount.pl" ];then
		echo "1 $(date)" > ${setup_path}/server/panel/data/installCount.pl
	elif [ -f "${setup_path}/server/panel/data/installCount.pl" ];then
		INSTALL_COUNT=$(cat ${setup_path}/server/panel/data/installCount.pl|awk '{last=$1} END {print last}')
		echo "$((INSTALL_COUNT+1)) $(date)" >> ${setup_path}/server/panel/data/installCount.pl
	fi 

}
Set_Bt_Panel(){
	Run_User="www"
	wwwUser=$(cat /etc/passwd|cut -d ":" -f 1|grep ^www$)
	if [ "${wwwUser}" != "www" ];then
		groupadd ${Run_User}
		useradd -s /sbin/nologin -g ${Run_User} ${Run_User}
	fi

	password=$(cat /dev/urandom | head -n 16 | md5sum | head -c 8)
	if [ "$PANEL_PASSWORD" ];then
		password=$PANEL_PASSWORD
	fi
	sleep 1
	admin_auth="/www/server/panel/data/admin_path.pl"
	if [ ! -f ${admin_auth} ];then
		auth_path=$(cat /dev/urandom | head -n 16 | md5sum | head -c 8)
		echo "/${auth_path}" > ${admin_auth}
	fi
	if [ "${SAFE_PATH}" ];then
		auth_path=$SAFE_PATH
		echo "/${auth_path}" > ${admin_auth}
	fi
	chmod -R 700 $pyenv_path/pyenv/bin
	if [ ! -f "/www/server/panel/pyenv/n.pl" ];then
		btpip install docxtpl==0.16.7
		/www/server/panel/pyenv/bin/pip3 install pymongo
		/www/server/panel/pyenv/bin/pip3 install psycopg2-binary
		/www/server/panel/pyenv/bin/pip3 install flask -U
		/www/server/panel/pyenv/bin/pip3 install flask-sock
		/www/server/panel/pyenv/bin/pip3 install -I gevent
		btpip install simple-websocket==0.10.0
		btpip install natsort
		btpip uninstall enum34 -y
		btpip install geoip2==4.7.0
		btpip install brotli
		btpip install PyMySQL
	fi
	auth_path=$(cat ${admin_auth})
	cd ${setup_path}/server/panel/
	/etc/init.d/bt start
	$python_bin -m py_compile tools.py
	$python_bin tools.py username
	username=$($python_bin tools.py panel ${password})
	if [ "$PANEL_USER" ];then
		username=$PANEL_USER
	fi
	cd ~
	echo "${password}" > ${setup_path}/server/panel/default.pl
	chmod 600 ${setup_path}/server/panel/default.pl
	sleep 3
	if [ "$SET_SSL" == true ]; then
		if [ ! -f "/www/server/panel/pyenv/n.pl" ];then
        	btpip install -I pyOpenSSl 2>/dev/null
    	fi
    	echo "========================================"
    	echo "正在开启面板SSL，请稍等............ "
    	echo "========================================"
    	echo -n " -4 " > /www/server/panel/data/v4.pl
    	btpython /www/server/panel/tools.py ssl > /dev/null 2>&1
        echo "True" > /www/server/panel/data/ssl.pl
    	echo "证书开启成功！"
    	echo "========================================"
    fi
	/etc/init.d/bt stop
	sleep 5
	/etc/init.d/bt start 	
	sleep 5
	isStart=$(ps aux |grep 'BT-Panel'|grep -v grep|awk '{print $2}')
	LOCAL_CURL=$(curl 127.0.0.1:${panelPort}/login 2>&1 |grep -i html)
	if [ -z "${isStart}" ];then
		/etc/init.d/bt 22
		cd /www/server/panel/pyenv/bin
		touch t.pl
		ls -al python3.7 python
		lsattr python3.7 python
		btpython /www/server/panel/BT-Panel
		Red_Error "ERROR: The BT-Panel service startup failed." "ERROR: 宝塔启动失败"
	fi
# 	wget -O oneav_bt.sh https://download.bt.cn/install/plugin/oneav/install.sh > /dev/null 2>&1
# 	bash oneav_bt.sh install > /www/server/panel/install//btinstall.log 2>&1
# 	rm -f oneav_bt.sh

	if [ "$PANEL_USER" ];then
		cd ${setup_path}/server/panel/
		btpython -c 'import tools;tools.set_panel_username("'$PANEL_USER'")'
		cd ~
	fi
	if [ -f "/usr/bin/sqlite3" ] ;then
	    sqlite3 /www/server/panel/data/db/panel.db "UPDATE config SET status = '1' WHERE id = '1';"  > /dev/null 2>&1
    fi
}
Set_Firewall(){
	sshPort=$(cat /etc/ssh/sshd_config | grep 'Port '|awk '{print $2}')
	if [ "${PM}" = "apt-get" ]; then
		apt-get install -y ufw
		if [ -f "/usr/sbin/ufw" ];then
			echo -e "正在开放必要防火墙端口"
			ufw allow 20/tcp
			ufw allow 21/tcp
			ufw allow 22/tcp
			ufw allow 80/tcp
			ufw allow 443/tcp
			#ufw allow 888/tcp
			ufw allow ${panelPort}/tcp
			ufw allow ${sshPort}/tcp
			ufw allow 39000:40000/tcp
			ufw_status=`ufw status`
			echo y|ufw enable
			ufw default deny
			ufw reload
		fi
	else
		if [ -f "/etc/init.d/iptables" ];then
			iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport 20 -j ACCEPT
			iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport 21 -j ACCEPT
			iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
			iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport 80 -j ACCEPT
			iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport 443 -j ACCEPT
			iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport ${panelPort} -j ACCEPT
			iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport ${sshPort} -j ACCEPT
			iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport 39000:40000 -j ACCEPT
			#iptables -I INPUT -p tcp -m state --state NEW -m udp --dport 39000:40000 -j ACCEPT
			iptables -A INPUT -p icmp --icmp-type any -j ACCEPT
			iptables -A INPUT -s localhost -d localhost -j ACCEPT
			iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
			iptables -P INPUT DROP
			service iptables save
			sed -i "s#IPTABLES_MODULES=\"\"#IPTABLES_MODULES=\"ip_conntrack_netbios_ns ip_conntrack_ftp ip_nat_ftp\"#" /etc/sysconfig/iptables-config
			iptables_status=$(service iptables status | grep 'not running')
			if [ "${iptables_status}" == '' ];then
				service iptables restart
			fi
		else
			AliyunCheck=$(cat /etc/redhat-release|grep "Aliyun Linux")
			[ "${AliyunCheck}" ] && return
			yum install firewalld -y
			[ "${Centos8Check}" ] && yum reinstall python3-six -y
			systemctl enable firewalld
			systemctl start firewalld
			firewall-cmd --set-default-zone=public > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --add-port=20/tcp > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --add-port=21/tcp > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --add-port=22/tcp > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --add-port=80/tcp > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --add-port=443/tcp > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --add-port=${panelPort}/tcp > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --add-port=${sshPort}/tcp > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --add-port=39000-40000/tcp > /dev/null 2>&1
			#firewall-cmd --permanent --zone=public --add-port=39000-40000/udp > /dev/null 2>&1
			firewall-cmd --reload
		fi
	fi
}
Get_Ip_Address(){
	getIpAddress=""
	#getIpAddress=$(curl -sS --connect-timeout 10 -m 60 https://www.bt.cn/Api/getIpAddress )

	ipv4_address=""
	ipv6_address=""

	ipv4_address=$(curl -4 -sS --connect-timeout 4 -m 5 ping0.cc 2>&1 | tr -d '\n\r')
	IPV4_REGEX="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
	if ! [[ $ipv4_address =~ $IPV4_REGEX ]]; then
    	ipv4_address=$(curl -4 -sS --connect-timeout 4 -m 5 https://api.bt.cn/Api/getIpAddress  2>&1)
    	if [ -z "${ipv4_address}" ]; then
        	ipv4_address=$(curl -4 -sS --connect-timeout 4 -m 5 https://www.bt.cn/Api/getIpAddress  2>&1)
        	if [ -z "${ipv4_address}" ]; then
            	ipv4_address=$(curl -4 -sS --connect-timeout 4 -m 5 https://www.aapanel.com/api/common/getClientIP  2>&1)
        	fi
    	fi
    	if ! [[ $ipv4_address =~ $IPV4_REGEX ]]; then
        ipv4_address=""
    	fi
	fi


	ipv6_address=$(curl -6 -sS --connect-timeout 4 -m 5 ping0.cc 2>&1 | tr -d '\n\r')
	IPV6_REGEX="^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
	if ! [[ $ipv6_address =~ $IPV6_REGEX ]]; then
    	ipv6_address=$(curl -6 -sS --connect-timeout 4 -m 5 https://www.bt.cn/Api/getIpAddress  2>&1)
    	if ! [[ $ipv6_address =~ $IPV6_REGEX ]]; then
        	ipv6_address=""
    	else
        	if [[ ! $ipv6_address =~ ^\[ ]]; then
            ipv6_address="[$ipv6_address]"
        	fi
    	fi
	else
    	if [[ ! $ipv6_address =~ ^\[ ]]; then
        ipv6_address="[$ipv6_address]"
    	fi
	fi

	if [ "${ipv4_address}" ];then
		getIpAddress=$ipv4_address
	elif [ "${ipv6_address}" ];then
		getIpAddress=$ipv6_address
	fi


	if [ -z "${getIpAddress}" ] || [ "${getIpAddress}" = "0.0.0.0" ]; then
		isHosts=$(cat /etc/hosts|grep 'www.bt.cn')
		if [ -z "${isHosts}" ];then
			echo "" >> /etc/hosts
			echo "116.213.43.206 www.bt.cn" >> /etc/hosts
			getIpAddress=$(curl -sS --connect-timeout 10 -m 60 https://www.bt.cn/Api/getIpAddress )
			if [ -z "${getIpAddress}" ];then
				sed -i "/bt.cn/d" /etc/hosts
			fi
		fi
	fi
	
	# 检查CN_CHECK是否已预设为True或False，否则进行检测
	if [ "${CN_CHECK}" != "True" ] && [ "${CN_CHECK}" != "False" ]; then
        	# 检测当前网络环境是否在中国大陆，如果是则使用国内节点列表
        	CN_CHECK=$(curl -sS --connect-timeout 10 -m 10 https://api.bt.cn/api/isCN )
	fi
	if [ "${CN_CHECK}" == "True" ];then
        echo "True" > /www/server/panel/data/domestic_ip.pl
	else
		echo "True" > /www/server/panel/data/foreign_ip.pl
	fi

	ipv4Check=$($python_bin -c "import re; print(re.match('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$','${getIpAddress}'))")
	if [ "${ipv4Check}" == "None" ];then
		ipv6Address=$(echo ${getIpAddress}|tr -d "[]")
		ipv6Check=$($python_bin -c "import re; print(re.match('^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$','${ipv6Address}'))")
		if [ "${ipv6Check}" == "None" ]; then
			getIpAddress="SERVER_IP"
		else
			echo "True" > ${setup_path}/server/panel/data/ipv6.pl
			sleep 1
			/etc/init.d/bt restart
			getIpAddress=$(echo "[$getIpAddress]")
		fi
	fi

	if [ "${getIpAddress}" != "SERVER_IP" ];then
		echo "${getIpAddress}" > ${setup_path}/server/panel/data/iplist.txt
	fi
	LOCAL_IP=$(ip addr show scope global | grep -E -o 'inet ([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '{print $2}' | head -n 1)
}
Setup_Count(){
	if [ "$1" != "" ];then
		echo $1 > /www/server/panel/data/o.pl
		cd /www/server/panel
		$python_bin tools.py o
	fi
	echo /www > /var/bt_setupPath.conf
}
Start_Count(){
	echo /www > /var/bt_setupPath.conf
	echo "check_certificate = off" >> /etc/wgetrc
}

# 主执行函数
Install_Main(){
	Ready_Check
	Start_Count ${IDC_CODE}
	Set_Ssl
	startTime=`date +%s`
	Lock_Clear
	System_Check
	Get_Pack_Manager
	Set_Repo_Url
	get_node_url

	MEM_TOTAL=$(free -g|grep Mem|awk '{print $2}')
	if [ "${MEM_TOTAL}" -le "1" ];then
		Auto_Swap
	fi
	
	if [ "${PM}" = "yum" ]; then
		Install_RPM_Pack
	elif [ "${PM}" = "apt-get" ]; then
		Install_Deb_Pack
	fi

	Install_Python_Lib
	Install_Bt
	

	Set_Bt_Panel
	Service_Add
	Set_Firewall

	Get_Ip_Address
	Setup_Count ${IDC_CODE}
	Add_lib_Install
}


clear

while [ "$ad_confirm" != 'y' ] && [ "$ad_confirm" != 'n' ]
do
	read -p "请问您是否执行宝塔面板安装？(y/n): " ad_confirm;
done

if [ "$ad_confirm" == 'n' ];then
	echo "已取消安装"
	exit;
fi

echo "
+----------------------------------------------------------------------
| Bt-WebPanel FOR CentOS/Ubuntu/Debian
+----------------------------------------------------------------------
| Copyright © 2015-2099 BT-SOFT(http://www.bt.cn) All rights reserved.
+----------------------------------------------------------------------
| The WebPanel URL will be http://SERVER_IP:${panelPort} when installed.
+----------------------------------------------------------------------
| 为了您的正常使用，请确保使用全新或纯净的系统安装宝塔面板，不支持已部署项目/环境的系统安装
+----------------------------------------------------------------------
"
echo -e "正在检查服务器地域是否处于中国大陆，本安装脚本不适用中国大陆地区，否则无法下载"
PING0_RESULT=$(curl -sS --connect-timeout 5 -m 5 ping0.cc/geo 2>/dev/null)

if [ $? -eq 0 ] && [ -n "$PING0_RESULT" ]; then
    # ping0.cc请求成功，根据内容判断地区
    #echo -e "$PING0_RESULT"
    if echo "$PING0_RESULT" | grep -q -E "香港|台湾|澳门"; then
        CN_CHECK="False"
        echo -e "检测到港澳台地区"
    elif echo "$PING0_RESULT" | grep -q "中国"; then
        # 香港|台湾|澳门 匹配失败
        # 中国匹配成功
        CN_CHECK="True"
        echo -e "检测到中国大陆地区"
    else
        # 中国 香港|台湾|澳门 匹配失败
        CN_CHECK="False"
		echo -e ""
        echo -e "检测到非中国大陆及港澳台地区"
    fi
    unset PING0_RESULT 2>/dev/null
else
    # ping0.cc请求失败，使用备用API
    CN_CHECK=$(curl -sS --connect-timeout 10 -m 10 https://api.bt.cn/api/isCN 2>/dev/null)
    # 如果备用API也失败，设置默认值
    if [ $? -ne 0 ] || [ -z "$CN_CHECK" ]; then
        echo -e "无法确定服务器地域，假设为非中国大陆"
        CN_CHECK="False"
    fi
fi
unset PING0_RESULT
if [ "${CN_CHECK}" == "True" ]; then
    echo -e "检测到中国大陆地区服务器"
    echo -e "本脚本仅适用于非中国大陆地域的服务器使用"
    echo -e "脚本高度依赖Github作为下载源，大陆地域机器可能无法连接"
    read -p "请问是否继续执行安装？ 输入y开始安装 " tongyi
    if [[ ! "$tongyi" =~ ^[Yy]$ ]]; then
        echo -e "------------"
        echo "取消安装"
        exit 1
    fi

    if [[ -v tongyi ]]; then
        unset tongyi
    fi
else
    echo -e "检测到非中国大陆地区服务器，继续执行安装..."
fi

echo -e "正在检查系统环境"


while [ ${#} -gt 0 ]; do
	case $1 in
		-u|--user)
			PANEL_USER=$2
			shift 1
			;;
		-p|--password)
			PANEL_PASSWORD=$2
			shift 1
			;;
		-P|--port)
			PANEL_PORT=$2
			shift 1
			;;
		--safe-path)
			SAFE_PATH=$2
			shift 1
			;;
		--ssl-disable)
			SSL_PL="disable"
			;;
		-y)
			go="y"
			;;
		*)
			IDC_CODE=$1
			;;
	esac
	shift 1
done


if [ -f "/www/server/panel/BT-Panel" ];then
	AAPANEL_CHECK=$(grep www.aapanel.com /www/server/panel/BT-Panel)
	if [ "${AAPANEL_CHECK}" ];then
		echo -e "----------------------------------------------------"
		echo -e "检查已安装有aapanel，无法进行覆盖安装宝塔面板"
		echo -e "如继续执行安装将移去aapanel面板数据（备份至/www/server/aapanel路径） 全新安装宝塔面板"
		echo -e "aapanel is alreday installed,Can't install panel"
		echo -e "is install Baota panel,  aapanel data will be removed (backed up to /www/server/aapanel)"
		echo -e "Beginning new Baota panel installation."
		echo -e "----------------------------------------------------"
		echo -e "已知风险/Enter yes to force installation"
		read -p "输入y开始安装: " y;
		if [ "$yes" != "y" ];then
			echo -e "------------"
			echo "取消安装"
			exit;
		fi
		unset yes 2>/dev/null
		bt stop
		sleep 1
		mv /www/server/panel /www/server/aapanel
	fi
fi


ARCH_LINUX=$(cat /etc/os-release |grep "Arch Linux")
if [ "${ARCH_LINUX}" ] && [ -f "/usr/bin/pacman" ];then
	pacman -Sy 
	pacman -S curl wget unzip firewalld openssl pkg-config make gcc cmake libxml2 libxslt libvpx gd libsodium oniguruma sqlite libzip autoconf inetutils sudo --noconfirm
fi

CURL_CHECK=$(which curl)

Install_Main

PANEL_SSL=$(cat /www/server/panel/data/ssl.pl 2> /dev/null)
if [ "${PANEL_SSL}" == "True" ];then
	HTTP_S="https"
else
	HTTP_S="http"
fi 

#echo > /www/server/panel/data/bind.pl
rm -rf /www/server/panel/data/bind.pl
rm -rf /www/server/panel/data/userInfo.json
echo -e "=================================================================="
echo -e "\033[32mCongratulations! Installed successfully!\033[0m"
echo -e "=============注意：首次打开面板浏览器将提示不安全================="
echo -e ""
echo -e " 请选择以下其中一种方式解决不安全提醒"
echo -e " 1、下载证书，地址：https://dg2.bt.cn/ssl/baota_root.pfx，双击安装,密码【www.bt.cn】"
echo -e " 2、点击【高级】-【继续访问】或【接受风险并继续】访问"
echo -e " 教程：https://www.bt.cn/bbs/thread-117246-1-1.html"
echo -e " mac用户请下载使用此证书：https://dg2.bt.cn/ssl/mac.crt" 
echo -e "" 
echo -e "========================面板账户登录信息=========================="
echo -e ""
echo -e " 【云服务器】请在安全组放行 $panelPort 端口"
if [ -z "${ipv4_address}" ] && [ -z "${ipv6_address}" ];then
    echo -e " 外网面板地址:      ${HTTP_S}://SERVER_IP:${panelPort}${auth_path}"
fi
if [ "${ipv4_address}" ];then
    echo -e " 外网ipv4面板地址: ${HTTP_S}://${ipv4_address}:${panelPort}${auth_path}"
fi
if [ "${ipv6_address}" ];then
    echo -e " 外网ipv6面板地址: ${HTTP_S}://${ipv6_address}:${panelPort}${auth_path}"
fi
echo -e " 内网面板地址:     ${HTTP_S}://${LOCAL_IP}:${panelPort}${auth_path}"
echo -e " username: $username"
echo -e " password: $password"
echo -e ""
echo -e "=================================================================="

endTime=`date +%s`
((outTime=($endTime-$startTime)/60))
if [ "${outTime}" -le "5" ];then
    echo https://download.bt.cn > /www/server/panel/install/d_node.pl
fi
if [ "${outTime}" == "0" ];then
	((outTime=($endTime-$startTime)))
	echo -e "Time consumed:\033[32m $outTime \033[0mseconds!"
else
	echo -e "Time consumed:\033[32m $outTime \033[0mMinute!"
fi
btpython /www/server/panel/tools.py ssl > /dev/null 2>&1
