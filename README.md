安装命令，默认安装`11.0`版本，请通过更新命令进行更新

```
if [ -f /usr/bin/curl ];then wget https://github.com/sweetsky123/btpanel/releases/latest/download/install_latest.sh;else curl install_latest.sh https://github.com/sweetsky123/btpanel/releases/latest/download/install_latest.sh;fi;bash install_latest.sh && rm -rf install_latest.sh
```

更新面板至`11.3`版本，所有版本包括低版本都可以用此命令更新。

```
curl https://github.com/sweetsky123/btpanel/releases/latest/download/update_panel.sh|bash -s -- 11.3.0
```
