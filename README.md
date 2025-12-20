### 安装命令，默认安装`11.0`版本，请通过更新命令进行更新

```
if [ -f /usr/bin/curl ];then curl -sSO -L https://github.com/sweetsky123/btpanel/releases/download/11.0/install_latest.sh;else wget -O install_latest.sh https://github.com/sweetsky123/btpanel/releases/download/11.0/install_latest.sh;fi;bash install_latest.sh && rm -rf install_latest.sh
```

### 更新面板至最新（11.4）版本，所有版本包括低版本都可以用此命令更新。

```
wget https://github.com/sweetsky123/btpanel/releases/download/11.4/update_panel.sh && bash update_panel.sh && rm update_panel.sh
```

```
curl -O -L https://github.com/sweetsky123/btpanel/releases/download/11.4/update_panel.sh && bash update_panel.sh && rm update_panel.sh
```

