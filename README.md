
# KoKo

Koko 是 Go 版本的 coco；重构了 coco 的 SSH/SFTP 服务和 Web Terminal 服务


## 移植 vscode 代理功能到 v2.7

将上游支持 vscode 代理的新特性移植到旧版本的 Koko 中，满足使用日常需求。

沿用了上游的做法，可以通过新增如下 vscode config 来支持 vscode 直连资产：

```
Host JMP
  HostName <koko_ssh_ip>
  User <jmp_login_user>#<permed_asset_user>#<asset_ip>
  Port <koko_ssh_port>
```

## 主要功能


- SSH
- SFTP
- web terminal
- web文件管理


## 安装

1.下载项目

```shell
git clone https://github.com/jumpserver/koko.git
```

2.编译应用

在 koko 项目下构建应用.
```shell
make linux
```
> 如果构建成功，会在项目下自动生成build文件夹,里面包含当前分支的linux 64位版本压缩包.
因为使用go mod进行依赖管理，可以设置环境变量 GOPROXY=https://goproxy.io 代理下载部分依赖包。

## 使用

1.拷贝压缩包文件到服务器

2.解压编译的压缩包
```shell
tar xzf koko-[branch name]-[commit]-linux-amd64.tar.gz
```

3.创建配置文件config.yml，配置参数请参考[config_example.yml](https://github.com/jumpserver/koko/blob/master/config_example.yml)文件
```shell
touch config.yml
```

4.运行koko
```shell
cd kokodir
./koko
```


## 构建docker镜像

```shell
make docker
```
构建成功后，生成koko镜像
