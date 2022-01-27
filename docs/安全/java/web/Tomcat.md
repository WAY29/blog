---
created: '21/08/02'
title: Tomcat
tags:
  - java
---
# Tomcat
[tomcat官网](http://tomcat.apache.org/)


## 安装tomcat
直接去官网下载然后安装，或者使用包管理器进行安装。

## 启动，关闭Tomcat
在Tomcat/bin目录中有startup.sh/startup.bat脚本用于启动Tomcat，Tomcat启动后默认开启在`http://127.0.0.1:8080`

在Tomcat/bin目录中有shutdown.sh/shutdown.bat脚本用于关闭Tomcat

## Tomcat配置
### 监听地址配置
修改name即可，默认是localhost，只能由本地访问，这个name也可以是一个域名，服务器启动时会优先从hosts文件中寻找这个域名并指向对应的地址(其实localhost也是这个道理，在hosts中直接指向了127.0.0.1，所以这里name为localhost和name为127.0.0.1是一样的)
```xml
<Host name="localhost"  appBase="webapps"
            unpackWARs="true" autoDeploy="true">
```
### 监听端口配置
修改port端口即可，默认是8080
```xml
<Connector port="8080" protocol="HTTP/1.1"
               connectionTimeout="20000"
               redirectPort="8443" />
```
### web目录配置
修改appBase即可，默认是当前目录下的webapps目录
```xml
<Host name="localhost"  appBase="webapps"
            unpackWARs="true" autoDeploy="true">
```

## 编写web页面
web目录默认在webapps下，ROOT是默认的网站根目录下的内容，其他的文件夹对应的就是访问的路径，例如examples文件夹下的内容需要通过`http://127.0.0.1:8080/examples/`访问。

我们可以在webapps下新建一个文件夹，然后写入index.html(默认打开的页面)，启动Tomcat服务器后访问即可。

或者我们可以参考webapps/examples下的内容进行学习，里面有很多官方的例子。

## IDEA中使用Tomcat
### 创建web项目
![](https://gitee.com/guuest/images/raw/master/img/20210802161557.png)

### 配置Tomcat
点击右上角的ADD CONFIGURATION添加配置
![](https://gitee.com/guuest/images/raw/master/img/20210802154815.png)

点击左上角的加号并选择Tomcat Server - Local
![](https://gitee.com/guuest/images/raw/master/img/20210802154945.png)

然后可以对Tomcat进行一些配置
![](https://gitee.com/guuest/images/raw/master/img/20210802155205.png)

还要再Deployment中添加artifacts，这里Application Context是一个路径映射，默认为/，即访问`http://127.0.0.1:8080/`，如果设置为其他内容如/test，则访问`http://127.0.0.1:8080/test`
![](https://gitee.com/guuest/images/raw/master/img/20210802161634.png)

配置完之后整个项目结构大概是这样
![](https://gitee.com/guuest/images/raw/master/img/20210802162143.png)

最后点击右上角的绿色运行箭头即可

## 总结
本节主要介绍了Tomcat的安装，启动和配置，以及IDEA中Web项目的创建与Tomcat的配置