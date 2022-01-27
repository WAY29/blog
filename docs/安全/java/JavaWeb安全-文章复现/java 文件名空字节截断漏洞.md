---
created: '21/11/16'
title: java 文件名空字节截断漏洞
tags:
  - java
  - java安全
---
# java 文件名空字节截断漏洞
空字节截断漏洞漏洞在诸多编程语言中都存在，究其根本是Java在调用文件系统(C实现)读写文件时导致的漏洞，并不是Java本身的安全问题。不过好在高版本的JDK在处理文件时已经把空字节文件名进行了安全检测处理。

## 漏洞历史
- 漏洞存在于`java SE 7 update 40`之前

- 漏洞在`2013年9月10日`发布的`java SE 7 Update 40`修复

  - 修复方法: 在`java.io.File`类中添加了一个`isInvalid`方法，专门检测文件名中是否包含了空字节, 修复的JDK版本所有跟文件名相关的操作都调用了isInvalid方法检测，防止文件名空字节截断

```Java
 final boolean isInvalid() {
     if (status == null) {
         status = (this.path.indexOf('\u0000') < 0) ? PathStatus.CHECKED : PathStatus.INVALID;
     }
     return status == PathStatus.INVALID;
 }
```

## 漏洞利用
```java
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public class FileNullBytes {

    public static void main(String[] args) {
        try {
            String           fileName = "/tmp/null-bytes.txt\u0000.jpg";
            FileOutputStream fos      = new FileOutputStream(new File(fileName));
            fos.write("Test".getBytes());
            fos.flush();
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
// 使用JDK1.7.0.40之前的版本成功截断写入null-bytes.txt
// 使用JDK1.7.0.40及之后的版本抛出java.io.FileNotFoundException: Invalid file path异常
 
```

## 漏洞利用场景
Java空字节截断利用场景最常见的利用场景就是文件上传时后端获取文件名后使用了`endWith`、正则使用如:`.(jpg|png|gif)$`验证文件名后缀合法性且文件名最终原样保存,同理文件删除(`delete`)、获取文件路径(`getCanonicalPath`)、创建文件(`createNewFile`)、文件重命名(`renameTo`)等方法也可适用。

## 修复方案
最简单直接的方式就是升级JDK，如果担心升级JDK出现兼容性问题可在文件操作时检测下文件名中是否包含空字节，如JDK的修复方式:`fileName.indexOf('\u0000')`即可

