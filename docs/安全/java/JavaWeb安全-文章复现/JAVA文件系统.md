---
created: '21/07/07'
title: java文件系统
tags:
  - java
  - java安全
---
# JAVA文件系统
JAVA SE内置了两类文件系统:：`java.io`和`java.nio`，`java.nio`的实现是`sun.nio`
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20210707110121.png)
## JAVA IO 文件系统
Java抽象出了一个文件系统的对象:`java.io.FileSystem`，不同的操作系统有不一样的文件系统,例如`Windows`和`Unix`就是两种不一样的文件系统： `java.io.UnixFileSystem`、`java.io.WinNTFileSystem`
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20210707110434.png)
`java.io.FileSystem`是一个抽象类，它抽象了对文件的操作，不同操作系统版本的JDK会实现其抽象的方法从而也就实现了跨平台的文件的访问操作。

需要注意的点有：
1.  并不是所有的文件操作都在`java.io.FileSystem`中定义,文件的读取最终调用的是`java.io.FileInputStream#read0、readBytes`、`java.io.RandomAccessFile#read0、readBytes`,而写文件调用的是`java.io.FileOutputStream#writeBytes`、`java.io.RandomAccessFile#write0`。
2.  Java有两类文件系统API！一个是基于`阻塞模式的IO`的文件系统，另一是JDK7+基于`NIO.2`的文件系统。

### FileInputStream
示例代码如下。
 ```java
package top.longlone;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;

public class FileStudy {
    public static void main(String[] args) throws Exception {
        File file = new File("C:\\Users\\11624\\Desktop\\test.txt");
        FileInputStream fileInputStream = new FileInputStream(file);
        int a = 0;
        byte[] bytes = new byte[1024];
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        while ((a = fileInputStream.read(bytes)) != -1) {
            byteArrayOutputStream.write(bytes, 0, a);
        }
        System.out.println(byteArrayOutputStream.toString());
    }
}
```

### FileOutputStream
示例代码如下。
```java
package top.longlone;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

public class FileStudy {
    public static void main(String[] args) throws Exception {
        File file = new File("C:\\Users\\11624\\Desktop\\test2.txt");
        String content = "Hello world.";
        FileOutputStream fileOutputStream = new FileOutputStream(file);
        fileOutputStream.write(content.getBytes(StandardCharsets.UTF_8));
        fileOutputStream.flush();
        fileOutputStream.close();
    }
}

```

## JAVA NIO.2 文件系统
Java 7提出了一个基于NIO的文件系统，这个NIO文件系统和阻塞IO文件系统两者是完全独立的。`java.nio.file.spi.FileSystemProvider`对文件的封装和`java.io.FileSystem`同理。
NIO的文件操作在不同的系统的最终实现类也是不一样的，比如Mac的实现类是: `sun.nio.fs.UnixNativeDispatcher`,而Windows的实现类是`sun.nio.fs.WindowsNativeDispatcher`。
合理的利用NIO文件系统这一特性我们可以绕过某些只是防御了`java.io.FileSystem`的`WAF`/`RASP`

