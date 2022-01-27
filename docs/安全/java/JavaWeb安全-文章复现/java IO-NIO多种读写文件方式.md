---
created: '21/11/16'
title: java IO/NIO多种读写文件方式
tags:
  - java
  - java安全
---
#  java IO/NIO多种读写文件方式
我们通常读写文件都是使用的阻塞模式，与之对应的也就是`java.io.FileSystem`。`java.io.FileInputStream`类提供了对文件的读取功能，java的其他读取文件的方法基本上都是封装了`java.io.FileInputStream`类，比如：`java.io.FileReader`。

## FileInputStream
`FileInputStream调用链`
```
java.io.FileInputStream.readBytes(FileInputStream.java:219)
java.io.FileInputStream.read(FileInputStream.java:233)
com.anbai.sec.filesystem.FileInputStreamDemo.main(FileInputStreamDemo.java:27)
```
其中readBytes是native方法，文件的打开、关闭等方法也都是native方法
```
private native int readBytes(byte b[], int off, int len) throws IOException;
private native void open0(String name) throws FileNotFoundException;
private native int read0() throws IOException;
private native long skip0(long n) throws IOException;
private native int available0() throws IOException;
private native void close0() throws IOException;
```


FileInputStream 读取文件示例
```java

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;

public class Main {

    public static void main(String[] args) throws Exception {
        File file = new File("/etc/passwd");
        // 打开文件对象并创建文件输入流
        FileInputStream fis = new FileInputStream(file);

        // 定义每次输入流读取到的字节数对象
        int a = 0;

        // 定义缓冲区大小
        byte[] bytes = new byte[1024];

        // 创建二进制输出流对象
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // 循环读取文件内容
        while ((a = fis.read(bytes)) != -1) {
            // 截取缓冲区数组中的内容，(bytes, 0, a)其中的0表示从bytes数组的
            // 下标0开始截取，a表示输入流read到的字节数。
            out.write(bytes, 0, a);
        }
        
        System.out.println(out.toString());
    }
}


```

## FileOutputStream
FileOutputStream 写文件示例
```java

import java.io.IOException;
import java.io.File;
import java.io.FileOutputStream;

public class FileOutputStreamDemo {

    public static void main(String[] args) throws IOException {
        // 定义写入文件路径
        File file = new File("/tmp/1.txt");

        // 定义待写入文件内容
        String content = "Hello World.";

        // 创建FileOutputStream对象
        FileOutputStream fos = new FileOutputStream(file);

        // 写入内容二进制到文件
        fos.write(content.getBytes());
        fos.flush();
        fos.close();
    }

}
```

## RandomAccessFile
Java提供了一个非常有趣的读取文件内容的类: `java.io.RandomAccessFile`,这个类名字面意思是任意文件内容访问，特别之处是这个类不仅可以像`java.io.FileInputStream`一样读取文件，而且还可以像`java.io.FileOutputStream` 写文件

```java
// RandomAccessFile 读取文件示例 
import java.io.*;

public class Main {

    public static void main(String[] args) throws Exception {
        File file = new File("/etc/passwd");

        try {
            // 创建RandomAccessFile对象,r表示以只读模式打开文件，一共有:r(只读)、rw(读写)、
            // rws(读写内容同步)、rwd(读写内容或元数据同步)四种模式。
            RandomAccessFile raf = new RandomAccessFile(file, "r");

            // 定义每次输入流读取到的字节数对象
            int a = 0;

            // 定义缓冲区大小
            byte[] bytes = new byte[1024];

            // 创建二进制输出流对象
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            // 循环读取文件内容
            while ((a = raf.read(bytes)) != -1) {
                // 截取缓冲区数组中的内容，(bytes, 0, a)其中的0表示从bytes数组的
                // 下标0开始截取，a表示输入流read到的字节数。
                out.write(bytes, 0, a);
            }

            System.out.println(out.toString());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

// RandomAccessFile 写入文件示例

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;


public class Main {

    public static void main(String[] args) {
        File file = new File("./test.txt");

        // 定义待写入文件内容
        String content = "Hello World";

        try {
            // 创建RandomAccessFile对象,rw表示以读写模式打开文件，一共有:r(只读)、rw(读写)、
            // rws(读写内容同步)、rwd(读写内容或元数据同步)四种模式。
            RandomAccessFile raf = new RandomAccessFile(file, "rw");

            // 写入内容二进制到文件
            raf.write(content.getBytes());
            raf.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
```

## FileSystemProvider
前面章节提到了JDK7新增的NIO.2的`java.nio.file.spi.FileSystemProvider`,利用`FileSystemProvider`我们可以利用支持异步的通道(`Channel`)模式读取文件内容

`java.nio.file.Files`是JDK7开始提供的一个对文件读写取非常便捷的API，其底层实在是调用了`java.nio.file.spi.FileSystemProvider`来实现对文件的读写的。最为底层的实现类是`sun.nio.ch.FileDispatcherImpl#read0`

- 打开FileChannel的调用链
```text
sun.nio.ch.FileChannelImpl.<init>(FileChannelImpl.java:89)
sun.nio.ch.FileChannelImpl.open(FileChannelImpl.java:105)
sun.nio.fs.UnixChannelFactory.newFileChannel(UnixChannelFactory.java:137)
sun.nio.fs.UnixChannelFactory.newFileChannel(UnixChannelFactory.java:148)
sun.nio.fs.UnixFileSystemProvider.newByteChannel(UnixFileSystemProvider.java:212)
java.nio.file.Files.newByteChannel(Files.java:361)
java.nio.file.Files.newByteChannel(Files.java:407)
java.nio.file.Files.readAllBytes(Files.java:3152)
com.anbai.sec.filesystem.FilesDemo.main(FilesDemo.java:23) 
```

- 文件读取的调用链
```text
sun.nio.ch.FileChannelImpl.read(FileChannelImpl.java:147)
sun.nio.ch.ChannelInputStream.read(ChannelInputStream.java:65)
sun.nio.ch.ChannelInputStream.read(ChannelInputStream.java:109)
sun.nio.ch.ChannelInputStream.read(ChannelInputStream.java:103)
java.nio.file.Files.read(Files.java:3105)
java.nio.file.Files.readAllBytes(Files.java:3158)
com.anbai.sec.filesystem.FilesDemo.main(FilesDemo.java:23)
```

```java
// 使用FileSystemProvider读取文件示例
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Main {

    public static void main(String[] args) throws Exception {
        Path path = Paths.get("/etc/passwd");

        try {
            byte[] bytes = Files.readAllBytes(path);
            System.out.println(new String(bytes));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

// 使用FileSystemProvider写入文件示例
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Main {

    public static void main(String[] args) throws Exception {
        Path path = Paths.get("./test.txt");

        String content = "Hello World";
        try {
            Files.write(path, content.getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

```

