---
created: '21/06/28'
title: ClassLoader类加载机制
tags:
  - java
  - java安全
---
# ClassLoader类加载机制
Java程序在运行前需要先编译成`class文件`，Java类初始化的时候会调用`java.lang.ClassLoader`加载类字节码，`ClassLoader`会调用JVM的native方法(`defineClass0/1/2`)来定义一个`java.lang.Class`实例。

## ClassLoader
包含以下几个ClassLoader：
- `Bootstrap ClassLoader` (引导类加载器) 该类加载器实现于JVM层，采用C++编写
- `Extension ClassLoader` (扩展类加载器)
- `App ClassLoader` (系统类加载器) 默认的类加载器

ClassLoader的核心方法有：
1.  `loadClass` (加载指定的Java类)
2.  `findClass` (查找指定的Java类)
3.  `findLoadedClass` (查找JVM已经加载过的类)
4.  `defineClass` (定义一个Java类)
5.  `resolveClass` (链接指定的Java类)

## 类加载方式
### 显式加载
```java
// 反射加载TestHelloWorld示例
Class.forName("top.longlone.TestHelloWorld");
// ClassLoader加载TestHelloWorld示例
this.getClass().getClassLoader().loadClass("top.longlone.TestHelloWorld");
```
### 隐式加载
指直接`类名.方法名()`或`new`类实例。

## 类加载流程
1. 调用`loadClass`加载
2. 调用`findLoadedClass`检查是否已加载，若已加载则直接返回已加载的类
3. 如果创建ClassLoader时传入了父类加载器(`new ClassLoader(父类加载器)`)则使用父类加载器先加载,否则使用JVM的`Bootstrap ClassLoader`加载
4. 若父类加载器无法加载则调用自身`findClass`加载
5. 如果调用loadClass的时候传入的`resolve`参数为true，那么还需要调用`resolveClass`方法链接类,默认为false
6. 加载失败或返回加载后的`java.lang.Class`类对象

## 自定义ClassLoader
```java
package top.longlone;

import java.util.Base64;
import java.lang.reflect.Method;

public class ClassLoaderStudy extends ClassLoader {
    private static final String testClassName = "top.longlone.Hello";
    // base64 -w Hello.class
    private static final byte[] testClassBytes = Base64.getDecoder().decode("yv66vgAAADQAHAoACAARBwASCgACABEIABMKAAIAFAoAAgAVBwAWBwAXAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEABWhlbGxvAQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsBAApTb3VyY2VGaWxlAQAKSGVsbG8uamF2YQwACQAKAQAXamF2YS9sYW5nL1N0cmluZ0J1aWxkZXIBAAZIZWxsbyAMABgAGQwAGgAbAQASdG9wL2xvbmdsb25lL0hlbGxvAQAQamF2YS9sYW5nL09iamVjdAEABmFwcGVuZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwEACHRvU3RyaW5nAQAUKClMamF2YS9sYW5nL1N0cmluZzsAIQAHAAgAAAAAAAIAAQAJAAoAAQALAAAAHQABAAEAAAAFKrcAAbEAAAABAAwAAAAGAAEAAAADAAEADQAOAAEACwAAACwAAgACAAAAFLsAAlm3AAMSBLYABSu2AAW2AAawAAAAAQAMAAAABgABAAAABQABAA8AAAACABA=");

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        if (name.equals(testClassName)) {
            return defineClass(testClassName, testClassBytes, 0, testClassBytes.length);
        }
        return super.findClass(name);
    }

    public static void main(String[] args) throws Exception {
        ClassLoaderStudy loader = new ClassLoaderStudy();
        Class testClass = loader.loadClass(testClassName);
        Object o = testClass.newInstance();
        Method sayHello = o.getClass().getMethod("hello", String.class);
        String longlone = (String) sayHello.invoke(o, "Longlone");
        System.out.println(longlone);

    }
}
```

## URLClassLoader
```java
package top.longlone;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;

public class ClassLoaderStudy {
    public static void main(String[] args) throws Exception {
        URL url = new URL("http://127.0.0.1/cmd.jar");
        URLClassLoader urlClassLoader = new URLClassLoader(new URL[]{url});
        String cmd = "whoami";
        Class<?> cmdClass = urlClassLoader.loadClass("top.longlone.CMD");
        Process process = (Process) cmdClass.getMethod("exec", String.class).invoke(null, cmd);
        InputStream inputStream = process.getInputStream();
        ByteArrayOutputStream byteArrayInputStream = new ByteArrayOutputStream();
        byte[] bytes = new byte[1024];
        int a = -1;
        while ((a = inputStream.read(bytes)) != -1) {
            byteArrayInputStream.write(bytes, 0, a);
        }
        System.out.println(byteArrayInputStream.toString());
    }
}
```
