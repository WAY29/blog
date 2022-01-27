---
created: '21/07/02'
title: Unsafe
tags:
  - java
  - java安全
---
# Unsafe
`sun.misc.Unsafe`是Java底层API(`仅限Java内部使用,反射可调用`)提供的一个神奇的Java类，`Unsafe`提供了非常底层的`内存、CAS、线程调度、类、对象`等操作、`Unsafe`正如它的名字一样它提供的几乎所有的方法都是不安全的，本节只讲解如何使用`Unsafe`定义Java类、创建类实例。
由于Unsafe是禁止外部调用的,我们可以先看看Unsafe的代码片段,看看如何通过反射获取Unsafe实例
```java
import sun.reflect.CallerSensitive;
import sun.reflect.Reflection;

public final class Unsafe {

    private static final Unsafe theUnsafe;

    static {
        theUnsafe = new Unsafe();
        省去其他代码......
    }

    private Unsafe() {
    }

    @CallerSensitive
    public static Unsafe getUnsafe() {
        Class var0 = Reflection.getCallerClass();
        if (var0.getClassLoader() != null) {
            throw new SecurityException("Unsafe");
        } else {
            return theUnsafe;
        }
    }

    ...
}
```
## 获取Unsafe实例
我们从上面的代码可以看到有2种方式获取Unsafe实例,以下分别介绍下这两种方式.
### 调用私有构造方法
```java
public static void main(String[] args) throws Exception {
        Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
        Constructor<?> declaredConstructor = unsafeClass.getDeclaredConstructor();
        declaredConstructor.setAccessible(true);
        Unsafe unsafe = (Unsafe) declaredConstructor.newInstance();
        System.out.println(unsafe);
    }
```

### 获取私有属性theUnsafe
```java
public static void main(String[] args) throws Exception {  
 Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");  
 Field theUnsafe = unsafeClass.getDeclaredField("theUnsafe");  
 theUnsafe.setAccessible(true);  
 Unsafe unsafe = (Unsafe) theUnsafe.get(null);  
 System.out.println(unsafe);  
}
```

## allocateInstance无视构造方法创建类实例
假设我们有一个叫`UnSafeTest`的类，因为某种原因我们不能直接通过反射的方式去创建`UnSafeTest`类实例，那么这个时候使用`Unsafe`的`allocateInstance`方法就可以绕过这个限制了。
```java
package top.longlone;  
  
import sun.misc.Unsafe;  
  
import java.lang.reflect.Constructor;  
import java.lang.reflect.Field;  
  
class UnsafeTest {  
 private UnsafeTest() {  
 System.out.println("success");  
 }}  
  
public class UnsafeStudy {  
 public static void main(String[] args) throws Exception {  
 Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");  
 Field theUnsafe = unsafeClass.getDeclaredField("theUnsafe");  
 theUnsafe.setAccessible(true);  
 Unsafe unsafe = (Unsafe) theUnsafe.get(null);  
 UnsafeTest unsafeTest = (UnsafeTest) unsafe.allocateInstance(UnsafeTest.class);  
 System.out.println(unsafeTest);  
 }}
```
Google的`GSON`库在JSON反序列化的时候就使用这个方式来创建类实例，在渗透测试中也会经常遇到这样的限制，比如RASP限制了`java.io.FileInputStream`类的构造方法导致我们无法读文件或者限制了`UNIXProcess/ProcessImpl`类的构造方法导致我们无法执行本地命令等。

## defineClass直接调用JVM创建类对象
```java
package top.longlone;  
  
import sun.misc.Unsafe;  
  
import java.lang.reflect.Constructor;  
import java.lang.reflect.Field;  
import java.lang.reflect.Method;  
import java.security.CodeSource;  
import java.security.ProtectionDomain;  
import java.security.cert.Certificate;  
import java.util.Base64;  
  
  
public class UnsafeStudy {  
 private static final String TEST_CLASS_NAME = "top.longlone.Hello";  
 private static final byte[] TEST_CLASS_BYTES = Base64.getDecoder().decode("yv66vgAAADQAJAoABwARCgASABMJAAYAFAkAFQAWCgAXABgHABkHABoBAAZudW1iZXIBABNMamF2YS9sYW5nL0ludGVnZXI7AQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAB2Rpc3BsYXkBAApTb3VyY2VGaWxlAQAKSGVsbG8uamF2YQwACgALBwAbDAAcAB0MAAgACQcAHgwAHwAgBwAhDAAiACMBABJ0b3AvbG9uZ2xvbmUvSGVsbG8BABBqYXZhL2xhbmcvT2JqZWN0AQARamF2YS9sYW5nL0ludGVnZXIBAAd2YWx1ZU9mAQAWKEkpTGphdmEvbGFuZy9JbnRlZ2VyOwEAEGphdmEvbGFuZy9TeXN0ZW0BAANvdXQBABVMamF2YS9pby9QcmludFN0cmVhbTsBABNqYXZhL2lvL1ByaW50U3RyZWFtAQAHcHJpbnRsbgEAFShMamF2YS9sYW5nL09iamVjdDspVgAhAAYABwAAAAEAAgAIAAkAAAACAAEACgALAAEADAAAACkAAgABAAAADSq3AAEqBLgAArUAA7EAAAABAA0AAAAKAAIAAAADAAQABAABAA4ACwABAAwAAAAnAAIAAQAAAAuyAAQqtAADtgAFsQAAAAEADQAAAAoAAgAAAAYACgAHAAEADwAAAAIAEA==");  
 public static void main(String[] args) throws Exception {  
 Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");  
 Field theUnsafe = unsafeClass.getDeclaredField("theUnsafe");  
 theUnsafe.setAccessible(true);  
 Unsafe unsafe = (Unsafe) theUnsafe.get(null);  
  
 // 获取系统的类加载器  
 ClassLoader classLoader = ClassLoader.getSystemClassLoader();  
  
 // 创建默认的保护域  
 ProtectionDomain domain = new ProtectionDomain(new CodeSource(null, (Certificate[]) null), null, classLoader, null);  
  
 // 直接调用JVM创建类对象  
 Class<?> helloClass = unsafe.defineClass(TEST_CLASS_NAME, TEST_CLASS_BYTES, 0, TEST_CLASS_BYTES.length, classLoader, domain);  
  
 Constructor<?> declaredConstructor = helloClass.getDeclaredConstructor();  
  
 declaredConstructor.setAccessible(true);  
  
 Object o = declaredConstructor.newInstance();  
  
 Method displayMethod = helloClass.getDeclaredMethod("display");  
  
 Object result = displayMethod.invoke(o);  
     }  
}
```