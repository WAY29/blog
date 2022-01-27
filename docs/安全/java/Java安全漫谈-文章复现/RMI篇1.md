---
created: '21/09/08'
title: RMI篇1
tags:
  - java
  - java安全
---
# RMI篇1
RMI全称是Remote Method Invocation，远程⽅方法调用。从这个名字就可以看出，他的目标和RPC其实是类似的，是让某个Java虚拟机上的对象调用另一个Java虚拟机中对象上的方法，只不过RMI是Java独有的一种机制。

一个简单的示例如下

远程调用的方法需要
- 一个继承了java.rmi.Remote的接口
- 一个实现了该接口并继承了UnicastRemoteObject的类
```java
package top.longlone;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface IRemoteHelloWorld extends Remote {
    public String hello() throws RemoteException;
}
```
```java
package top.longlone;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

public class RemoteHelloWorld extends UnicastRemoteObject implements IRemoteHelloWorld {
    protected RemoteHelloWorld() throws RemoteException {
        super();
    }

    @Override
    public String hello() throws RemoteException {
        System.out.println("call");
        return "hello world";
    }
}
```

RMIServer需要创建Registry，并将上面的类实例化后绑定到一个地址。
```java
package top.longlone;

import java.rmi.Naming;
import java.rmi.registry.LocateRegistry;

public class RMIServer {
    private void start() throws Exception {
        RemoteHelloWorld helloWorld = new RemoteHelloWorld();
        LocateRegistry.createRegistry(1099);
        Naming.bind("rmi://192.168.135.142:1099/Hello", helloWorld);
    }

    public static void main(String[] args) throws Exception {
        new RMIServer().start();
    }
}
```

RMIClient使用`Naming.lookup`在Registry中找到HelloWorld的对象，这里也可以看出来接口的重要性: 虽然我们是在远程调用方法，但是我们还是需要实例知道有哪些方法，因此客户端也需要这个接口。
```java
package top.longlone;

import java.rmi.Naming;

public class RMIClient {
    public static void main(String[] args) throws Exception{
        IRemoteHelloWorld helloWorld = (IRemoteHelloWorld) Naming.lookup("rmi://192.168.135.142:1099/Hello");
        String ret = helloWorld.hello();
        System.out.println(ret);
    }
}
```

结合文章所说的，整个RMI的流程如下:

> 首先客户端连接Registry，并在其中寻找Name是Hello的对象，这个对应数据流中的Call消息；然后Registry返回一个序列化的数据，这个就是找到的Name=Hello的对象，这个对应数据流中的ReturnData消息；客户端反序列化该对象，发现该对象是一个远程对象，地址在192.168.135.142:33769，于是再与这个地址建立TCP连接。在这个新的连接中，才执行真正远程方法调用，也就是hello()。

![](https://gitee.com/guuest/images/raw/master/img/20210908163138.png)

> RMI Registry就像一个网关，他自己是不会执行远程方法的，但RMI Server可以在上面注册一个Name到对象的绑定关系；RMI Client通过Name向RMI Registry查询，得到这个绑定关系，然后再连接RMI Server；最后，远程方法实际上在RMI Server上调用。