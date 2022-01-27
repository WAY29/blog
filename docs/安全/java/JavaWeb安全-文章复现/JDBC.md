---
created: '21/11/16'
title: JDBC
tags:
  - java
  - java安全
---
# JDBC
JDBC(Java Database Connectivity)是Java提供对数据库进行连接、操作的标准API。Java自身并不会去实现对数据库的连接、查询、更新等操作而是通过抽象出数据库操作的API接口(JDBC)，不同的数据库提供商必须实现JDBC定义的接口从而也就实现了对数据库的一系列操作

## JDBC Connection
`java`通过`java.sql.DriverManager`来管理所有数据库的驱动注册，所以如果想要建立数据库连接需要先在`java.sql.DriverManager`中注册对应的驱动类，然后调用`getConnection`方法才能连接上数据库

 `JDBC`定义了一个叫`java.sql.Driver`的接口类负责实现对数据库的连接，所有的数据库驱动包都必须实现这个接口才能够完成数据库的连接操作。`java.sql.DriverManager.getConnection(xx)`其实就是间接的调用了`java.sql.Driver`类的`connect`方法实现数据库连接的。数据库连接成功后会返回一个叫做`java.sql.Connection`的数据库连接对象，一切对数据库的查询操作都将依赖于这个`Connection`对象

 JDBC连接数据库的一般步骤
  1. 注册驱动: `Class.forName("数据库驱动的类名")`
  2. 获取连接: `DriverManager.getConnection(xxx
  
  ```java
// JDBC连接数据库示例代码
String CLASS_NAME = "com.mysql.jdbc.Driver";
String URL = "jdbc:mysql://localhost:3306/mysql"
String USERNAME = "root";
String PASSWORD = "root";

Class.forName(CLASS_NAME);// 注册JDBC驱动类
Connection connection = DriverManager.getConnection(URL, USERNAME, PASSWORD);
```

## 数据库配置信息
数据库配置信息寻找方法

传统的Web应用的配置信息存放路径
  - `WEB-INF`目录下的`*.properites .yml *.xml`
  - Spring boot项目:`src/main/resources/`

常见的存储数据库配置信息的文件路径
  - `WEB-INF/applicationContext.xml`
  - `WEB-INF/hibernate.cfg.xml`
  - `WEB-INF/jdbc/jdbc.properties`
- 使用系统命令寻找,如寻找mysql: `find 路径 -type f |xargs grep "com.mysql.jdbc.Driver"`

- 需要`Class.forName`的原因: 在Driver的static中注册了驱动包
  ![](https://static.zhishibox.net/20210118/108448336_image-20191208225820692.png)

  `Class.forName("com.mysql.jdbc.Driver")`实际上会触发类加载，`com.mysql.jdbc.Driver`类将会被初始化，所以`static`静态语句块中的代码也将会被执行

反射类而不想触发类静态代码块的途径
  - `Class.forName("xxxx", false, loader)`
  - `ClassLoader.load("xxxx")`

`Class.forName`可以省去的原因
  - 实际上这里又利用了`Java`的一大特性:`Java SPI(Service Provider Interface)`，因为`DriverManager`在初始化的时候会调用`java.util.ServiceLoader`类提供的SPI机制，Java会自动扫描jar包中的`META-INF/services`目录下的文件，并且还会自动的`Class.forName`(文件中定义的类)

## 总结
课后思考
  1. `SPI机制`是否有安全性问题？
      1. [Java SPI安全](http://www.liuhaihua.cn/archives/642853.html)
      2. [Java-SPI机制与SnakeYaml反序列化漏洞](https://ce-automne.github.io/2020/02/08/Java-SPI机制与SnakeYaml反序列化漏洞/)
  2. `Java反射`有哪些安全问题？

java反射机制
  1. `Java类加载机制`是什么？
  2. 数据库连接时密码安全问题？
  3. 使用JDBC如何写一个通用的`数据库密码爆破`模块？