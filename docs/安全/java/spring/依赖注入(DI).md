---
created: '21/07/22'
title: 依赖注入(DI)
tags:
  - java
  - spring
---
# 依赖注入(DI)
## 构造器注入
参考[HelloSpring](HelloSpring.md)

## Set方式注入
- 依赖注入
    - 依赖: bean对象的创建依赖于容器
    - 注入: bean对象中的所有属性由容器来注入
### 注入复杂的值
```java
public class Address {
    private String address;
     // 省略getter setter toStirng方法
}
```
```java
public class Student {
    private Address address;
    private String name;
    private String[] books;
    private List<String> hobbies;
    private Map<String, String> card;
    private Set<String> games;
    private String friend;
    private Properties info;
     // 省略getter setter toStirng方法
}
```
```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="address" class="top.longlone.Address">
        <property name="address" value="https://longlone.top"/>
    </bean>
    <bean id="student" class="top.longlone.Student">
        <!--普通注入-->
        <property name="name" value="longlone"/>
        <!--bean注入-->
        <property name="address" ref="address"/>
        <!--数组注入-->
        <property name="books">
            <array>
                <value>语文</value>
                <value>数学</value>
                <value>英语</value>
            </array>
        </property>
        <!--List注入-->
        <property name="hobbies">
            <list>
                <value>听歌</value>
                <value>敲代码</value>
                <value>干饭</value>
            </list>
        </property>
        <!--Map注入-->
        <property name="card">
            <map>
                <entry key="Boy" value="bbb"/>
                <entry key="Girl" value="ggg"/>
            </map>
        </property>
        <!--Set注入-->
        <property name="games">
            <set>
                <value>LOL</value>
                <value>CF</value>
                <value>DOTA</value>
            </set>
        </property>
        <!--null注入-->
        <property name="friend">
            <null/>
        </property>
        <!--Properties注入-->
        <property name="info">
            <props>
                <prop key="idcard">2020111111</prop>
                <prop key="sex">1</prop>
                <prop key="blog">https://longlone.top/</prop>
            </props>
        </property>
    </bean>
</beans>
```

## 扩展注入
假设我们有一个Bean如下
```java
package top.longlone;

public class User {
    private String name;
    private int age;
    // 省略getter setter toStirng Constructor方法
}
```
### p命名空间注入
p对应的是property，其实是Set注入的一个简化模式
需要在beans里加入一个扩展`xmlns:p="http://www.springframework.org/schema/p"`，通过这个扩展可以直接在bean里注入对象的属性，而不需要property标签
```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:p="http://www.springframework.org/schema/p"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">

    <bean id="user" class="top.longlone.User" p:age="18" p:name="whoami"/>
</beans>
```
### c命名空间注入
c对应的是constructor，其实是构造器注入的一个简化模式
需要在beans里加入一个扩展`xmlns:c="http://www.springframework.org/schema/c"`，通过这个扩展可以直接在bean里调用构造器直接注入类的属性，而不需要constructor-arg标签
```xml
<?xml version="1.0" encoding="UTF-8"?>  
<beans xmlns="http://www.springframework.org/schema/beans"  
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  
 xmlns:c="http://www.springframework.org/schema/c"  
 xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">  
  
 <bean id="user" class="top.longlone.User" c:age="18" c:name="whoami"/>  
</beans>
```

## 总结
依赖注入(DI)是一种实现控制反转的方式，在对象创建时，通过使用者将所需依赖注入到对象里。
Spring中的依赖注入方式有三种，分别为构造器注入，Set方式注入和扩展注入。