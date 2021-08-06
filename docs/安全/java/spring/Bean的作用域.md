---
created: '21/07/24'
title: Bean的作用域
tags:
  - java
  - spring
---
# Bean的作用域
## singleton 单例模式
Bean的默认作用域，默认情况下Bean都是单例模式，即无论获取多少次Bean，返回的都是相同的实例，也可以显式地声明这个作用域:
```xml
<bean id="user" class="top.longlone.User" c:age="18" c:name="whoami" scope="singleton"/>
```
## prototype 原型模式
与单例模式对应，每次获取Bean都会创建一个新的实例
```xml
<bean id="user" class="top.longlone.User" c:age="18" c:name="whoami" scope="prototype"/>
```
测试如下:
```java
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import top.longlone.Student;
import top.longlone.User;

public class MyTest {
    public static void main(String[] args) {
        ApplicationContext context = new ClassPathXmlApplicationContext("ApplicationContext.xml");
        User user = context.getBean("user", User.class);
        User user2 = context.getBean("user", User.class);
        System.out.println(user == user2); // false
    }
}
```
## 其他作用域
剩下的作用域都在Web开发里才能用到
### request
### session
### application
### websocket

## 总结
主要了解了Bean的作用域，需要先了解的有单例模式(singleton)和原型模式(prototype)，两者的主要区别是获取Bean时使用相同的实例对象还是创建新的实例对象。