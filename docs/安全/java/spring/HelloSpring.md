---
created: '21/07/17'
title: HelloSpring
tags:
  - java
  - spring
---
# HelloSpring
编写一个简单的类去体现Spring的思想
```java
package top.longlone;

public class HelloSpring {
    private String str;

    public String getStr() {
        return str;
    }

    public void setStr(String str) {
        this.str = str;
    }

    @Override
    public String toString() {
        return "HelloSpring{" +
                "str='" + str + '\'' +
                '}';
    }
}
```
```xml
<!-- beans.xml -->
<?xml version="1.0" encoding="UTF-8"?>  
<beans xmlns="http://www.springframework.org/schema/beans"  
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  
 xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">  
 <!--
 通过Spring管理的类叫Bean
一个id对应一个Bean
Spring通过反射创建Bean，我们通过id获取Bean   
property用于给Bean的属性设置值，value指定一个值，ref指向一个Bean
 -->
 <bean id="hello" class="top.longlone.HelloSpring">  
 <property name="str" value="Spring"/>  
 </bean>  
</beans>
```
```java
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import top.longlone.HelloSpring;

public class MyTest {
    public static void main(String[] args) {
        ApplicationContext context = new ClassPathXmlApplicationContext("beans.xml");
        HelloSpring hello = (HelloSpring) context.getBean("hello");
        System.out.println(hello.toString());

    }
}
````
可以看到Spring帮助我们创建，管理，分配对象，我们不再需要自己去new一个对象了，Spring中的对象默认是单例模式，在配置文件加载时对象已经注册了。

## 使用构造函数
前面xml中设置属性其实是通过调用setter方法去设置的，我们也可以使用构造函数去设置属性，例如：
```java
public class HelloSpring {
    public HelloSpring() {
    }

    public HelloSpring(String str) {
        this.str = str;
    }
    // ...
}
```
- 对应的xml如下：
```xml
...
 <bean id="hello" class="top.longlone.HelloSpring">  
     <constructor-arg index="0" value="whoami"></constructor-arg> <!-- 下标方式 -->
      <constructor-arg name="str" value="whoami"></constructor-arg> <!-- 变量名方式 -->
 </bean>  
...
```

## 总结
简单了解了如何使用Spring的XML配置文件创建，管理，分配对象。
在Spring中Bean是其管理的对象，是程序构建的基本块。Bean其实是符合一定规范编写的Java类，这些规范分别是
1. 所有属性为private  
2. 提供默认构造方法  
3. 提供getter和setter  
4. 实现serializable接口
