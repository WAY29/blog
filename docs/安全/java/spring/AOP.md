---
created: '21/07/30'
title: AOP
tags:
  - java
  - spring
---
# AOP
AOP是Aspect Oriented Programming，即面向切面编程。AOP是一种新的编程方式，它和OOP不同，OOP把系统看作多个对象的交互，AOP把系统分解为不同的关注点，或者称之为切面（Aspect）。
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20210730143011.png)

## SpringAOP
在SpringAOP中，通过Advice定义横切逻辑，Spring支持5种类型的Advice:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20210730143136.png)
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20210730152452.png)

### 导入依赖
要在Spring中使用AOP织入，需要导入以下依赖
```xml
<dependency>
  <groupId>org.aspectj</groupId>
  <artifactId>aspectjweaver</artifactId>
  <version>1.9.8.M1</version>
</dependency>
```
### 实现方式一:原生Spirng API接口
```java
package top.longlone.service;

public interface UserService {
    public void add();
    public void delete();
    public void update();
    public void query();
}
```
```java
package top.longlone.service;

import org.springframework.stereotype.Service;

public class UserServiceImpl implements UserService {
    @Override
    public void add() {
        System.out.println("增加一个用户");
    }

    @Override
    public void delete() {
        System.out.println("删除一个用户");

    }

    @Override
    public void update() {
        System.out.println("更新一个用户");

    }

    @Override
    public void query() {
        System.out.println("查询一个用户");

    }
}
```
```java
package top.longlone.log;

import org.springframework.aop.AfterReturningAdvice;
import org.springframework.aop.MethodBeforeAdvice;

import java.lang.reflect.Method;

public class Log implements MethodBeforeAdvice, AfterReturningAdvice {
    @Override
    public void before(Method method, Object[] args, Object target) throws Throwable {
        System.out.println(target.getClass().getName() + "的" + method.getName() + "执行之前");
    }

    @Override
    public void afterReturning(Object returnValue, Method method, Object[] args, Object target) throws Throwable {
        System.out.println(target.getClass().getName() + "的" + method.getName() + "执行完毕");
    }
}
```
```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:aop="http://www.springframework.org/schema/aop"
       xsi:schemaLocation="
       http://www.springframework.org/schema/beans
       http://www.springframework.org/schema/beans/spring-beans.xsd
       http://www.springframework.org/schema/aop
       http://www.springframework.org/schema/aop/spring-aop.xsd">
    <bean id="userService" class="top.longlone.service.UserServiceImpl"/>
    <bean id="log" class="top.longlone.log.Log"/>

    <!-- 方式一:使用原生Spring API接口-->
    <!-- 导入aop，需要导入aop的约束  -->
    <aop:config>
        <!-- 增加切入点，expression:execution(修饰符 返回值 类名 方法名 参数) -->
        <aop:pointcut id="pointcut" expression="execution(public * top.longlone.service.UserServiceImpl.*(..))"/>
        <aop:advisor advice-ref="log" pointcut-ref="pointcut"/>
    </aop:config>
</beans>
```
### 实现方式二:自定义类
这种方式有一个缺点是无法拿到切入点和Target的信息，优点是更好理解。
```java
package top.longlone.log;

public class CustomLog {
    public void before() {
        System.out.println("====执行前====");
    }
    public void after() {
        System.out.println("====执行后====");
    }
}
```
```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:aop="http://www.springframework.org/schema/aop"
       xsi:schemaLocation="
       http://www.springframework.org/schema/beans
       http://www.springframework.org/schema/beans/spring-beans.xsd
       http://www.springframework.org/schema/aop
       http://www.springframework.org/schema/aop/spring-aop.xsd">
    <bean id="userService" class="top.longlone.service.UserServiceImpl"/>
    <bean id="log" class="top.longlone.log.Log"/>

    <bean id="customLog" class="top.longlone.log.CustomLog"/>
    <aop:config>
        <aop:aspect ref="customLog">
            <aop:pointcut id="pointcut" expression="execution(* top.longlone.service.UserServiceImpl.*(..))"/>
            <aop:before method="before" pointcut-ref="pointcut"/>
            <aop:after method="after" pointcut-ref="pointcut"/>
        </aop:aspect>
    </aop:config>
</beans>
```
### 实现方式三:注解
```java
package top.longlone.log;

import org.aspectj.lang.annotation.After;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Before;

@Aspect
public class AnnotationLog {
    @Before("execution(* top.longlone.service.UserServiceImpl.*(..))")
    public void before() {
        System.out.println("==执行前==");
    }

    @After("execution(* top.longlone.service.UserServiceImpl.*(..))")
    public void after() {
        System.out.println("==执行后==");
    }

    @Around("execution(* top.longlone.service.UserServiceImpl.*(..))")
    public void around(ProceedingJoinPoint jp) throws Throwable {
        System.out.println("环绕前");
        System.out.println(jp.getSignature());  // 输出签名
        System.out.println(jp.getTarget());  // 获取被通知对象并输出
        Object proceed = jp.proceed();
        System.out.println("环绕后");
    }
}
```
```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:aop="http://www.springframework.org/schema/aop"
       xsi:schemaLocation="
       http://www.springframework.org/schema/beans
       http://www.springframework.org/schema/beans/spring-beans.xsd
       http://www.springframework.org/schema/aop
       http://www.springframework.org/schema/aop/spring-aop.xsd">
    <bean id="userService" class="top.longlone.service.UserServiceImpl"/>
    <bean id="log" class="top.longlone.log.Log"/>

     <bean id="annotaionLog" class="top.longlone.log.AnnotationLog"/>
    <!-- 开启注解支持 JDK proxy-target-class="false" cglib proxy-target-class="true" -->
    <aop:aspectj-autoproxy/>
</beans>
```
## 总结
Spring中的AOP其实是通过动态代理实现的。AOP有几种使用方式，分别是:
1. 使用原生Spring API接口
2. 使用自定义类
3. 使用注解