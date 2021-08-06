---
created: '21/07/27'
title: Bean的装配
tags:
  - java
  - spring
---
# Bean的装配
在Spring中有三种装配方式
- xml配置
- java代码配置
- 隐式自动配置
## Bean的自动装配
Spring会在上下文中自动寻找，并自动给Bean装配属性

### 通过xml实现自动装配
主要是通过beans中的default-autowire属性或者bean中的autowire属性来实现自动装配

#### byName自动装配
当设置属性值为byName时，Bean会在上下文中寻找与属性名相同的Beanid并自动注入依赖，必须保证Bean名字唯一。

#### byType自动装配
当设置属性值为byType时，Bean会在上下文中寻找与属性类型相同的Bean并自动注入依赖，必须保证同意类型的Bean唯一。

#### constructor自动装配
和byType自动装配类似，也是根据类型去自动装配，但是是调用构造函数实现依赖注入。


### 注解实现自动装配
依赖:
1. jdk>=1.5
2. spring>=2.5

使用前需要导入扩展和配置注解支持
```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:context="http://www.springframework.org/schema/context"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd http://www.springframework.org/schema/context http://www.springframework.org/schema/beans/spring-context.xsd">

    <context:annotation-config/>

</beans>
```
使用方法
依然在xml中编写bean，但是不需要再注入属性
```xml
    <bean id="people" class="top.longlone.People"/>
    <bean id="dog" class="top.longlone.Dog"/>
```
然后在代码属性上使用@Autowired注解，实现的效果是先类似于byType自动装配，若有多个相同类型，则类似于byName自动装配
```java
package top.longlone;

import org.springframework.beans.factory.annotation.Autowired;

public class People {
    @Autowired
    private Dog dog;
    // 省略getter setter toStirng方法
```
 @Autowired可以设置属性required，默认为true，若设置为false，则声明这个依赖是非必须的，可以为空
 ```java
package top.longlone;  
  
import org.springframework.beans.factory.annotation.Autowired;  
  
public class People {  
 @Autowired(required = false)  
 private Dog dog;
}
```
如果有多个相同类型的bean，则可以使用@Qualifier注解来指定使用哪个名字的bean
```java
package top.longlone;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;

public class People {
    @Autowired
    @Qualifier(value = "dog")
    private Dog dog;
}
```
在java<11中jva原生自带了一个@Resource注解，它的作用和@Autowired类似，实现的效果是先类似于byName自动装配，若无法找到对应的id，则类似byType自动装配，同时它可以执行name属性来指向具体的一个bean
```java
package top.longlone;


import javax.annotation.Resource;

public class People {
    @Resource(name = "dog22")
    private Dog dog;
}
```
java11及之后需要通过添加依赖的方式才能使用@Resource注解
```xml
<dependency>
   <groupId>javax.annotation</groupId>
   <artifactId>javax.annotation-api</artifactId>
   <version>1.3.1</version>
</dependency>
```
## 总结
Bean实现自动装配有两种方式，分别是通过xml和通过注解。
Bean通过xml实现自动装配有三种方式，分别是byName，byType和constructor。
Bean通过注解实现自动装配有三个常见注解，分别@Autowired，@Qualfilter，@Resource