---
created: '21/07/29'
title: Spring中使用java代码配置
tags:
  - java
  - spring
---
# Spring中使用java代码配置
在Spring中也可以使用java代码进行spring的配置，这种方式相比xml更加的灵活
```java
package top.longlone;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;

@Configuration
public class AppConfig {

    @Bean
    @Scope("singleton")
    public User user() {
        return new User();
    }
}
```
这相当于xml配置中的
```xml
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:context="http://www.springframework.org/schema/context"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd http://www.springframework.org/schema/context http://www.springframework.org/schema/context/spring-context.xsd">

    <bean id="user" class="top.longlone.User"/>
</beans>
```
这里也有一些相关常用的注解
## 相关注解
### @Configuration 
这是一个配置类的注解，用于配置其他bean
### @Import
相当于xml中的`<import>`标签，用于包含其他配置类
### CompoentScan
在java类代码中每次创建一个bean都需要在配置类中写一个方法，这样很不方便，所以可以使用包扫描的方式，相当于xml中的`<context:component-scan base-package=""/>`
```java
package top.longlone;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;

@Configuration
@ComponentScan({"top.longlone"})
public class AppConfig {

    @Bean
    @Scope("singleton")
    public User user() {
        return new User();
    }
}
```

## 总结
这种配置类经常见于SpringBoot中。是spring4之后推荐使用的配置方式。它和xml配置文件任选其一作为spring的配置方式即可。