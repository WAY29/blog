---
created: '21/07/28'
title: Spring中使用注解配置
tags:
  - java
  - spring
---
# Spring中使用注解配置
## 前提
```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:context="http://www.springframework.org/schema/context"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd http://www.springframework.org/schema/context http://www.springframework.org/schema/beans/spring-context.xsd">

    <context:annotation-config/>
    <context:component-scan base-package="top.longlone"/>
</beans>
```
## spring中常用的注解

### @Resource
参考[Bean的装配](Bean的装配.md)
### @Component
用于注解类，相当于直接往spring中注册这个类为Bean，要使用这个注解必须在xml中配置`context:compoent-scan`
### Repository
同Component，用于DAO层
### Service
同Component，用于Service层
### Controller
同Component，用于Controller层
### Scope
同xml中bean下的scope属性，用于设置bean的作用域(单例模式，原型模式等)，例如`@Scope("singleton")`
### @Value
注解属性或者set方法，用于自动设置实例属性值，相当于`<property name="..." value="..."/>`，例如`@Value("whoami")`
### @Autowired
用于自动装配属性，相当于`<property name="..." ref="..."/>`

参考[Bean的装配](Bean的装配.md)
### @Qualfilter
参考[Bean的装配](Bean的装配.md)

## 总结
xml适用性更高，注解更简洁，但是复杂的配置还是应该使用xml进行配置。在实际开发中，可以考虑使用xml进行bean的管理，然后使用注解完成属性注入。