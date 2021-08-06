---
created: '21/07/22'
title: Spring使用XML配置
tags:
  - java
  - spring
---
# Spring使用XML配置
## alias
用于给存在的bean起别名，例如给user起别名为userNew
```xml
<alias name="user" alias="userNew"/>
```

## bean
- id: bean的唯一标识符
- class: bean对象对应的完整类名（包名+类名）
- name: 别名，可以使用空格或逗号取多个别名
```xml
<bean id="hello" class="top.longlone.HelloSpring" name="h1,h2">  
 <property name="str" value="Spring"/>  
</bean>
```

## import
一般用于团队开发使用，可以导入其他配置文件
```xml
<import resource="beans.xml"/>
```

## 总结
了解了Spring XML配置文件中的配置选项，分别是alias，bean，import。