---
created: '21/08/19'
title: JavaBean
tags:
  - java
---
# JavaBean
## Bean
Bean其实是一个符合规范的实体类
- 所有属性为private
- 提供默认构造方法
- 提供getter和setter
- 实现serializable接口

### 简单示例
```java
package top.longlone.pojo;  
  
import java.io.Serializable;  
  
public class People{  
 private int id;  
 private String name;  
 private String address;  
  
 public People() {  
 }  
 public int getId() {  
 return id;  
 }  
  
 public void setId(int id) {  
 this.id = id;  
 }  
  
 public String getName() {  
 return name;  
 }  
  
 public void setName(String name) {  
 this.name = name;  
 }  
  
 public String getAddress() {  
 return address;  
 }  
  
 public void setAddress(String address) {  
 this.address = address;  
 }  
  
 @Override  
 public String toString() {  
 return "People{" +  
 "id=" + id +  
 ", name='" + name + '\'' +  
 ", address='" + address + '\'' +  
 '}';  
 }  
}
```

## 总结
简单了解了Bean究竟是一个什么东西:一个符合规范的实体类