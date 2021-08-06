---
created: '21/07/15'
title: 控制反转(IOC)
tags:
  - java
  - spring
---
# 控制反转(IOC)
**控制反转(IOC)**是一种设计思想，用于降低代码之间的耦合度。

**依赖注入(DI)**是一种用于实现控制反转的设计模式。

通过依赖注入实现控制反转，就是说对象在被创建的时候，由业务层将其所依赖的对象的传递给它。也可以说，依赖被注入到对象中。

通常我们使用依赖注入的方式实现控制反转，但是控制反转还有其他的实现方式，如[ServiceLocator](https://martinfowler.com/articles/injection.html)。

## 例子
### IOC前
```java
package top.longlone;  
  
public interface Fruit {  
 public String type();  
}
```
```java
package top.longlone;

public class Apple implements Fruit{

    @Override
    public String type() {
        return "Apple";
    }
}
````
```java
package top.longlone;  
  
public class Banana implements Fruit {  
  
 @Override  
 public String type() {  
 return "Banana";  
 }}
```
```java
package top.longlone;

public class User {
    private Fruit favouriteFruit = new Apple(); // 这里是写死了
    public void say() {
        System.out.println("My favourite fruit is " + favouriteFruit.type());
    }
}
```
```java
package top.longlone;  
  
import org.junit.Test;  
  
import static org.junit.Assert.*;  
  
public class UserTest {  
 @Test  
 public void testUser() throws Exception {  
 User user = new User();  
 user.say();  
 // output: My favourite fruit is Apple
 }  
}
```
从代码里可以看到User的favouriteFruit是写死了的属性，业务层难以修改

### IOC后
 ```java
package top.longlone;

public class User {
    private Fruit favouriteFruit;

    public User(Fruit favouriteFruit) {
        this.favouriteFruit = favouriteFruit;
    }

    public User() {
    }

    public void setFavouriteFruit(Fruit favouriteFruit) {
        this.favouriteFruit = favouriteFruit;
    }

    public Fruit getFavouriteFruit() {
        return favouriteFruit;
    }

    public void say() {
        System.out.println("My favourite fruit is " + favouriteFruit.type());
    }
}

 ```
 ```java
package top.longlone;

import org.junit.Test;

import static org.junit.Assert.*;

public class UserTest {
    @Test
    public void testUser() throws Exception {
        User user = new User(new Apple());
        // user.setFavouriteFruit(new Banana()); 或者使用这种方式
        user.say();

    }
}
```
可以看到修改后，我们通过依赖注入的方式为User类添加依赖，从而使得依赖控制权从代码层转移到了业务层，实现了控制反转。
loC是Spring框架的核心内容，使用多种方式完美的实现了loC，可以使用XML配置，也可以使用注解，新版本的Spring也可以零配置实现loC。

## 总结
控制反转(IOC)是一个设计思想，是开发者将依赖对象的控制权转移到了业务层而不是开发者自己，用于解耦(降低代码的耦合度)。
