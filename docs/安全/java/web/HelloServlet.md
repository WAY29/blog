---
created: '21/08/03'
title: HelloServlet
tags:
  - java
---
# HelloServlet

## Servlet 简介
Servlet（Server Applet），全称Java Servlet。是用Java编写的服务器端程序。其主要功能在于生成动态Web内容。狭义的Servlet是指Java语言实现的一个接口，广义的Servlet是指任何实现了这个Servlet接口的类，一般情况下，人们将Servlet理解为后者。
想要开发一个Java Web程序，只需要完成2个步骤:
1. 编写一个类，实现Servlet接口
2. 把开发好的Java类部署到web服务器中

## 项目构建
1. 构建一个普通的maven项目，删掉src目录，这个空工程就是maven主工程
2. 在主工程的pom.xml中添加以下依赖
```xml
<dependencies>
        <dependency>
            <groupId>javax.servlet</groupId>
            <artifactId>javax.servlet-api</artifactId>
            <version>4.0.1</version>
        </dependency>
        <dependency>
            <groupId>javax.servlet.jsp</groupId>
            <artifactId>javax.servlet.jsp-api</artifactId>
            <version>2.3.3</version>
        </dependency>
    </dependencies>
```
4. 在主工程下面新建maven模块，创建一个maven web子工程
5. 在子工程的pom.xml中添加parent标签，以继承主工程的依赖
6. 修改子工程下src/main/webapp/WEB-INF/web.xml为最新
```xml
<?xml version="1.0" encoding="UTF-8"?>
 <web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
                 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                 xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                  http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
                 version="4.0">
    
 </web-app >
```
6. 在src/main/新建java和resources文件夹并标记(mark)
7. 在右上角中添加Tomcat配置，具体步骤参考之前的[Tomcat](Tomcat.md)

## 简单示例
1. 编写一个继承HttpServlet的类
2. 重写`do***`方法，如`doGet`，`doPost`
```java
package top.longlone.servlet;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class HelloServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        PrintWriter writer = resp.getWriter();
        writer.print("Hello,Servlet");
    }
}
```
3. 编写Servlet映射(src/main/webapp/WEB-INF/web.xml)
url-pattern可以使用\*通配符，但是只能有两种格式:
- \*.扩展名 
- /开头，\*结尾。

url-pattern还存在优先级，越精准的pattern优先级越高，越模糊的pattern优先级越低，所以我们可以使用/\*这个pattern来自定义404界面。

一个servlet可以指定一个或多个映射路径。
```xml
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                  http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">
    <!-- 注册servlet -->
    <servlet>
        <servlet-name>hello</servlet-name>
        <servlet-class>top.longlone.servlet.HelloServlet</servlet-class>
    </servlet>
     <!-- 设置servlet映射 -->
    <servlet-mapping>
        <servlet-name>hello</servlet-name>
     <!-- 
      这里url-pattern可以使用*通配符，但是只能有两种格式
      一是*.扩展名
      二是以/开头，*结尾
      -->
        <url-pattern>/hello</url-pattern>
    </servlet-mapping>
</web-app >
```
4. 启动tomcat服务器，访问/hello

## Servlet与Tomcat工作原理
1.  Web Client 向Servlet容器（Tomcat）发出Http请求
2.   Servlet容器接收Web Client的请求
3.   Servlet容器创建一个HttpRequest对象，将Web Client请求的信息封装到这个对象中。
4.   Servlet容器创建一个HttpResponse对象
5.  Servlet容器调用HttpServlet对象的service方法，把HttpRequest对象与HttpResponse对象作为参数传给 HttpServlet 对象。
6.  HttpServlet调用HttpRequest对象的有关方法，获取Http请求信息。
7.  HttpServlet调用HttpResponse对象的有关方法，生成响应数据。
8.  Servlet容器把HttpServlet的响应结果传给Web Client。

## 总结
这节主要介绍了Servlet，以及如何在IDEA中使用Servlet的简单用例，最后介绍了Servlet与Tomcat的工作原理。