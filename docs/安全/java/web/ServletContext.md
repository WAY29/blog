---
created: '21/08/04'
title: ServletContext
tags:
  - java
---
# ServletContext
ServletContext，Servlet的上下文对象，web容器在启动的时候,它会为每个web程序都创建一个对应的 Servletcontext对象,它代表了当前的web应用;

## ServletContext的作用

### 共享数据
```java
package top.longlone.servlet;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class HelloServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        ServletContext context = this.getServletContext();
        String username = "Longlone";
        context.setAttribute("username", username);
        PrintWriter writer = resp.getWriter();
        writer.print("Hello," + username);
    }
}
```
```java
package top.longlone.servlet;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class WelcomeServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        ServletContext context = this.getServletContext();
        String username = (String) context.getAttribute("username");
        PrintWriter writer = resp.getWriter();
        writer.print("Welcome," + username);
    }
}
```
在HelloServlet中使用ServletContext保存的数据可以在WelcomeServlet中拿到，这样Servlet之间就可以很方便地共享数据

### 配置文件
在web.xml中可以设置context-param
```xml
<context-param>
    <param-name>databaseUrl</param-name>
    <param-value>jdbc:mysql://localhost:3306/mybatis</param-value>
</context-param>
```
然后在ServletContext中可以调用getInitParameter方法拿到
```java
package top.longlone.servlet;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class GetServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        ServletContext context = this.getServletContext();
        String databaseUrl = (String) context.getInitParameter("databaseUrl");
        PrintWriter writer = resp.getWriter();
        writer.print("Database Url: " + databaseUrl);
    }
}
```
所以ServletContext也可以充当一个配置类，去获取web.xml中的配置

### 请求转发
ServletContext也可以将请求转发到另外一个请求上
```java
package top.longlone.servlet;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class ForwardServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        ServletContext context = this.getServletContext();
        RequestDispatcher requestDispatcher = context.getRequestDispatcher("/get");
        requestDispatcher.forward(req, resp);
    }
}
```
例如上面的例子，当访问ForwardServlet的时候，实际上会将请求转发到/get对应的GetServlet中，响应的内容自然也是GetServlet的响应

### 读取资源文件
在resources文件夹中写入db.properties
```properties
username=root  
password=123456
```
当tomcat启动时，resources文件夹里的文件将会被打包到项目名/WEB-INF/classes里

我们可以通过ServletContext获取这个资源流，然后使用Properties类加载这个资源文件
```java
package top.longlone.servlet;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class ResourceServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        ServletContext context = this.getServletContext();
        InputStream is = context.getResourceAsStream("/WEB-INF/classes/db.properties");

        Properties properties = new Properties();
        properties.load(is);

        String usernanme = properties.getProperty("username");
        String password = properties.getProperty("password");

        resp.getWriter().print(usernanme + ":" + password);

    }
}
```