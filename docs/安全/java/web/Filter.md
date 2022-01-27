---
created: '21/08/23'
title: Filter
tags:
  - java
---
# Filter
可以理解为中间件，开发者可以对web服务器管理的所有web资源：例如JSP，Servlet，静态图片文件或静态HTML文件进行拦截，从而实现一些特殊功能。
![](https://gitee.com/guuest/images/raw/master/img/20210823141157.png)

## 示例代码
一个简单的通过设置请求头来解决中文显示乱码的过滤器

实现Filter接口，重写`init`，`doFilter`，`destroy`三个方法，这里注意`chain.doFilter`方法，它将请求转发给过滤器链下一个filter , 如果没有filter那就是你请求的资源，如果没有调用该方法，请求就会在这个过滤器中结束
```java
package top.longlone.filter;

import javax.servlet.*;
import java.io.IOException;

public class CharacterEncodingFilter implements Filter {

    public void init(FilterConfig filterConfig) throws ServletException {
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        response.setContentType("text/html; charset=utf-8");

        chain.doFilter(request, response);
    }

    public void destroy() {
    }
}
```
一个用于简单测试的Servlet
```java
package top.longlone.servlet;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class IndexServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.getWriter().write("乱码测试");
    }
}
```

修改web.iml，同样需要在此对过滤器进行注册和映射，使用filter和filter-mapping两个标签
```xml
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">
    
    <servlet>
        <servlet-name>index</servlet-name>
        <servlet-class>top.longlone.servlet.IndexServlet</servlet-class>
    </servlet>
    
    <servlet-mapping>
        <servlet-name>index</servlet-name>
        <url-pattern>/index</url-pattern>
    </servlet-mapping>

    <filter>
        <filter-name>characterEncoding</filter-name>
        <filter-class>top.longlone.filter.CharacterEncodingFilter</filter-class>
    </filter>

    <filter-mapping>
        <filter-name>characterEncoding</filter-name>
        <url-pattern>/index</url-pattern>
    </filter-mapping>
</web-app>
```