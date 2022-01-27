---
created: '21/08/24'
title: Exercise
tags:
  - java
---
# Exercise
最后用前面学到的知识做一个小练习，做一个登录认证

所用到的知识有:
- Servlet，HttpServletRequest，HttpServletResponse
- Session
- Filter

config.properties
```properties
username=admin
password=123456
```
Index页面，登录后的页面
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
        resp.getWriter().write("欢迎你，admin");
    }
}
```
Login页面，要求登录的页面
```java
package top.longlone.servlet;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class LoginServlet extends HttpServlet {


    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        InputStream in = this.getServletContext().getResourceAsStream("/WEB-INF/classes/config.properties");
        Properties prop = new Properties();
        prop.load(in);

        String username = req.getParameter("username");
        String password = req.getParameter("password");
        String adminUsername = prop.getProperty("username");
        String adminPassword = prop.getProperty("password");

        if (username == null || password == null) {
            resp.getWriter().write("Please submit username and password parameter");
            return;
        }

        if (username.equals(adminUsername) && password.equals(adminPassword)) {
            HttpSession session = req.getSession();
            session.setAttribute("username", "admin");
            resp.sendRedirect("/index");
        } else {
            resp.getWriter().write("Login error");
        }

    }
}
```
认证过滤器
```java
package top.longlone.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

public class AuthFilter implements Filter {

    public void init(FilterConfig filterConfig) throws ServletException {
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest servletRequest = (HttpServletRequest) request;
        HttpServletResponse servletResponse = (HttpServletResponse) response;

        HttpSession session = servletRequest.getSession();
        String username = (String) session.getAttribute("username");
        if (username == null || username.equals("")) {
            servletResponse.sendRedirect("/login");
            return;
        }
        chain.doFilter(request, response);
    }

    public void destroy() {
    }
}
```
设置响应头过滤器
```java
package top.longlone.filter;

import javax.servlet.*;
import java.io.IOException;

public class CharacterEncodingFilter implements Filter {

    public void init(FilterConfig filterConfig) throws ServletException {
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        request.setCharacterEncoding("utf-8");
        response.setContentType("text/html; charset=utf-8");


        chain.doFilter(request, response);
    }

    public void destroy() {
    }
}
```
web.xml
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
    <servlet>
        <servlet-name>login</servlet-name>
        <servlet-class>top.longlone.servlet.LoginServlet</servlet-class>
    </servlet>
    
    <servlet-mapping>
        <servlet-name>index</servlet-name>
        <url-pattern>/index</url-pattern>
    </servlet-mapping>


    <servlet-mapping>
        <servlet-name>login</servlet-name>
        <url-pattern>/login</url-pattern>
    </servlet-mapping>

    <filter>
        <filter-name>characterEncoding</filter-name>
        <filter-class>top.longlone.filter.CharacterEncodingFilter</filter-class>
    </filter>


    <filter>
        <filter-name>auth</filter-name>
        <filter-class>top.longlone.filter.AuthFilter</filter-class>
    </filter>

    <filter-mapping>
        <filter-name>characterEncoding</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>


    <filter-mapping>
        <filter-name>auth</filter-name>
        <url-pattern>/index</url-pattern>
    </filter-mapping>
</web-app>
```
