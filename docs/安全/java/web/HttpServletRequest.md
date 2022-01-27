---
created: '21/08/08'
title: HttpServletRequest
tags:
  - java
---
# HttpServletRequest
Http servletRequest代表客户端的请求，用户通过HTTP协议访问服务器，HTTP请求中的所有信息会被封装到 `HttpServletRequest`,通过`HttpServletRequest`的方法，获得客户端的所有信息。
## 常见应用
### 获取请求参数和请求头
```java
package top.longlone.servlet;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;

public class HelloServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        // 设置请求编码
        req.setCharacterEncoding("utf-8");
        // 设置响应编码
        resp.setHeader("Content-Type", "text/html; charset=utf-8");

        String ua = req.getHeader("User-Agent");
        // 获取参数value
        String value = req.getParameter("value");
        // 获取参数values，允许多个参数，如values=1&values=2
        String[] values = req.getParameterValues("values");

        // 输出
        PrintWriter out = resp.getWriter();
        out.write("UA:" + ua + "<br>参数: " + value + " " + Arrays.toString(values));
    }
}
```
### 获取请求体
```java
package top.longlone.servlet;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;

public class HelloServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
       // 字符串形式获取body
       // BufferedReader reqReader = req.getReader();
       // String str, body = "";
       //
       // while((str=reqReader.readLine()) != null) {
       //     body += str;
       // }

        // 二进制形式获取body
        int len = req.getContentLength();
        ServletInputStream reqInputStream = req.getInputStream();
        byte[] body = new byte[len];
        reqInputStream.read(body, 0, len);

        resp.getWriter().write(new String(body));
    }
}
```
### 转发
```java
package top.longlone.servlet;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;

public class HelloServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        // 这里的/get中/代表当前程序的根目录，不加/的话就是相对的路径，这里加不加都可以
       req.getRequestDispatcher("/get").forward(req, resp);
    }
}

```
## 总结
本节主要讲了HttpServletRequest类的使用。