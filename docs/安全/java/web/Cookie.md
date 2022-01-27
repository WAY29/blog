---
created: '21/08/09'
title: Cookie
tags:
  - java
---
# Cookie
1. Cookie 是浏览器访问服务器后，服务器传给浏览器的一段数据。
2. 浏览器会保存这段数据，不轻易删除。
3. 此后每次浏览器访问该服务器，都会带上这段数据，以此来读取一些客户信息。


## 简单示例
```java
package top.longlone.servlet;

import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLDecoder;
import java.text.SimpleDateFormat;
import java.util.Date;

public class CookieServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        req.setCharacterEncoding("UTF-8");
        resp.setHeader("Content-Type", "text/html; charset=UTF-8");

        PrintWriter out = resp.getWriter();
        Cookie[] cookies = req.getCookies();
        Boolean flag = false;

        // 遍历寻找cookie
        if (cookies.length > 0) {
            for (Cookie cookie:cookies) {
                // 取cookie的值
                if (cookie.getName().equals("time")) {
                    SimpleDateFormat sdf = new SimpleDateFormat();
                    sdf.applyPattern("yyyy-MM-dd HH:mm:ss");
                    Long time = Long.parseLong(cookie.getValue());
                    
                    out.write("你上一次访问服务器的时间是: " + sdf.format(time));
                    flag = true;
                    break;
                }
            }
            if (!flag) {
                out.write("第一次访问服务器");
            }

        } else {
            out.write("没有Cookie访问服务器");
        }

        // 设置cookie
        Date date = new Date();
        Cookie cookie = new Cookie("time", String.valueOf(date.getTime()));
        // 设置MaxAge为0的话则会立即销毁该名字对应的cookie
        cookie.setMaxAge(24*60*60);
        resp.addCookie(cookie);
    }
}
````


## 总结
这节主要讲了什么是Cookie以及Cookie的简单示例。