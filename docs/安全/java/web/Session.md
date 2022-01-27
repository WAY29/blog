---
created: '21/08/09'
title: Session
tags:
  - java
---
# Session
在计算机中，尤其是在网络应用中，称为“会话控制”。Session对象存储特定用户会话所需的属性及配置信息。这样，当用户在应用程序的Web页之间跳转时，存储在Session对象中的变量将不会丢失，而是在整个用户会话中一直存在下去。当用户请求来自应用程序的 Web页时，如果该用户还没有会话，则Web服务器将自动创建一个 Session对象。当会话过期或被放弃后，服务器将终止该会话。

## 示例代码
```java
package top.longlone.servlet;

import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.*;
import java.io.IOException;
import java.io.PrintWriter;

public class HelloServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        req.setCharacterEncoding("UTF-8");
        resp.setHeader("Content-Type", "text/html; charset=UTF-8");

        PrintWriter out = resp.getWriter();

        // 获取session
        HttpSession session = req.getSession();

        if (session.isNew()) {
            out.write("获取Session，id: " + String.valueOf(session.getId()));
            // 设置session中的值，这里是Object类型，可以存任意值
            session.setAttribute("name", "Longlone");
        } else {
            // 获取session中的值
            String name = (String) session.getAttribute("name");
            out.write("读取Session，Session的name: " + name);
        }

        // 销毁session
        // session.invalidate();
    }
}

```

## 设置session有效时间
在web.xml中设置session有效时间(分钟)
```xml
<session-config>
  <session-timeout>2</session-timeout>
</session-config>
```

## Cookie和Session的区别
1. session 在服务器端，cookie 在客户端
2. cookie通常用于存储不太重要的信息，因为其可以被客户端伪造，而session通常用于存储比较重要的信息
3. session 默认被存在服务器的一个文件里
4. session 的运行依赖 session id，而 session id 是存在 cookie 中的，也就是说，如果浏览器禁用了 cookie ，同时 session 也会失效（但是可以通过其它方式实现，比如在 url 中传递 session_id）  

## 总结
这节主要讲了什么是Session以及Cookie和Session的区别。