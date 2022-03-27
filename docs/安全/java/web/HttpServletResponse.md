---
created: '21/08/05'
title: HttpServletResponse
tags:
  - java
---
# HttpServletResponse
web服务器接收到客户端的请求后，会封装一个HttpServletRequest和HttpServletResponse
## HttpServletResponse中的方法

### 获取输出响应对象
```java
public ServletOutputStream getOutputStream() throws IOException;
public PrintWriter getWriter() throws IOException;
```

### 设置响应信息
```java
public void setCharacterEncoding(String charset);
public void setContentLength(int len);
public void setContentLengthLong(long len);
public void setContentType(String type);
public void addCookie(Cookie cookie);
public void setDateHeader(String name, long date);
public void addDateHeader(String name, long date);
public void setHeader(String name, String value);
public void addHeader(String name, String value);
public void setIntHeader(String name, int value);
public void addIntHeader(String name, int value);
public void setStatus(int sc);
public void sendError(int sc, String msg) throws IOException;
public void sendRedirect(String location) throws IOException;
```

### 获取响应信息
```java
public int getStatus();
public String getHeader(String name);
public Collection<String> getHeaders(String name);
public Collection<String> getHeaderNames();
public String getCharacterEncoding();
public String getContentType();

```

### 其他
```java
public String encodeURL(String url);
public String encodeRedirectURL(String url);
```

## 常见应用
### 输出响应本体
使用`getOutputStream`或`getWriter`获取输出响应对象之后就可以输出响应本体了。
### 下载文件
1. 获取下载文件路径和文件名
2. 设置响应头
3. 获取下载文件输入流和OutputStream对象
4. 创建buffer缓冲区
5. 将FileOutputStream流写入buffer缓冲区，再将其输出到客户端
```java
package top.longlone.servlet;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLEncoder;

public class DownloadServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        // 获取资源文件路径
        String filepath = this.getServletContext().getRealPath("/WEB-INF/classes/db.properties");

        // 获取文件名
        File file = new File(filepath);
        String fileName = file.getName();

        // 设置响应头，这里要将filename编码一下以支持中文名
        resp.setHeader("Content-Disposition", "attachment;filename=" + URLEncoder.encode(fileName, "UTF-8"));
        resp.setHeader("Content-Length", String.valueOf(file.length()));

        //  获取下载文件输入流和OutputStream对象
        FileInputStream fis = new FileInputStream(filepath);
        ServletOutputStream outputStream = resp.getOutputStream();

        // 创建buffer缓冲区
        int len = 0;
        byte[] buffer = new byte[1024];

        // 将FileOutputStream流写入buffer缓冲区，再将其输出到客户端
        while ((len=fis.read(buffer)) != -1) {
            outputStream.write(buffer, 0, len);
        }

        fis.close();
        outputStream.close();

    }
}
```
### 重定向
```java
package top.longlone.servlet;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class RedirectServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        /* 等价于下面的方式
        resp.setHeader("Location", "/servlet_01/hello");
        resp.setStatus(302);
         */
        resp.sendRedirect("/servlet_01/hello");
    }
}
```
#### 重定向和转发的区别
重定向
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20210806164813.png)
转发
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20210806164831.png)


1. 转发是在服务器端完成的，重定向是在客户端发生的。
2. 转发的速度快，重定向速度慢。
3. 转发是同一次请求，重定向是两次请求。
4. 转发地址栏没有变化，重定向地址栏有变化。
5. 转发必须是在同一台服务器下完成，重定向可以在不同的服务器下完成。
6. 重定向的根目录在webapps根目录，转发的根目录在当前应用程序的根目录。

## 总结
本节主要讲了HttpServletReponse类的使用。