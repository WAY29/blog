---
created: '21/08/10'
title: JSP
tags:
  - java
---
# JSP
摘自[菜鸟教程 - JSP简介](https://www.runoob.com/jsp/jsp-intro.html)

JSP即Java Server Pages，是一种动态网页开发技术。它使用JSP标签在HTML网页中插入Java代码。标签通常以<%开头以%>结束。
JSP是一种Java servlet，主要用于实现Java web应用程序的用户界面部分。网页开发者们通过结合HTML代码、XHTML代码、XML元素以及嵌入JSP操作和命令来编写JSP。
## JSP原理
当我们访问对应页面的时候，在 tomcat/work 目录下可以看到我们访问的jsp页面会生成对应的java程序，JSP最终会转换成Servlet，浏览器最后访问的其实是Servlet。
```java
// 初始化
  public void _jspInit() {
  }
// 销毁
  public void _jspDestroy() {
  }
//JSP Service
  public void _jspService(final javax.servlet.http.HttpServletRequest request, final javax.servlet.http.HttpServletResponse response) throws java.io.IOException, javax.servlet.ServletException {
  
  }
```
1. 判断请求
2. 内置一些对象
```java
final javax.servlet.jsp.PageContext pageContext;  // 页面上下文
javax.servlet.http.HttpSession session = null;       // session
final javax.servlet.ServletContext application;      // Servlet上下文
final javax.servlet.ServletConfig config;                // config
javax.servlet.jsp.JspWriter out = null;                   // out
final java.lang.Object page = this;                        // 当前页
javax.servlet.jsp.JspWriter _jspx_out = null;
javax.servlet.jsp.PageContext _jspx_page_context = null;
HttpServletRequest request                                 // 请求
HttpServletResponse response                            // 响应
```
3. 给对象赋值
```java
response.setContentType("text/html");
pageContext = _jspxFactory.getPageContext(this, request, response, null, true, 8192, true);
_jspx_page_context = pageContext;
application = pageContext.getServletContext();
config = pageContext.getServletConfig();
session = pageContext.getSession();
out = pageContext.getOut();
_jspx_out = out;
```
4. 以上对象可以在jsp页面中直接使用
![](https://gitee.com/guuest/images/raw/master/img/20210810104423.png)

## JSP基础语法

### 导入依赖
JSTL(JSP标准标签库)是一个JSP标签集合，它封装了JSP应用的通用核心功能。
```xml
<dependency>
	<groupId>javax.servlet.jsp.jstl</groupId>
	<artifactId>jstl</artifactId>
	<version>1.2</version>
</dependency>
```
### 中文乱码问题
```
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
```

### 基础语法
jsp不仅支持java的全部语法，而且有自己的扩充语法，摘自[JSP语法 - 菜鸟教程](https://www.runoob.com/jsp/jsp-syntax.html)
#### 脚本程序
`<% java代码片段 %>`

脚本程序可以包含任意的JAVA语句
#### JSP表达式
`<%= java代码片段 %>`

JSP表达式，会将计算得到的表达式直接输出
#### JSP声明
`<%! 声明 %>`

JSP声明，一个声明语句可以声明一个或多个变量、方法，供后面的Java代码使用。
#### JSP注释
`<%-- 注释--%>`
#### JSP指令
`<%@ directive attribute="value" %>`

JSP指令用来设置与整个JSP页面相关的属性。

这里有三种指令标签：

|指令|描述|
|----|----|
|<%@ page ... %>|定义页面的依赖属性，比如脚本语言、error页面、缓存需求等等|
|<%@ include ... %>|包含其他文件|
|<%@ taglib ... %>|引入标签库的定义，可以是自定义标签|

##### 自定义错误页面
error/500.jsp

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>  
<%@ page isErrorPage="true"%>  
<html>  
<head>  
 <title>500 - Error</title>  
</head>  
<body>  
<p>500 error!</p>  
</body>  
</html>
```
index.jsp

```jsp
<%--index.jsp--%>
<%@page errorPage="error/500.jsp" %>  
<html>  
 <head>  
 <title>Hello world</title>  
 </head>  
<body>  
<h2>111</h2>  
<% int a = 1/0; %>  
</body>  
</html>
```
或者在web.iml中全局设置错误页面
```xml
    <error-page>
        <error-code>404</error-code>
        <location>/error/404.jsp</location>
    </error-page>
```
##### 包含共有文件
common/header.jsp

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>  
<p>this is header</p>
```
common/footer.jsp

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>  
<p>this is footer</p>
```
index.jsp

```jsp
<%@page errorPage="error/500.jsp" %>
<html>
    <head>
        <title>Hello world</title>
    </head>
<body>
<%@ include file="common/header.jsp"%>
<h2>content</h2>

<%@ include file="common/footer.jsp"%>
</body>
</html>
```

值得一提的是使用`<jsp:include page=""/>`也可以实现一样的事情，这标签与上面标签的区别是底层实现不同，该标签底层通过拼接页面实现

### 九大内置对象
- PageContext
- Request
- Response
- Session
- Application [ServletContext]
- config [ServletConfig]
- out
- page
- exception

作用域:
- pageContext: 只在一个页面中有效
- request: 只在一次请求中有效
- session: 只在一次会话中有效
- application: 在整个应用中有效

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>Title</title>
</head>
<body>
<%
    pageContext.setAttribute("name1", "test1"); // 保存的数据只在一个页面有效
    request.setAttribute("name2", "test2");     // 保存的数据只在一次请求中有效
    session.setAttribute("name3", "test3");     // 保存的数据只在一次会话中有效
    application.setAttribute("name4", "test4"); // 保存的数据在整个应用中有效
%>
<%
    // getAttribute和findAttribute的区别:
    // getAttribute: 在page scope内查找与name相关的属性，找到返回就返回对象，找不到就返回null。
    // findAttribute: 依次在page，request，session（如果有效的话）和application Scope（范围）查找以name为名的Attribute，找到就返回对象，都找不到返回null

    String name1 = (String) pageContext.getAttribute("name1");
    String name2 = (String) pageContext.findAttribute("name2");
    String name3 = (String) pageContext.findAttribute("name3");
    String name4 = (String) pageContext.findAttribute("name4");
%>
<h2>${name1}</h2>
<h2>${name2}</h2>
<h2>${name3}</h2>
<h2>${name4}</h2>
</body>

</html>
```


#### JSP标签
`<jsp:action_name attribute="value" />`

行为标签基本上是一些预先就定义好的函数，下表罗列出了一些可用的JSP行为标签:

|语法|描述|
|----|----|
|jsp:include|用于在当前页面中包含静态或动态资源|
|jsp:useBean|寻找和初始化一个JavaBean组件|
|jsp:setProperty|设置 JavaBean组件的值|
|jsp:getProperty|将 JavaBean组件的值插入到 output中|
|jsp:forward|从一个JSP文件向另一个文件传递一个包含用户请求的request对象|
|jsp:plugin|用于在生成的HTML页面中包含Applet和JavaBean对象|
|jsp:element|动态创建一个XML元素|
|jsp:attribute|定义动态创建的XML元素的属性|
|jsp:body|定义动态创建的XML元素的主体|
|jsp:text|用于封装模板数据|

### JSTL标签
安装和配置参考[JSTL](https://www.runoob.com/jsp/jsp-jstl.html)
使用不多，略

### EL表达式
简单语法: `${expr}`。其中，expr指的是表达式。在JSP EL中通用的操作符是` .` 和 `{}`。这两个操作符允许您通过内嵌的JSP对象访问各种各样的JavaBean属性。

JSP EL支持下表列出的隐含对象：

|隐含对象|描述|
|----|----|
|pageScope|page 作用域|
|requestScope|request 作用域|
|sessionScope|session 作用域|
|applicationScope|application 作用域|
|param|Request 对象的参数，字符串|
|paramValues|Request对象的参数，字符串集合|
|header|HTTP 信息头，字符串|
|headerValues|HTTP 信息头，字符串集合|
|initParam|上下文初始化参数|
|cookie|Cookie值|
|pageContext|当前页面的pageContext|



## JSP的缺点
摘自[知乎 - # jsp为什么被淘汰了？](https://www.zhihu.com/question/328713931/answer/711014242)

1. 动态资源和静态资源全部耦合在一起，无法做到真正的动静分离。服务器压力大，因为服务器会收到各种http请求，例如css的http请求，js的，图片的，动态代码的等等。一旦服务器出现状况，前后台一起玩完，用户体验极差。
2. 前端工程师做好html后，需要由java工程师来将html修改成jsp页面，出错率较高（因为页面中经常会出现大量的js代码），修改问题时需要双方协同开发，效率低下。
3. jsp必须要在支持java的web服务器里运行（例如tomcat等），无法使用nginx等（nginx据说单实例http并发高达5w，这个优势要用上），性能提不上来。
4. 第一次请求jsp，必须要在web服务器中编译成servlet，第一次运行会较慢。
5. 每次请求jsp都是访问servlet再用输出流输出的html页面，效率没有直接使用html高。
6. jsp内有较多标签和表达式，前端工程师在修改页面时会捉襟见肘，遇到很多痛点。
7. 如果jsp中的内容很多，页面响应会很慢，因为是同步加载。

## 总结
本节主要介绍了JSP的基础语法，JSTL标签和EL表达式，同时说明了JSP被淘汰的原因。