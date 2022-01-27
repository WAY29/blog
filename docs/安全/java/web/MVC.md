---
created: '21/08/20'
title: MVC
tags:
  - java
---
# MVC
参考了[浅谈 MVC、MVP 和 MVVM 架构模式](https://draveness.me/mvx/)
## MVC架构
- M - model - 模型: 管理应用的行为和数据，响应数据请求（经常来自视图）和更新状态的指令（经常来自控制器）
- V - view - 视图: 管理作为位图展示到屏幕上的图形和文字输出；
- C - controller - 控制器: 翻译用户的输入并依照用户的输入操作模型和视图；
![](https://gitee.com/guuest/images/raw/master/img/20210820103758.png)
控制器负责对模型中的数据进行更新，而视图向模型中请求数据；当有用户的行为触发操作时，会有控制器更新模型，并通知视图进行更新，在这时视图向模型请求新的数据，而这就是**作者所理解的**标准 MVC 模式下，Model、View 和 Controller 之间的协作方式。

## Spring中的MVC架构
Spring中的MVC和标准的MVC架构有些不同
![](https://gitee.com/guuest/images/raw/master/img/20210820104727.png)

1.  通过 DispatchServlet 将控制器层和视图层完全解耦；
2.  视图层和模型层之间没有直接关系，只有间接关系，通过控制器对模型进行查询、返回给 DispatchServlet 后再传递至视图层；
