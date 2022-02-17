---
created: '22/02/15'
title: JRMP
tags:
  - java
---
# JRMP
> Java远程方法协议（英语：Java Remote Method Protocol，JRMP）是特定于Java技术的、用于查找和引用远程对象的协议。这是运行在Java远程方法调用（RMI）之下、TCP/IP之上的线路层协议（英语：Wire protocol）。

JRMP全称为`Java Remote Method Protocol`，也就是Java远程方法协议，通俗点解释，它就是一个协议，一个在TCP/IP之上的线路层协议，一个RMI的过程，是用到JRMP这个协议去组织数据格式然后通过TCP进行传输，从而达到RMI，也就是远程方法调用。

我们在使用浏览器进行访问一个网络上的接口时，它和服务器之间的数据传输以及数据格式的组织，是用到基于TCP/IP之上的HTTP协议，只有通过这个HTTP协议，浏览器和服务端约定好的一个协议，它们之间才能正常的交流通讯。而JRMP也是一个与之相似的协议，只不过JRMP这个协议仅用于Java RMI中。

