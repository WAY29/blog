---
created: '21/09/28'
title: RMI篇3
tags:
  - java
  - java安全
---
# RMI篇3

## 流量分析
略
### SerializationDumper

[下载地址](https://github.com/NickstaDB/SerializationDumper/releases/tag/1.13)

## 什么是classAnnotations
> 众所周知，在序列化Java类的时候用到了一个类，叫ObjectOutputStream。这个类内部有一个方法 annotateClass，ObjectOutputStream的子类有需要向序列化后的数据里放任何内容，都可以重写这个方法，写入你自己想要写入的数据。然后反序列化时，就可以读取到这个信息并使用。


`classAnnotations`表示和类相关的`Annotation`的描述信息，这里的数据值一般是由`ObjectOutputStream`的`annotateClass()`方法写入的，但由于`annotateClass()`方法默认为空，所以`classAnnotations`后一般会设置`TC_ENDBLOCKDATA`标识；

