---
created: '21/11/08'
title: 反序列化CC篇总结
tags:
  - java
  - java安全
  - 反序列化
---
# 反序列化CC篇总结
1. 首先CC链虽然很多条，但是基本上都可以分为前段和后段，重要的承上启下方法是`Transformer.transform`
2. CC链的利用条件存在一些限制，主要表现为:
    - jdk8u71之前可以使用AnnotationInvocationHandler作为前段，之后不行
    - jdk7低版本中无法使用CC5(BadAttributeValueExpException不存在readObject)
    - commons-collections3.x可以使用LazyMap.decorate作为前段，之后不行
    - commons-collections4.0之后可以直接回调PriorityQueue作为前段，之前不行

## 自己写的工具-javaGGC
https://github.com/WAY29/javaGGC

## CC链调用逻辑
### CC1
```
AnnotationInvocationHandler.readObject()
  Proxy.entrySet() // readObject调用了proxy的某些方法，回调invoke
    Proxy.invoke() === AnnotationInvocationHandler.invoke()
      LazyMap.get()
         ChainedTransformer.transform()
	      ConstantTransformer.transform() // 获取Runtime.class
	      InvokerTransformer.transform()   // 获取Runtime.getRuntime
	      InvokerTransformer.transform()   // 获取Runtime实例
	      InvokerTransformer.transform()   // 调用exec方法触发rce
```

### CC2
```
PriorityQueue.readObject()
  PriorityQueue.heapify()
  PriorityQueue.siftDown()
  PriorityQueue.siftDownUsingComparator()
  comparator.compare() === TransformingComparator.compare()
    InvokerTransformer.transform()
      TemplatesImpl.newTransformer()
        TemplatesImpl.getTransletInstance() 
          TemplatesImpl.defineTransletClasses()  // 定义类
        ...  // 创建类实例，触发static代码块
```

### CC3
```
AnnotationInvocationHandler.readObject()
  Proxy.entrySet() // readObject调用了proxy的某些方法，回调invoke
    Proxy.invoke() === AnnotationInvocationHandler.invoke()
        LazyMap.get()
        ChainedTransformer.transform()
          InvokerTransformer.transform()
          InstantiateTransformer.transform()
          newInstance()
            TrAXFilter#TrAXFilter()
              TemplatesImpl.newTransformer()
                TemplatesImpl.getTransletInstance() 
                  TemplatesImpl.defineTransletClasses()  // 定义类
                ...  // 创建类实例，触发static代码块
```

### CC4
```
PriorityQueue.readObject()
  PriorityQueue.heapify()
  PriorityQueue.siftDown()
  PriorityQueue.siftDownUsingComparator()
  comparator.compare() === TransformingComparator.compare()
    ChainedTransformer.transform()
      InvokerTransformer.transform()
      InstantiateTransformer.transform()
      newInstance()
        TrAXFilter#TrAXFilter()
          TemplatesImpl.newTransformer()
            TemplatesImpl.getTransletInstance() 
              TemplatesImpl.defineTransletClasses()  // 定义类
            ...  // 创建类实例，触发static代码块
```

### CC5
```
BadAttributeValueExpException.readObject()
  valObj.toString() === TiedMapEntry.toString()
    TiedMapEntry.getValue()
      LazyMap.get()
         ChainedTransformer.transform()
	      ConstantTransformer.transform() // 获取Runtime.class
	      InvokerTransformer.transform()   // 获取Runtime.getRuntime
	      InvokerTransformer.transform()   // 获取Runtime实例
	      InvokerTransformer.transform()   // 调用exec方法触发rce
```

### CC6
```
HashMap.readObject()
  putForCreate(key) === key.hashCode() === TiedMapEntry.hashCode()
    TiedMapEntry.getValue()
      LazyMap.get()
         ChainedTransformer.transform()
	      ConstantTransformer.transform() // 获取Runtime.class
	      InvokerTransformer.transform()   // 获取Runtime.getRuntime
	      InvokerTransformer.transform()   // 获取Runtime实例
	      InvokerTransformer.transform()   // 调用exec方法触发rce
```

### CC7
```
Hashtable.readObject()
  Hashtable.reconstitutionPut()
    org.apache.commons.collections.map.AbstractMapDecorator.equals() === java.util.AbstractMap.equals()
        LazyMap.get()
           ChainedTransformer.transform()
            ConstantTransformer.transform() // 获取Runtime.class
            InvokerTransformer.transform()   // 获取Runtime.getRuntime
            InvokerTransformer.transform()   // 获取Runtime实例
            InvokerTransformer.transform()   // 调用exec方法触发rce
```