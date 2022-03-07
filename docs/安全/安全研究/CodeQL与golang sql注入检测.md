---
title: CodeQL与golang sql注入检测
tags:
  - codeql
  - golang
  - 代码审计
---
# CodeQL与golang sql注入检测
## 什么是CodeQL
  
CodeQL是一个可以对代码进行分析的引擎, 安全人员可以用它作为挖洞的辅助或者直接进行挖掘漏洞,节省进行重复操作的精力。
  
在CodeQL中，代码被解析成数据，存储在数据库中。安全漏洞、错误和其他错误被建模为可以针对数据库执行的查询。我们可以运行由GitHub研究人员和社区贡献者编写的标准CodeQL查询，也可以编写自己的查询以用于自定义分析。查找潜在错误的查询直接在源文件中突出显示结果。

## 保姆级安装教程
  
虽然官方提供了可以进行查询的网站，但是由于官网在国外而且执行速度不快，或者某些语言(如c/c++)需要自定义编译命令来编译，实际上在网站是完全不够使用的，所以我们只能本地搭建环境，以下步骤是一步步进行的。

### codeql-cli
在命令行(cli)的环境下运行codeql

[项目地址 : github/codeql-cli-binaries](https://github.com/github/codeql-cli-binaries)
打开项目地址之后进入Releases库，下载对应操作系统的压缩包解压到任意一个文件夹

### codeql
开源的codeql标准库和查询库

[项目地址: github/codeql](https://github.com/github/codeql)
进入到上面解压codeql-cli的文件夹，并把该仓库clone下来，保证codeql-cli和codeql在同一个目录下
![](https://gitee.com/guuest/images/raw/master/img/20211101170723.png)

### vscode-codeql
vscode的codeql插件，直接在插件市场安装
![](https://gitee.com/guuest/images/raw/master/img/20211101170802.png)

### 配置环境变量
为了方便我们使用codeql-cli，我们需要将其路径放到PATH下，具体的方法就不多介绍了(windows下将其添加到环境变量中，linux下修改PATH变量)

同时我们最好再配置下codeql插件的可执行文件路径，打开vscode的设置，搜索codeql，修改Executable Path
![](https://gitee.com/guuest/images/raw/master/img/20211101171106.png)


至此我们的环境算是配的差不多了。。。但是如果你需要用go的话还需要进行额外配置

### codeql-go
开源的codeql-go标准库和查询库(不太明白为什么不直接放在codeql库里)

[项目地址: github/codeql-go](https://github.com/github/codeql-go)

这个项目了写明了安装方法，但是存在以下弊端:
1. 这是一个sh脚本，意味着windows办法使用
2. 这个项目有这么一段话
>   If you want to use the CodeQL extension for Visual Studio Code, import this repository into your VS Code workspace.

意思是说我们如果需要使用go的标准库时，还需要手动添加到vscode的workspace里，非常麻烦

为了解决这个弊端，我自己捣鼓了一下，将其放在了codeql标准库里，具体步骤如下
1. clone仓库到ql文件夹里(即codeql标准库)并改其文件夹名为go
![](https://gitee.com/guuest/images/raw/master/img/20211101171752.png)

2. 修改.codeqlmanifest.json，加入一行`"go/.codeqlmanifest.json",`
```json
{ "provide": [ "ruby/.codeqlmanifest.json",
                      "go/.codeqlmanifest.json",
                "*/ql/src/qlpack.yml",
               "*/ql/lib/qlpack.yml",
               "*/ql/test/qlpack.yml",
               "cpp/ql/test/query-tests/Security/CWE/CWE-190/semmle/tainted/qlpack.yml",
               "*/ql/examples/qlpack.yml",
               "*/upgrades/qlpack.yml",
               "javascript/ql/experimental/adaptivethreatmodeling/lib/qlpack.yml",
               "javascript/ql/experimental/adaptivethreatmodeling/src/qlpack.yml",
               "misc/legacy-support/*/qlpack.yml",
               "misc/suite-helpers/qlpack.yml" ] }
```
至此我们已经成功安装了包括go在内的codeql标准库以及codeql的cli程序，来写个Hello world测试一下

##  Hello world
我们来创建一个我们的学习工作区并输出一个codeql的hello,world，步骤如下:

1. 创建一个文件夹，这里以codeql_study为例
2. 用vscode打开该文件夹，创建一个ql文件夹，并在该文件夹下创建helloworld.ql和qlpack.yml
3. qlpack.yml的内容如下
```yml
name: longlone/codeql-study
version: 0.0.1
libraryPathDependencies: codeql-go
extractor: go
```
4. helloworld.ql的内容如下
```ql
import go

select "hello world"
```
5. 创建一个codeql database，这里我们需要指定一个go项目作为分析目标
```
codeql database create ./codeql_database -s D:\Coding\golang\src\codeql_study --language=go
```
6. 从vscode中选择codeql_database作为数据库
![](https://gitee.com/guuest/images/raw/master/img/20211101174647.png)
![](https://gitee.com/guuest/images/raw/master/img/20211101174714.png)

7. 右键helloworld.ql，选择`CodeQL: Run Query`
![](https://gitee.com/guuest/images/raw/master/img/20211101174805.png)

如果显示以上画面，那么我们成功就安装好了环境。

## CodeQL语法前言
CodeQL的很多语法和现在的主流高级语言有很多相似之处，但也有许多的不同，学习的时候需要注意。
举一个简单的例子，在CodeQL中不存在`==`，只有`=`，当一个变量定义了而没有初始化的时候，`=`的意思是赋值，但当其已经被赋值了之后，`=`的意思就变成了比较。

## 基础数据类型(Primitive types)
CodeQL 是一种静态类型的语言，因此每个变量都必须有一个声明的类型。类型是一组值。例如，int 类型是一组整数。注意，一个值可以属于这些集合中的多个，这意味着它可以有多个类型。
整型(int)，浮点型(float)，日期型(date)，字符型(stirng)，布尔型(boolean)。

## 谓词(Predicates)
谓词有点类似于其他语言中的函数，但又与函数不同，谓词用于描述构成 QL 程序的逻辑关系。确切的说，谓词描述的是给定参数与元组集合的关系。
定义谓词有以下几个注意点(坑点):
1. 需要注意的是谓词的名字开头必须是小写字母。
2. 绑定行为与绑定集，这个在后面会介绍。

### 无结果谓词
没有结果的谓词以predicate作为开头，剩下的语法结构类似于定义函数。这种谓词只能在where语句中使用
一个简单的例子如下:
```ql
predicate isCity(string city) {
city = "Beijing"
or
city = "ShangHai"
}

from string city
where city = "Beijing" and isCity(city)
select city
```

### 结果谓词
有结果的谓词的定义类似于c/c++语言的函数定义，以返回类型替代predicate作为开头。这种谓词可以在where与select语句中使用
一个简单的例子如下:
```ql
int addOne(int i) {
    result = i + 1 and
    i in [1 .. 10]
}

from int v
where v = 1
select addOne(v)
```

## 查询(Query)
查询是CodeQL的输出。查询有两种类型，分别是
- 选择子句
- 查询谓词，这意味着我们可以在当前模块中定义或者从其他模块中导入

### 选择子句
选择子句的格式如下:
```ql
[from] /* ... variable declarations ... */
[where] /* ... logical formula ... */
select /* ... expressions ... */
```
其中from和where语句是可选的。我们可以在from中定义变量，在where中给变量赋值和对查询结果的过滤，最后在select中显示结果。
在select语句中我们还可以使用一些关键字:
- `as`关键字，后面跟随一个名字。作用相当于sql中的`as`，为结果列提供了一个"标签"，并允许在后续的select表达式中使用它们。
- `order by`关键字，后面跟随一个一个结果列名。作用相当于sql中的`order by`，用于排序结果，并且在结果列名后可选`asc`(升序)或`desc`(降序)关键字。

一个简单的例子如下:
```ql
from int x, int y
where x = 3 and y in [0 .. 2]
select x, y, x * y as product, "product: " + product
```

## 污点分析定义
污点分析可以抽象成一个三元组`<sources,sinks,processor>`的形式，其中:
-   **source 即污点源**，代表直接引入不受信任的数据或者机密数据到系统中
-   **sink 即污点汇聚点**，代表直接产生安全敏感操作（违反数据完整性）或者泄露隐私数据到外界（违反数据保密性）
-   **sanitizer 即无害处理**，代表通过数据加密或者移除危害操作等手段使数据传播不再对软件系统的信息安全产生危害

## golang sql注入检测
### 什么是sql注入？
我们先看看百科上是怎么说的
> SQL注入即是指web应用程序对用户输入数据的合法性没有判断或过滤不严，攻击者可以在web应用程序中事先定义好的查询语句的结尾上添加额外的SQL语句，在管理员不知情的情况下实现非法操作，以此来实现欺骗数据库服务器执行非授权的任意查询，从而进一步得到相应的数据信息。
看完官方的介绍，我在来说下我理解的sql注入是什么

sql注入其实就是**不受信任的用户输入**通过字符拼接的方式**进入sql语句**中从而导致sql语句的语义改变，通过这种恶意sql语句实现的一种攻击。

这里有两个关键点，一个是**不受信任的用户输入**，一个是**进入sql语句**，可以看到它们就类似于上面污点分析说到的**source**和**sink**

### 一段简单的sql注入代码
```go
package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
)

var (
	Addr       = "0.0.0.0:8080"
)

func init() {
	flag.StringVar(&Addr, "addr", "0.0.0.0:8080", "Server listen address")
	flag.Parse()
}

func main() {
	db, err := sql.Open("mysql",
		"root:root@tcp(127.0.0.1:3306)/test")
	defer db.Close()

	if err != nil {
		panic(err)
	}
	err = db.Ping()
	if err != nil {
		panic(err)
	}
	router := gin.Default()
	router.GET("/inject", func(ctx *gin.Context) {
		var (
			username string
		)
        // source
		id := ctx.Query("id")
		if id == "" {
			id = "1"
		}

		id2 := id + "hhhhhh"
        // sink
		rows, err := db.Query("select username from users where id = " + id2)
		if err != nil {
			log.Panic(err)
		}
		defer rows.Close()

		for rows.Next() {
			err := rows.Scan(&username)
			if err != nil {
				log.Panic(err)
			}
		}

		ctx.String(200, username)
	})
	router.Run(Addr)
}

```
### 利用CodeQL检测sql注入
我们这先尝试自己去编写一个CodeQL来检测这段代码中存在的sql注入，这里利用了CodeQL自带的一个污点追踪功能
```ql
from Method GinQuery, DataFlow::CallNode GinQueryCallNode,
     Method DBQuery, DataFlow::CallNode DBQueryCallNode,
     DataFlow::Node sink, DataFlow::Node src
where
     GinQuery.hasQualifiedName("github.com/gin-gonic/gin","Context","Query")
     and GinQueryCallNode = GinQuery.getACall() 
     and DBQuery.hasQualifiedName("database/sql","DB","Query")
     and DBQueryCallNode = DBQuery.getACall()
     and src = GinQueryCallNode.getResult()
     and sink = DataFlow::exprNode(DBQueryCallNode.getCall().getArgument(0))
     and TaintTracking::localTaint(src, sink)
select src, sink
```
最后执行结果如下
![](https://gitee.com/guuest/images/raw/master/img/20211103214319.png)

### 官方标准库检测sql注入
官方标准库中也存在sql注入的检测，位于`codeql-go/lib/src/Security/SqlInjection.ql`，我们来学习一下官方代码是怎么编写的
官方源码如下:
```ql
/**
 * @name Database query built from user-controlled sources
 * @description Building a database query from user-controlled sources is vulnerable to insertion of
 *              malicious code by the user.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id go/sql-injection
 * @tags security
 *       external/cwe/cwe-089
 */

import go
import semmle.go.security.SqlInjection
import DataFlow::PathGraph

from SqlInjection::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "This query depends on $@.", source.getNode(),
  "a user-provided value"
```
可以看到代码很简短，证明真实的实现并不在这里，我们按下Ctrl跟进SqlInjection::Configuration看看
![](https://gitee.com/guuest/images/raw/master/img/20211103204938.png)
这里可以看到Configuration继承了`TaintTracking::Configuration`，这个是官方自带的污点追踪的配置，我们只要实现`isSource`谓词和`isSink`谓词即可，我们继续跟进`Source`类
可以看到`Source`类就是个继承了`DataFlow::Node`的抽象类，那么我们就要去找它的子类
![](https://gitee.com/guuest/images/raw/master/img/20211103205149.png)
子类就在最下面，它又是"继承"于`UntrustedFlowSource`
![](https://gitee.com/guuest/images/raw/master/img/20211103205244.png)
继续跟进`UntrustedFlowSource`，可以看到这里有些比较抽象的代码，实际上这等价于`UntrustedFlowSource`又"继承"于`UntrustedFlowSource::Range`
`UntrustedFlowSource::Range`就在下面，它又是一个继承了`DataFlow::Node`的抽象类，我们继续去找它的子类
![](https://gitee.com/guuest/images/raw/master/img/20211103205329.png)
通过vscode搜索`extends UntrustedFlowSource::Range`，可以看到该类有很多子类，都是为了适配golang中比较出名的web框架(如Beego，Chi，Gin等)
![](https://gitee.com/guuest/images/raw/master/img/20211103205514.png)
这里我们的代码是用Gin作为框架的，我们就以其为例，查看`Gin.qll`，里面有2个类继承了`extends UntrustedFlowSource::Range`，其中一个类的代码如下:
![](https://gitee.com/guuest/images/raw/master/img/20211103210118.png)
最上面这一块的意思是去寻找一个方法调用，并且获取他的返回结果作为source
下面一块的意思是寻找类中的字段(Accepted或Params，是一个数组)，并且在其读取元素时获取他的值作为source

另外一个类的代码如下:
![](https://gitee.com/guuest/images/raw/master/img/20211103210822.png)
这段代码的意思是这些函数调用时获取其第一个参数作为source

上面的代码可能有点复杂，我们稍微简化一下，可以得到以下代码
```ql
import go

abstract class Source extends DataFlow::Node { }

class Node1 extends Source {
  Node1() {
    exists(DataFlow::MethodCallNode call, string methodName |
        call.getTarget().hasQualifiedName("github.com/gin-gonic/gin", "Context", methodName) and
        methodName in [
            "FullPath", "GetHeader", "QueryArray", "Query", "PostFormArray", "PostForm", "Param",
            "GetStringSlice", "GetString", "GetRawData", "ClientIP", "ContentType", "Cookie",
            "GetQueryArray", "GetQuery", "GetPostFormArray", "GetPostForm", "DefaultPostForm",
            "DefaultQuery", "GetPostFormMap", "GetQueryMap", "GetStringMap", "GetStringMapString",
            "GetStringMapStringSlice", "PostFormMap", "QueryMap"
          ]
      |
        this = call.getResult(0)
   )
  }
}

from Source src
select src
```
这里如果对CodeQL不够熟悉可能会产生疑问，为什么Source的子类Node1的特征谓词(可以理解为其他语言中的构造函数)会对Source产生限制作用呢？其实这个就是CodeQL的特点，子类的特征谓词会限定父类。

sink的分析和source同理，我们这里就不再分析了。可以看到其实CodeQL官方就是将很多常用的Web框架的source和sink都写了一遍，这样当我们使用这些Web框架编写代码时就可以使用CodeQL标准库来检测我们的代码是否存在漏洞了。
我们来运行下官方的标准库，可以得到相同的结果:
![](https://gitee.com/guuest/images/raw/master/img/20211103214011.png)
