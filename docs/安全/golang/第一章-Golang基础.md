---
created: '21/06/06 08:50'
title: 第一章-Golang基础
tags:
  - golang
---
# 第一章-Golang基础

### 环境搭建

相关文章: [vscode搭建go语言开发环境](https://juejin.im/post/6844904122450182151)

### go build

- 将go文件编译成可执行文件 `go build hello.go`

- 去除调试信息和符号表以节约可执行文件大小 `go build -ldflags "-w -s"`

- 交叉编译(如使用windows编译成linux的可执行文件)

   ```纯文本
   SET CGO_ENABLED=0
   SET GOOS=linux
   SET GOARCH=amd64
   go build -ldflags "-s -w" -o hello hello.go
   ```


### go doc

相关文章: [godoc 命令和 golang 代码文档管理](https://www.jianshu.com/p/b9ce0cbaabd5) 

 ```Bash
 # 查看目标包的文档索引
 go doc [targetPackage]
 # 查看目标包的某内容的文档索引
 go doc [targetPackage].[函数名]
 # 或者空格隔开也显示某内容的文档
 go doc [targetPackage] [函数名]
 # 子包的文档注释
 go doc [targetPackage]/[subpackage]
 # 代码文档编写, 按 go 的标准注释写法编写
 // Biz implements a business
 type Biz struct {
 }
 
 // business initialization
 func (b *Biz) Init() {
 }
 ```


### go mod(golang v1.11及以上)

相关文章:  [go mod 使用](https://juejin.im/post/6844903798658301960) 

 ```Bash
 # 配置 go mod
 export GO111MODULE=true
 # 创建新项目
 go mod init hello
 # 接下来几乎可以不用管了,在使用第三方包时import, 在运行时会自动从网上下载依赖
 # go module 安装 package 的原則是先拉最新的 release tag，若无tag则拉最新的commit
 # 使用go get时也会由go mod接管
 
 # 运行 go get -u 将会升级到最新的次要版本或者修订版本(x.y.z, z是修订版本号， y是次要版本号)
 # 运行 go get -u=patch 将会升级到最新的修订版本
 # 运行 go get package@version 将会升级到指定的版本号version
 # 运行go get如果有版本的更改，那么go.mod文件也会更改
 
 # 使用go mod时引入当前文件夹下的包不能再使用 ./package, 而是使用 project/package
 
 # 常用的go mod命令
 go mod tidy # 自动安装所缺的依赖包以及去除无用的依赖包
 
 ```


### go 变量与常量

- 相关文章 [Go五种定义变量的方法](https://mp.weixin.qq.com/s?__biz=MzU1NzU1MTM2NA==&mid=2247483669&idx=2&sn=e70a1400c094e981f15b8da552bd8fbf&chksm=fc355b7ecb42d26824985163a3ef0c3567134975637c4efc42161751f54ab10343b485b36e23&scene=21#wechat_redirect)

- 在函数之外不能使用`a := value`的语句定义变量

- 通常使用以下语句定义全局变量

   ```Go
   var (
     WG sync.WaitGroup
     LOCK sync.Mutex
   )
   ```


- 通常使用以下语句定义常量

   ```Go
   const (
     PI float64 = 3.14
     WEIGHT int = 5
   )
   ```


### go 结构体

- 相关文章 [Go Struct 超详细讲解](https://juejin.im/post/6844903814168838151)

- 特别注意的是go结构体中的匿名字段,看以下两种写法

   ```Go
   // 写法一
   package main
   
   import (
     "fmt"
   )
   
   type Animal struct {
     Name  string
     Color string
   }
   
   func (a *Animal) Run() {
     fmt.Println(a.Name, a.Color)
   }
   
   type Lion Animal // Lion是Animal的别名,这样只能继承Animal的属性,而无法调用Animal的方法,解决方法是使用接口/实现func (a *Lion) Run()
   
   func main() {
     var lion = Lion{
       Name:  "小狮子",
       Color: "灰色",
     }
     // 无法调用lion.Run()
     fmt.Println(lion.Name)
   }
   
   // 写法二
   package main
   
   import (
     "fmt"
   )
   
   type Animal struct {
     Name  string
     Color string
   }
   
   func (a *Animal) Run() {
     fmt.Println(a.Name, a.Color)
   }
   
   type Lion struct {
     Animal //匿名字段,这样组合了Animal的特性,可以直接使用func (a *Animal) Run()
   }
   
   func main() {
     var lion = Lion{
       Animal{
               Name:  "小狮子",
               Color: "灰色",
           },
     }
     lion.Run()
     fmt.Println(lion.Name)
   }
   
   ```


### go 接口

- 相关文章 [Go语言的接口interface,struct的组合与继承](https://www.cnblogs.com/pluse/p/7655977.html)

- go中定义接口使用type和interface关键字

- 在Go中，定义一个interface类型，该类型说明了它有哪些方法，然后在其他的函数中，将该interface类型作为函数的形参，任意一个实现了interface类型的实参都能作为该interface的实例对象

- 示例如下

   ```Go
   package main
   
   import "fmt"
   
   type Animal interface {
     Say()
   }
   
   type Dog struct {
     age int
   }
   
   func (a *Dog) Say() {
     fmt.Println("Dog say: I am ", a.age)
   }
   
   type Cat struct {
     age int
   }
   
   func (a *Cat) Say() {
     fmt.Println("Cat say: I am ", a.age)
   }
   
   func AnimalSay(a Animal) {
     a.Say()
   }
   
   func main() {
     dog := Dog{age: 2}
     cat := Cat{age: 3}
     AnimalSay(&dog)
     AnimalSay(&cat)
   }
   
   ```


### go 异常处理

相关文章: [Golang异常处理机制](https://studygolang.com/articles/9152)    [Golang错误和异常处理的正确姿势](https://www.jianshu.com/p/f30da01eea97) 

go中使用**defer, error, panic, recover**处理异常

1. defer

  - defer关键字用来标记最后执行的Go语句，一般用在资源释放、关闭连接等操作，会在函数关闭前调用。

  - 多个defer的定义与执行类似于栈的操作：先进后出，最先定义的最后执行。

   ```Go
   import (
     "net"
       "fmt"
   )
   func func() {
       conn, err := net.Dial("tcp","127.0.0.1:8080")
       defer conn.close()
       if err != nil {
           fmt.Println("Connect Error:", err)
       } else {
           fmt.Println("Connect OK.")
       }
   }
   ```


2. error

error的接口如下

   ```Go
   type error interface {
       Error() string
   }
   ```


  - 一般我们使用errors.New()或fmt.Errorf()来生成自定义的错误信息

  - 假如error比较复杂需要自定义,我们可以自定义一个结构体并且实现对应方法来自定义错误

   ```Go
   package main
   
   import (
     "fmt"
     "strconv"
   )
   
   type TestError struct {
     ErrorCode int
   }
   
   func (err *TestError) Error() string {
     return "TestError: error code " + strconv.Itoa(err.ErrorCode)
   }
   
   func Test() error {
     return &TestError{
       ErrorCode: 1,
     }
   }
   
   func main() {
     err := Test()
     if err != nil {
       fmt.Println(err)
       fmt.Println("Golang custom error is easy!")
     }
   }
   ```


3. panic和recover

  - panic为golang内置函数, 类似于python中的raise, 用于主动抛出异常, panic可以接受任意类型的对象

  - 当主动抛出异常或者遇到runt-ime panics时代码将会终止执行,然后按照FILO的规则执行defer函数

  - recover为golang内置函数, 只能在defer函数中被调用,用于接收panic 函数的参数信息

  - 如果在 defer 语句中也调用 panic 函数，则只有最后一个被调用的 panic 函数的参数会被 recover 函数获取到。如果 goroutine 没有 panic，那调用 recover 函数会返回 nil

   ```Go
   package main
   
   import (
     "fmt"
   )
   
   func Test() {
     defer func() {
       if r := recover(); r != nil {
         fmt.Println("Panic info is:", r)
       }
     }()
     panic("Oh no panic!")
   }
   
   func main() {
     Test()
   }
   ```


### go 并发与信道

1. 并发

  - golang中使用go关键字开启一个新的协程(goroutine)

  - 协程默认是单核并发的,可以通过`runtime.GOMAXPROCS(cpuNum)`来使其多核并行

  - 子协程会在主协程退出时退出

  - 示例如下

   ```Go
   package main
   
   import (
     "os"
     "time"
   )
   
   func test() {
     for {
       file, _ := os.OpenFile("test2.txt", os.O_RDWR|os.O_APPEND|os.O_CREATE, 0664)
       file.WriteString("hello world\n")
       file.Sync()
       file.Close()
       time.Sleep(1 * time.Second)
     }
   }
   
   func main() {
     go test()
     time.Sleep(3 * time.Second)
   }
   
   ```


2. 信道

  - 相关文章 [详解Go信道](https://juejin.im/post/6844904178247008269)

  - golang中使用chan来声明一个信道

  - 信道有容量和长度之分,有缓存与无缓存之分,有双向与单向之分

  - 可以使用信道做锁, 示例如下

     ```Go
     package main
     
     import (
       "fmt"
       "os"
       "time"
     )
     
     func test(ch chan<- bool) {
       file, _ := os.OpenFile("test2.txt", os.O_RDWR|os.O_APPEND|os.O_CREATE, 0664)
       file.WriteString("hello world\n")
       file.Sync()
       file.Close()
       time.Sleep(1 * time.Second)
       ch <- true
     }
     
     func main() {
       ch := make(chan bool)
       go test(ch)
       <-ch
       fmt.Println("finish")
     }
     
     ```


### go 锁与WaitGroup

- go中存在标准库sync

- 锁的使用, 示例如下

   ```Go
   // 定义一个锁
   var lock sync.Mutex
   // 使用锁
   func test() {
       lock.Lock()
       defer lock.Unlock()
       // do something
   }
   // 注意不要在锁已Lock的时候再次请求锁,会造成死锁并且不会引发panic
   ```


- WaitGroup的使用, 示例如下

   ```Go
   // 定义一个WaitGroup
   var wg sync.WaitGroup
   // 使用WaitGroup优雅地等待子协程结束
   package main
   
   import (
     "fmt"
     "sync"
   )
   
   var wg sync.WaitGroup
   
   func test(i int) {
     wg.Add(1)
     defer wg.Done()
     fmt.Println("here is ", i, "goroutine")
   }
   
   func main() {
     for i := 0; i < 10; i++ {
       go test(i)
     }
     wg.Wait()
     fmt.Println("Done")
   }
   ```

