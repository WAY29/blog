---
created: '21/06/06 08:53'
title: golang-sec-note
tags:
  - golang
---


# 第三章-HTTP

### 了解net/http包

- 有以下几个常用的函数

  - `Get(url string) (resp *Response, err error)`

  - `Head(url string) (resp *Response, err error)`

  - `Post(url string, bodyType string, body io.Reader) (resp *Response, err error)`

  - `PostForm(url string, data url.Values) (resp *Response, err error)`

- 简单地发送GET/POST请求

   ```Go
   package main
   
   import (
     "fmt"
     "io/ioutil"
     "log"
     "net/http"
     "net/url"
     "strings"
   )
   
   func main() {
     r1, err := http.Get("http://httpbin.org/get?a=1")
     if err != nil {
       log.Fatalln("Error: ", err)
     }
     defer r1.Body.Close()
     body, err := ioutil.ReadAll(r1.Body)
     if err != nil {
       log.Fatalln("Error: ", err)
     }
     fmt.Println(string(body))
     form := url.Values{}
     form.Add("foo", "bar")
     r2, err := http.Post(
       "http://httpbin.org/post",
       "application/x-www-form-urlencoded",
       strings.NewReader(form.Encode()),
     )
     if err != nil {
       log.Fatalln("Error: ", err)
     }
     defer r2.Body.Close()
     r3, err := http.PostForm(
       "http://httpbin.org/post",
       form,
     )
     if err != nil {
       log.Fatalln("Error: ", err)
     }
     defer r3.Body.Close()
   }
   
   ```


### 通过NewReuqest/Client拓展请求

- NewRequest定义为: `NewRequest(umethod, vurl string, wbody io.Reader) (req *Request, err error)`

  - 通过NewRequest自定义请求头,示例如下:

     ```Go
     package main
     
     import (
       "encoding/json"
       "fmt"
       "log"
       "net/http"
     )
     
     type Result struct {
       Slideshow map[string]interface{} `json:"slideshow"`
     }
     
     func main() {
       req, err := http.NewRequest("GET", "https://httpbin.org/json", nil)
       var client http.Client = http.Client{}
       req.Header.Add("Accept", "application/json")
       resp, err := client.Do(req)
       if err != nil {
         log.Fatalln("error:", err)
       }
       defer resp.Body.Close()
       var result Result
       if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
         log.Fatalln("error:", err)
       }
       fmt.Printf("%#v\n", result)
     }
     ```


  - 通过NewReuqest发送其他请求方法, 示例如下:

   ```Go
   package main
   
   import (
     "log"
     "net/http"
   )
   
   func main() {
     req, err := http.NewRequest("DELETE", "https://www.google.com/robots.txt", nil)
     var client http.Client
     resp, err := client.Do(req)
     if err != nil {
       log.Fatalln("error:", err)
     }
     defer resp.Body.Close()
   }
   
   ```


  - Client可以控制重定向, 超时时间等,示例如下:

   ```Go
   package main
   
   import (
     "log"
     "net/http"
     "time"
   )
   
   func main() {
     req, err := http.NewRequest("GET", "https://www.google.com/robots.txt", nil)
     var client http.Client = http.Client{
       CheckRedirect: func(req *http.Request, via []*http.Request) error {  // 禁止重定向
         return http.ErrUseLastResponse
       },
       Timeout: time.Duration(90 * time.Second),  // 90秒超时时间
     }
     resp, err := client.Do(req)
     if err != nil {
       log.Fatalln("error:", err)
     }
     defer resp.Body.Close()
   }
   
   ```

