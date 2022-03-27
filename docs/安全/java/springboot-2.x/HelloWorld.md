---
created: '22/02/22'
title: HelloWorld
tags:
  - java
  - spring
  - springboot
---
# HelloWorld
## SpringBoot是什么？
> Spring Boot是由Pivotal团队提供的全新[框架](https://baike.baidu.com/item/%E6%A1%86%E6%9E%B6/1212667)，其设计目的是用来[简化](https://baike.baidu.com/item/%E7%AE%80%E5%8C%96/3374416)新[Spring](https://baike.baidu.com/item/Spring/85061)应用的初始搭建以及开发过程。该框架使用了特定的方式来进行配置，从而使开发人员不再需要定义样板化的配置。通过这种方式，Spring Boot致力于在蓬勃发展的快速应用开发领域(rapid application development)成为领导者。

可以看到SpringBoot主要目的是为了简化Spring应用的搭建与开发。

## 初始化工程
可以使用[Spring Initializr](https://start.spring.io/)页面进行创建，或者直接使用idea创建。这里直接使用idea。

首先点击新建项目:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220222105914.png)

按照如图所示配置，这里选用java8，Maven进行依赖管理。
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220222105953.png)

选择需要的依赖，这里选择Spring Web，SpringBoot版本选择默认的2.6.3
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220222110325.png)

点击FINISH，即可创建项目，需要等待一段时间idea解析maven依赖。

创建好后的项目结构如图所示(controller文件夹是我后续添加的，一开始是没有的)
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220222110527.png)
如上图所示，Spring Boot的基础结构共三个文件夹(具体路径根据用户生成项目时填写的Group和ArtiFact有所差异）:
-   `src/main/java`下的程序入口：`SpringBootStudyApplication`
-   `src/main/resources`下的配置文件：`application.properties`
-   `src/test/`下的测试入口：`SpringBootStudyApplicationTests`

## 编写HelloWorldController
在`src/main/java`文件夹下创建`com.example.springbootstudy.controller`包，在该包下创建`HelloWorldController` (注意，这里我们的Controller必须在我们的`SpringbootStudyApplication`文件夹及子文件夹下，否则无法加载，Controller类首字母必须大写):

```java
package com.example.springbootstudy.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {
    @RequestMapping("/hello")
    public String index() {
        return "Hello World";
    }
}
```

这里解释一下其中的2个注解的作用:
- `@RestController`:  其等价于`@ResponseBody` + `@Controller`，分别介绍下这2个注解:
    - `@ResponseBody`: 设置了这个注解的类/方法返回的值就是return中的内容，无法返回指定的View页面(如`index.html`等)，但是其能够返回json，xml或自定义mediaType内容到页面(即将一个Object自动序列化成json后返回)
    - `@Controller`: 表示Spring某个类是否可以接收HTTP请求，能够返回指定的View页面(如`return index`则会跳转到视图层`index.html`)
- `@RequestMapping`: 设置请求映射(即路由)

## 配置
springboot中可以使用application.properties或者application.yml对项目进行配置，后者的优先级较高。两者的区别是前者比较直接，但没有层次感，后者相反。

在springboot 2.1之后，springboot启动默认不会显示mapping日志，我们可以通过修改配置来让其输出mapping日志，以了解哪些controller被成功加载，我们以application.properties为例:
```
server.port=8080  
logging.level.org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping=trace
```
第一行设置的是服务的监听端口，第二行就是设置mapping日志级别，以显示我们的mapping日志。

## 运行
运行SpringbootStudyApplication.main()方法，启动springboot，有以下信息就证明controller被成功加载了:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220222124501.png)


尝试访问http://127.0.0.1:8080/hello:
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20220222124604.png)

## 编写测试
需要给pom.xml添加junit依赖:
```xml
<dependency>
    <groupId>junit</groupId>
    <artifactId>junit</artifactId>
    <scope>test</scope>
</dependency>
```

完整的测试如下，需要注意的是最后的三个import，需要static才能import，这里我们编写测试，测试一下/hello是否返回200 ok及响应是否为Hello World:
```java
package com.example.springbootstudy;

import com.example.springbootstudy.controller.HelloController;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.hamcrest.Matchers.equalTo;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
class SpringbootStudyApplicationTests {
    private MockMvc mvc;

    @Test
    public void getHello() throws Exception {
        mvc = MockMvcBuilders.standaloneSetup(new HelloController()).build();
        mvc.perform(MockMvcRequestBuilders.get("/hello").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().string(equalTo("Hello World")));
    }
}
```

