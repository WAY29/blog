# pe文件型病毒
## 病毒如何感染PE文件
- 首先判断文件是否是PE文件
如何判断一个文件是否为PE文件？
检验文件头部第一个字的值是否等于MZ，如果是，则DOS头有效。
用DOS头的字段e_Ifanew来定位PE头。
比较PE头的第一个双字的值是否等于50450000H（PE\0\0）。
- 接下来，添加节
![](https://gitee.com/guuest/images/raw/master/img/20210616141045.png)
## pe病毒编写的关键技术
- **定位**
- **获得API函数**
- 搜索目标文件
- **感染**
- 破坏

## 代码重定位
### pe文件变量重定位
病毒是在宿主的运行环境下运行，所以无法像在自己本身的运行环境下一样访问自己的静态（全局）变量的数据和直接调用系统API。
![](https://gitee.com/guuest/images/raw/master/img/20210616142751.png)
![](https://gitee.com/guuest/images/raw/master/img/20210616143135.png)
### 动态api函数地址获取
![](https://gitee.com/guuest/images/raw/master/img/20210616144210.png)

![](https://gitee.com/guuest/images/raw/master/img/20210616144641.png)
![](https://gitee.com/guuest/images/raw/master/img/20210616144827.png)
![](https://gitee.com/guuest/images/raw/master/img/20210616153912.png)
![](https://gitee.com/guuest/images/raw/master/img/20210616154041.png)

#### 引入表
存在于.idata区段，将.idata区块合并成另一个区块已成为一种惯例，典型的是.rdata区块
![](https://gitee.com/guuest/images/raw/master/img/20210616144300.png)
#### 引出表
存在于.edata区段，经常被合并到.text或.rdata 区块中
![](https://gitee.com/guuest/images/raw/master/img/20210616160007.png)

#### 引出表解析流程


#### kernel32地址获取方法
![](https://gitee.com/guuest/images/raw/master/img/20210616155409.png)
![](https://gitee.com/guuest/images/raw/master/img/20210616222200.png)

![](https://gitee.com/guuest/images/raw/master/img/20210616155425.png)
![](https://gitee.com/guuest/images/raw/master/img/20210616155452.png)
![](https://gitee.com/guuest/images/raw/master/img/20210616155516.png)



#### 从Kernel32.dll的导出表中获取某个API函数的地址
![](https://gitee.com/guuest/images/raw/master/img/20210616162132.png)
①在名字表遍历RVA地址，转换成FOA地址，然后根据FOA比较FOA指向的字符串与func是否相等，不相等则判断下一个。  
②如果相等则获取到其在名字表中的索引(下标)，根据该索引获取对应的序号表中同一下标索引到的序号值value。  
③value作为地址表的索引，索引到的值即为func()的地址。
#### 总结
![](https://gitee.com/guuest/images/raw/master/img/20210616163842.png)

### 如何判断文件是否是PE文件
检验文件头部第一个字的值是否等于MZ，如果是，则DOS头有效。
用DOS头的字段e_lfanew来定位PE头。
比较PE头的第一个双字的值是否等于50450000H（PE\0\0）。


### 病毒感染PE文件的方式

#### 添加节
![](https://gitee.com/guuest/images/raw/master/img/20210616164350.png)
![](https://gitee.com/guuest/images/raw/master/img/20210616165118.png)
![](https://gitee.com/guuest/images/raw/master/img/20210616170311.png)
![](https://gitee.com/guuest/images/raw/master/img/20210616170318.png)
![](https://gitee.com/guuest/images/raw/master/img/20210616170329.png)

#### 扩展节
![](https://gitee.com/guuest/images/raw/master/img/20210616164946.png)
![](https://gitee.com/guuest/images/raw/master/img/20210616165137.png)

#### 插入节
![](https://gitee.com/guuest/images/raw/master/img/20210616165228.png)
![](https://gitee.com/guuest/images/raw/master/img/20210616165242.png)
