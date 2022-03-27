# 关于windows提升效率那些事
最近换了新电脑，配置的时候刚好想起来，于是总结下如何在windows下提高效率（主要是实现mac/\*unix下的一些已经有的功能）

## caps2esc
*参考[这篇文章](https://orxing.top/post/d3c3145e.html)*


Caps Lock的作用是锁定输入为大写字母，这个键位对我来说没什么用，完全可以使用Shift代替。
所以这里可以考虑将Caps Lock利用起来，在单击和长按时分别映射为Esc和Ctrl，这样我们就几乎没必要再去按ESC(左上角)和Ctrl(左下角)了。
### 安装
1. 那么要如何实现呢？结合前人的经验我们可以直接白嫖，链接在[这里](https://github.com/oblitum/Interception/releases/tag/v1.0.1)
直接下载Interception.zip，在**command line installer**文件夹和**samples/x86**文件夹下找到我们需要的工具：**install-interception.exe**和**caps2esc.exe**
2. 打开具有**管理员权限**的CMD或POWERSHELL窗口，执行以下代码:`.\install-interception.exe /install`
3. 此时再运行`caps2esc.exe`就可以达到我们的效果了（如果没效果试试重启大法，否则就是上面的install没有成功）
4. 为了方便我们，可以将**caps2esc.exe**设置为开机启动
5. 如果要卸载的话，则执行`.\install-interception.exe /uninstall`即可。
### 使用
就如我们刚刚所说，此时Caps Lock键单击时会变成esc键（以前我不喜欢按esc键，因为它实在太远了，但是现在越按越爽），配合其他按键一起的时候就是Ctrl键，也就是说你可以使用Caps Lock + c作为Ctrl + c等，同时原本的ESC键则变为了原始Caps Lock的功能

## virtual-desktop-enhancer
我们知道windows10中是存在多虚拟桌面的，但是一直不够好用（不能通过键盘切换到指定的桌面，不能通过键盘将某个进程移动到某个指定的桌面），而virtual-desktop-enhancer就是为了解决这个问题的
### 安装
virtual-desktop-enhancer在github上就能搜到，但是早就归档不更新了，这就导致新版windows无法使用，此时就要去找它的fork项目，找到还能新版windows用的(windows 版本21h1可以使用)，链接在[这里](https://github.com/amrahm/win-10-virtual-desktop-enhancer)

安装直接`git clone https://github.com/amrahm/win-10-virtual-desktop-enhancer`即可
### 使用 
1. 使用windows+tab去创建几个新的虚拟桌面(好像可以省略)
2. 可以安装autohotkey去运行.ahk脚本或者直接运行exe，相关配置在**settings.ini**
3. 看看右下角任务栏是否开了个新的应用程序，是一个数字（对应当前的桌面）
4. 修改配置，这里贴下我的配置,使用windows+数字键切换到对应的虚拟桌面，使用windows+shift+数字键将当前的进程移动到对应的虚拟桌面，同时可以修改[Wallpapers]中的路径，从而使得不同的虚拟桌面自动切换不同的桌面背景
```ini
[General]
DefaultDesktop=2
TaskbarScrollSwitching=0
UseNativePrevNextDesktopSwitchingIfConflicting=0
DesktopWrapping=1

[Tooltips]
Enabled=1
; One of LEFT, CENTER, RIGHT
PositionX=CENTER
; One of TOP, CENTER, BOTTOM
PositionY=CENTER
FontSize=11
FontColor=0xFFFFFF
FontInBold=1
BackgroundColor=0x1F1F1F
Lifespan=750
; Watch out! Long durations (> 500ms) could cause troubles as the program freezes during the animation.
FadeOutAnimationDuration=100
OnEveryMonitor=1

[KeyboardShortcutsCombinations]
TogglePinWindow=Win, Ctrl, Shift, Q
TogglePinApp=Win, Ctrl, Shift, A
PinWindow=
PinApp=
UnpinWindow=
UnpinApp=
; "SC029" is the key below your "Esc" key
OpenDesktopManager=
ChangeDesktopName=Win, F2

[KeyboardShortcutsModifiers]
SwitchDesktop=Win
MoveWindowToDesktop=Win, Shift
MoveWindowAndSwitchToDesktop=Win, Shift, Alt
NextTenDesktops=

[KeyboardShortcutsIdentifiers]
PreviousDesktop=,
NextDesktop=.
Desktop1=1
Desktop2=2
Desktop3=3
Desktop4=4
Desktop5=5
Desktop6=6
Desktop7=7
Desktop8=8
Desktop9=9
Desktop10=0
DesktopAlt1=Numpad1
DesktopAlt2=Numpad2
DesktopAlt3=Numpad3
DesktopAlt4=Numpad4
DesktopAlt5=Numpad5
DesktopAlt6=Numpad6
DesktopAlt7=Numpad7
DesktopAlt8=Numpad8
DesktopAlt9=Numpad9
DesktopAlt10=Numpad0

[Wallpapers]
1=
2=
3=
4=
5=
6=
7=
8=
9=
10=

[DesktopNames]
1=code
2=view
3=work
4=play
5=other
6=
7=
8=
9=
10=

[RunProgramWhenSwitchingToDesktop]
1=
2=
3=
4=
5=
6=
7=
8=
9=
10=

[RunProgramWhenSwitchingFromDesktop]
1=
2=
3=
4=
5=
6=
7=
8=
9=
10=
```
5. 愉快地享受

## utools
这个工具是快速启动工具，同类软件有wox，Alfred等，最终选择utools的原因是因为这个工具下有个神级插件：**快捷命令**

### 安装
直接去官网下载安装即可
### 使用技巧
1. 修改启动快捷键，我个人是喜欢设置为Alt+\`这个键位
2. 安装**快捷命令**这个插件，然后就能愉快地去实现许多功能，例如搭配我编写的[工具](https://github.com/WAY29/ptg)快速根据模板生成payload，并且会自动复制到剪切板里，例如反弹shell的payload,例如：
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20210622161151.png)
![](https://tuchuang-1300339532.cos.ap-chengdu.myqcloud.com/img/20210622161312.png)
更多的功能可以自己去研究（
3. 设置全局快捷键，例如我设置Ctrl + Alt + T快速打开windows terminal，Ctrl + Alt + B快速打开Burpsuite
4. 超级面板，看着用，有时候还挺方便的，比如我写了个快捷命令，将选中的文件快速丢到wsl里

