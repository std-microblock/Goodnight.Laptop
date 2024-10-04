<div align=center>
<img src="./icon.webp" width=130>
<h1>Goodnight · 晚安好梦</h1>
<h3>修复 S0 StandBy</h3>
<img src="./screenshot.webp" />
</div>


### 这玩意是干啥的？
**简而言之** - 改善笔记本电脑的待机体验并消除对放在包中时电池耗尽的担忧。

**到底干啥**
- 在睡眠期间暂停几乎所有进程。
- 睡眠时禁用网络连接、鼠标输入和键盘输入。
- 如果意外唤醒，自动快速返回睡眠状态。
- 记录内核电源事件。
- 关闭“离开模式”以防止干扰 S0 睡眠。

Goodnight 是一个命令行应用程序、一个 GUI 应用程序和一个 C++ 库。

### 用法

#### GUI
打开 GUI 并启用您需要的功能。

#### CLI
简单用法：打开 goodnight-cli.exe，它将在默认配置下运行。

详细信息：
```text

     ___                _     __ _       _     _
    / _ \___   ___   __| | /\ \ (_) __ _| |__ | |_
   / /_\/ _ \ / _ \ / _` |/  \/ / |/ _` | '_ \| __|
  / /_\\ (_) | (_) | (_| / /\  /| | (_| | | | | |_
  \____/\___/ \___/ \__,_\_\ \/ |_|\__, |_| |_|\__|
                                   |___/

    Goodnight CLI v0.1.1

用法:
  goodnight-cli.exe [-k|--keep-sleep] [-l|--wake-log] [-s|--suspend-processes] [-w|-a|--wakeup-actions <wakeupActions>] [-v|--verbose] [-d|--disable-devices] [-?|-h|--help]

选项、参数：
-k，--keep-sleep 使系统保持睡眠模式
-l，--wake-log 记录唤醒事件
-s，--suspend-processes 睡眠时暂停进程
-w，-a，--wakeup-actions <wakeupActions: [DisplayOn, PowerButton, Keyboard, Mouse, TouchPad, ACDCPower, Other, All]>
-v，--verbose 详细日志
-d，--disable-devices 睡眠时禁用部分设备
-?，-h，--help
```

<sup><sub>Fuck Microsoft. Fuck AMD & Intel.</sub></sup>
