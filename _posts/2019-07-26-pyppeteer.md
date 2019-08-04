# kong

## BOM对象和DOM对象

BOM和DOM是中立于平台和语言的应用程序API

### BOM和window对象

- 浏览器对象模型用于操作浏览器的API,BOM对象是JS对BOM接口的实现
- 通过BOM对象可以调用或访问浏览器功能部件和属性
- window对象是Javascript顶层对象,其他BOM对象均为window对象的子对象,可以作为window对象的属性来调用

#### location对象

可以获取浏览器当前的URL信息

- hash 设置或返回从井号 (#) 开始的 URL（锚）
- host 设置或返回主机名和当前 URL 的端口号
- hostname 设置或返回当前 URL 的主机名
- href 设置或返回完整的 URL
- pathname 设置或返回当前 URL 的路径部分
- protocol 设置或返回当前 URL 的协议
- port 设置或返回当前 URL 的端口号
- search 设置或返回从问号 (?) 开始的 URL（查询部分）
- assign() 加载新的文档
- reload() 重新加载当前文档
- replace() 用新文档代替当前文档

#### navigator对象

可以操作浏览器的属性

- appCodeName 返回浏览器的代码名。
- appMinorVersion 返回浏览器的次级版本
- appName 返回浏览器的名称
- appVersion 返回浏览器的平台和版本信息
- browserLanguage 返回当前浏览器的语言
- cookieEnabled 返回指明浏览器中是否启用 cookie 的布尔值
- cpuClass 返回浏览器系统的 CPU 等级
- onLine 返回指明系统是否处于脱机模式。true则没联网，false则是联网
- platform 返回运行浏览器的操作系统平台
- systemLanguage 返回 OS 使用的默认语言
- userAgent 返回由客户机发送服务器的 user-agent 头部的值。
- userLanguage 返回 OS 的自然语言设置

#### history对象

浏览器的浏览历史记录信息

- length 返回浏览器历史列表中的 URL 数量
- back() 加载 history 列表中的前一个 URL
- forward() 加载 history 列表中的下一个 URL
- go() 加载 history 列表中的某个具体页面

#### screen对象

浏览器的屏幕信息,可以通过JS拿到这些信息


  - document对象:文档对象

### DOM和document对象

- DOM定义了HTML和XML的逻辑结构
- document对象是javascript对DOM接口的实现
- 可以通过document对象对HTML/XML文档进行增删改查
- document对象属于window对象,所以DOM也可以看作是BOM的一部分

> window和document等对象都是单例模式,所以自己创建BOM或DOM对象是没用的

## Headless Chrome

无头chrome浏览器,在chrome59版本后加入,可以在后台用命令行操作浏览器的工具,这里不讨论用法,直接学习使用基于Headless Chrome API的库就好

这些封装库的实现多是基于Chrome Debugging Protocol接口的

大前提:

```bash
# 启动一个监听端口0.0.0.0:9222:
chrome --remote-debugging-port=9222 --remote-debugging-address=0.0.0.0
```

### CDP - Chrome Debugging Protocol的基本用法

也可以不用封装库,直接通过ws调用CDP的API,文档在这里:

```bash
https://chromedevtools.github.io/devtools-protocol/
```

这套协议通过 websocket 进行通信，发送和返回的内容都是 json 格式:

```json
{
"id": id,
"method": command,
"params": params,
}
```

创建 websocket 连接 DevTools

```python
websocket_url = 'ws://0.0.0.0:9222/devtools'
websocket.create_connection(websocket_url, enable_multithread=True)
```

创建⼀个浏览器的新标签⻚⾯

```bash
command = {
    "method": "Target.createTarget",
    "params": {'url': 'about:blank'}
    }
```

申请⼀个⾮共享空间的新标签⻚⾯

```bash
command = {
    "method": "Target.createBrowserContext"
    }
```

利⽤navigate打开特定⽹站

```bash
command = {
    "method": "Page.navigate",
    "params": {"url": "https://xz.aliyun.com"}
}
```

CDP提供WebShell级别的完美API操控

- Page.getCookies
- Page.captureScreenshot
- Page.printToPDF

### chrome_remote_interface

通过headless chrome打开的监听端口来控制访问target url来截取页面的解析过程中所有的流量,相当chrome审查元素的network模块,可以将这些流量交给扫描器或者漏洞插件去做测试

### pyppeteer

pyppeteer模版是对puppeteer的python封装，puppeteer是用nodejs写的，所以要在python中使用得用pyppeteer模块


## Chromium 检测反射/DOM XSS漏洞

