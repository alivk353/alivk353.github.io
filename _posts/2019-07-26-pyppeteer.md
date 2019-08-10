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

## Chromium 挖掘反射/DOM XSS漏洞

### 爬虫收集url

传统的web1.0爬虫通过xpath,bs4,正则等方式来获取静态链接,在web2.0中越来越多的数据通过后台js发送请求并动态加载,许多document内的节点都可以通过JQuery vue.js等前端框架来生成,一些请求数据的接口需要我们取触发特定事件才能发现

通过直接调用CDP接口或pyppeteer库向浏览器注入js代码来尽可能的获取页面上的链接信息,关键在于我们js代码注入的时间点:

- 在页面加载前,可以劫持一些函数来达到记录一些绑定事件,ajax请求
- 在页面加载后,可以注入js代码来遍历各个节点,触发各种事件来获取链接

#### 页面加载前

CDP提供的Page.addScriptToEvaluateOnNewDocument接口可以在加载前执行我们的js代码

pyppeteer中page.evaluateOnNewDocument方法可在页面加载前注入我们的js代码

此时页面的document还没有构建,所以无法操作DOM,可以劫持的对象:

##### 阻塞页面加载函数,会弹出对话框的函数:

- window.alert = () => {};
- window.prompt = (msg,input) => {return input;};
- window.confirm = () => {};
- window.clone = () => {};

##### ⻚⾯被意外跳转和关闭:

```javascript
window.open();
window.location="/123";
window.location="/456";
```

可以使用chromium的插件来拦截请求

##### 获取ajax请求

hook xhr对象

```javascript
var oldws = window.WebSocket;
window.WebSocket = (url,arg) => {save_res(url);return new oldws(url,arg);};

var oldEventSource = window.EventSource;
window.EventSource = (url) => {save_res(url); return new oldEventSource(url);};

var oldFetch = window.Fetch;
window.Fetch = (url) => {save_res(url); return new oldFetch(url);};


XMLHttpRequest.prototype.__originalOpen	= XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = function (method,url,async,user,password){
    return this.__originalOpen(method, url, async, user, password);	
};
XMLHttpRequest.prototype.__originalSend	= XMLHttpRequest.prototype.send;
XMLHttpRequest.prototype.send =	function(data) {
    save_res('xhr...');
    return this.__originalSend(data);
};
```

> 某些情况下,触发事件会导致xhr请求中断,导致丢失链接.

#### 页面加载后

可以判断页面加载完毕的三种事件:

- page.once('load',()=>{}) 触发load事件
- networkkidle2 等待⽹络链接不超过两个的时候才继续执⾏
- DOMContentLoaded 即document.readyState === "complete"

```text
load: when load event is fired.
domcontentloaded: when the DOMContentLoaded event is fired.
networkidle0: when there are no more than 0 network connections for at least 500 ms.
networkidle2: when there are no more than 2 network connections for at least 500 ms.
```

可以在同时监控这三种时间的同时设置超时时间,一般load事件会在最后,DOMContentLoaded会不叫靠前

简单通过pyppeteer的page.goto()方法来判断页面已经加载完毕:

```text
timeout (int): Maximum navigation time in milliseconds, defaults to 30 seconds, pass 0 to disable timeout. The default value can be changed by using the setDefaultNavigationTimeout() method.

waitUntil (str|List[str]): When to consider navigation succeeded, defaults to load. Given a list of event strings, navigation is considered to be successful after all events have been fired. Events can be either:

load: when load event is fired.
domcontentloaded: when the DOMContentLoaded event is fired.
networkidle0: when there are no more than 0 network connections for at least 500 ms.
networkidle2: when there are no more than 2 network connections for at least 500 ms.
```

##### 遍历节点

在页面加载完毕后,遍历DOM节点.收集链接信息和事件信息,这里先不触发事件:

```javascript
var treeWalker = document.createTreeWalker(
            document,
            NodeFilter.SHOW_ELEMENT,
            {acceptNode: function (node) {return NodeFilter.FILTER_ACCEPT;}},
            //tree_walker_filter,
            false
        );
```

##### 触发事件

在页面加载之前需要劫持的之间注册函数:

- Element.prototype.addEventListener
- window.addEventListener
- HTMLElement.prototype.onclick
- inner-event 内联事件 在遍历节点时发现

在收集所有节点的静态链接之后,开始触发已经收集到的事件,这里存在两种情况,一是添加了新节点,二是发出新请求

通过MutationObserver监听新节点,绑定callback函数遍历新节点,获取新的链接和新的事件


## 未完...
