---
layout: post
title: "XSS 备忘"
comments: false
description: " "
keywords: " "
---

# XSS

## 浏览器解析机制

当浏览器从网络中获取到一段文本,触发HTML解析器进行解析,HTML解析器是一个状态机,初始状态为数据状态(`DATA State`),当解析到 `<`字符进入标签开始状态(`Tag open state`),接着解析 `a-z` 字符组成的标签名进入标签名状态(`Tag name state`),此时会发出一个 `Start tag token` ,这个token会在DOM tree中生成一个新节点,继续解析如果存在属性键值对会依次进入前属性名状态,属性值状态...指导解析到 `>` 字符进入标签关闭状态(`Tag close state`),然后回到数据状态(`Data State`), 当解析器再遇到 `<` 字符时,会先入标签开始状态(`Tag open state`),接着遇到 `/` 后发出 `end tag token` 并进入标签名状态(`Tag name state`),直到遇到 `>` 解析完这个标签,再次回到数据状态(`DATA State`)

在这个阶段会对HTML实体编码进行解析,以下三种情况会对实体编码进行解解码:

***

### 数据状态(DATA State)

```html
<div>&#60;img src=x onerror=alert(4)&#62;</div>
```
在解析`<div>`标签后,回到数据状态(`DATA State`),遇到 `&#60;` 会做实体字符解码 `<`,但不会进入标签开始状态(`Tag open state`),也就不会在DOM树中生成`<img>`节点,而是生成`#Text`节点,所以上述js代码不会被执行

### 属性值状态(attribute value state)

```html
<a href="&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:%61%6c%65%72%74%28%32%29">a标签</a>
```

在进入标签开始状态(`Tag open state`)后,接着解析属性键值对,将属性值内的实体编码解析,所以对`href`中的代码执行没有影响

### RCDATA状态

解析到`<textarea>`和`<title>`进入RCDATA状态

```html
<textarea>&#60;script&#62;alert(5)&#60;/script&#62;</textarea>
```

在RCDATA状态中,实体字符编码会被解码,但是不会进入标签开始状态(`Tag open state`),也就不会被解析成新节点,所以上述文本中的js代码不会被执行

***

在对HTML文本解析完毕,即词法解析完成,DOM树也就建立完成,Javascript解析器会对内联脚本进行解析,js解析的同时,如果遇到URL的上下文会由URl解析器来处理

### URL解析

首先，URL资源类型必须是ASCII字母 `http:`, `javascript:` 不可以被编码,包括冒号

```html
<a href="%6a%61%76%61%73%63%72%69%70%74:%61%6c%65%72%74%28%31%29"></a>
```

上述代码中的协议名被url编码,所以不会成功执行

### Javascript解析

`<script>` 和 `<style>`都属于原属文本,内部的所有HTML实体字符编码都不会被解析

在js代码块中的\Uxxxx称为Unicode转义序列,在不影响js执行的情况下,可以放在三种情况下使用

#### 1.字符串中

单双引号,换行符不会被解释

#### 2.函数名,变量名等标识符名称

可以被当作标识符的一部分使用,不会影响代码执行

#### 3.控制字符

在代码执行过程中用到的单双引号,小括号都属于控制字符,对这些字符做js编码会影响到代码执行

### 外部元素

MathML命名空间或者SVG命名空间的元素,他们都遵循的是XML标准:

- `在XML中实体会自动转义,除了<![CDATA[和]]>包含的实体`

SVG遵循XML标准的同时也定义`script`标签,所以下面的payload可以执行:

```html
<svg><script>alert&#40;1)</script></svg>
```

## 关于CSP策略

CSP的特点就是他是在浏览器层面做的防护，是和同源策略同一级别，除非浏览器本身出现漏洞，否则不可能从机制上绕过

一个CSP策略分为多个组,以分号为界,每一组策略包含一个策略指令和一个内容源列表:

```html
Content-Security-Policy: default-src 'self' www.baidu.com; script-src 'unsafe-inline'
```

- 常用的策略指令:
    - script-src定义了页面中Javascript的有效来源
    - style-src定义了页面中CSS样式的有效来源
    - img-src定义了页面中图片和图标的有效来源
    - font-src font-src定义了字体加载的有效来源
    - connect-src定义了请求、XMLHttpRequest、WebSocket 和 EventSource 的连接来源。
    - child-src 指定定义了 web workers 以及嵌套的浏览上下文（如`<frame`>和`<iframe>`）的源。
- 内容源:
    - 源列表 一个字符串,可以使用通配符前缀来匹配地址和端口
    - 关键字
        - 'none' 空集,不匹配任何url
        - 'self' 和文档同源,有着相同的 URL 协议和端口号
        - 'unsafe-inline' 允许使用内联资源,如内联的`<script>`元素、javascript: URL、内联的事件处理函数和内联的`<style>`元素
        - 'unsafe-eval' 允许使用 eval() 等通过字符串创建代码的方法
    - 数据
      - data: 支持 data://协议
      - mediastream:

### CSP策略的绕过


```php
header("Content-Security-Policy: default-src 'self'; script-src 'self' ");
```

## X-XSS-Protection

X-XSS-Protection字段用于开启浏览器XSS防护机制，ie是XSS filter，Chrome是XSS auditor,响应头无此字段默认为1,且此字段存在一定安全隐患

常规设置为 X-XSS-Protectin:1,mode-block

限制引用当前域脚本,可以找到上传图片的地方,上传一个内容为js代码的图片



## Basics 一些案例

```html
<a href="%6a%61%76%61%73%63%72%69%70%74:%61%6c%65%72%74%28%31%29"></a>
URL encoded "javascript:alert(1)"
```

Answer: The javascript will NOT execute.
> 解析URL编码时，解析器会判断该URl的资源类型，经过编码的协议类型不会被URl解析器解析。后面的冒号:同理。

```html
<a href="&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:%61%6c%65%72%74%28%32%29">
Character entity encoded "javascript" and URL encoded "alert(2)"
```

Answer: The javascript will execute.

> 实体编码可以在不破坏DOM结构的情况下被解析，首先HTMl解析器实体引用，之后UR了解析器会对href属性值解析。

```html
<a href="javascript%3aalert(3)"></a>
URL encoded ":"
```

Answer: The javascript will NOT execute.
> 不可以对协议资源类型及冒号进行编码，url解析器会认为他是无类型地址。


```html
<div>&#60;img src=x onerror=alert(4)&#62;</div>
Character entity encoded < and >
```
Answer: The javascript will NOT execute.

> HTML解析器在解析&#60;div&#62;后处于“数据状态”，此状态下可以解析实体字符引用，这种情况& #60;会被解析成“<”但是不会当作一个标签的开始，也就不会建立新标签。因此，我们能够利用字符实体编码这个行为来转义用户输入的数据从而确保用户输入的数据只能被解析成“数据”。

```html
<textarea>&#60;script&#62;alert(5)&#60;/script&#62;</textarea>
Character entity encoded < and >
```

Answer: The javascript will NOT execute AND the character entities will NOT
be decoded either

> 在标签textarea和title中，实体编码会被解析，但是不会被执行。

```html
<textarea><script>alert(6)</script></textarea>
```
Answer: The javascript will NOT execute.

> 标签testarea中的内容不会被当作脚本进行执行。

## Advanced

```html
<button onclick="confirm('7&#39;);">Button</button>
Character entity encoded '
```

Answer: The javascript will execute.
> 标签属性值中的实体字符会被HTML解析器解析，随后经过JS解析器成功执行。

```html
<button onclick="confirm('8\u0027);">Button</button>
Unicode escape sequence encoded '
```

Answer: The javascript will NOT execute.

> 例子中Unicode编码处于控制字符内，例如单双引号，括号等都属于控制字符，当使用Unicode表示一个控制字符时，他仅仅会被解析成字符串常量，例中导致单引号没有闭合，不会执行。

```html
<script>&#97;&#108;&#101;&#114;&#116&#40;&#57;&#41;&#59</script>
Character entity encoded alert(9);
```

Answer: The javascript will NOT execute.

> 所有的“script”都属于“原始文本”元素。在“script”的字符编码引用并不会被解析和解码。

```html
<script>\u0061\u006c\u0065\u0072\u0074(10);</script>
Unicode Escape sequence encoded alert
```
Answer: The javascript will execute.

> 例中Unicode编码位于标识符中，即函数方法的名字中，会被解码成函数名，方法名的一部分。

```html
<script>\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0031\u0029</script>
Unicode Escape sequence encoded alert(11)
```

Answer: The javascript will NOT execute.

> 对小括号进行Unicode编码会将括号结成字符串，不会作为程序控制的一部分。

```html
    <script>\u0061\u006c\u0065\u0072\u0074(\u0031\u0032)</script>
    Unicode Escape sequence encoded alert and 12 
```

Answer: The javascript will NOT execute.

> 括号中的内容没有被当作字符串进行解码 ，没有处于‘’内。

```html
    <script>alert('13\u0027)</script>
    Unicode escape sequence encoded '
```

Answer: The javascript will NOT execute.

> \u0027不会被解码成控股之字符，导致单引号没有闭合。

```html
<script>alert('14\u000a')</script>
Unicode escape sequence encoded line feed.
```
Answer: The javascript will execute.

 > \u000a是换行符，例中Unicode编码处于字符串中,在JS中Unicode转义将永远不会破环字符串上下文，所以它们只能被解释成字符串常量。

***

## Bonus

```html
<a href="&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;&#x25;&#x35;&#x63;&#x25;&#x37;&#x35;&#x25;&#x33;&#x30;&#x25;&#x33;&#x30;&#x25;&#x33;&#x36;&#x25;&#x33;&#x31;&#x25;&#x35;&#x63;&#x25;&#x37;&#x35;&#x25;&#x33;&#x30;&#x25;&#x33;&#x30;&#x25;&#x33;&#x36;&#x25;&#x36;&#x33;&#x25;&#x35;&#x63;&#x25;&#x37;&#x35;&#x25;&#x33;&#x30;&#x25;&#x33;&#x30;&#x25;&#x33;&#x36;&#x25;&#x33;&#x35;&#x25;&#x35;&#x63;&#x25;&#x37;&#x35;&#x25;&#x33;&#x30;&#x25;&#x33;&#x30;&#x25;&#x33;&#x37;&#x25;&#x33;&#x32;&#x25;&#x35;&#x63;&#x25;&#x37;&#x35;&#x25;&#x33;&#x30;&#x25;&#x33;&#x30;&#x25;&#x33;&#x37;&#x25;&#x33;&#x34;&#x28;&#x31;&#x35;&#x29;"></a>
```

Answer: The javascript will execute.

首先，HTML解析器解码实体字符:

```html
javascript:%5c%75%30%30%36%31%5c%75%30%30%36%63%5c%75%30%30%36%35%5c%75%30%30%37%32%5c%75%30%30%37%34(15)
```

URL解析器解码：

```html
javascript:\u0061\u006c\u0065\u0072\u0074(15)
```

JS解析器解码Unicode：

```html
javascript:alert(15)
```