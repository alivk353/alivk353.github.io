---
layout: post
title: "XSS相关编码"
comments: false
description: " "
keywords: " "
---
## Basics
```
<a href="%6a%61%76%61%73%63%72%69%70%74:%61%6c%65%72%74%28%31%29"></a>
URL encoded "javascript:alert(1)"
```
Answer: The javascript will NOT execute.
> 解析URL编码时，解析器会判断该URl的资源类型，经过编码的协议类型不会被URl解析器解析。后面的冒号:同理。

***

```
<a href="&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:%61%6c%65%72%74%28%32%29">
Character entity encoded "javascript" and URL encoded "alert(2)"
```
Answer: The javascript will execute.

> 实体编码可以在不破坏DOM结构的情况下被解析，首先HTMl解析器实体引用，之后UR了解析器会对href属性值解析。

***

```
<a href="javascript%3aalert(3)"></a>
URL encoded ":"
```

Answer: The javascript will NOT execute.
> 不可以对协议资源类型及冒号进行编码，url解析器会认为他是无类型地址。

***

```
<div>&#60;img src=x onerror=alert(4)&#62;</div>
Character entity encoded < and >
```
Answer: The javascript will NOT execute.

> HTML解析器在解析&#60;div&#62;后处于“数据状态”，此状态下可以解析实体字符引用，这种情况& #60;会被解析成“<”但是不会当作一个标签的开始，也就不会建立新标签。因此，我们能够利用字符实体编码这个行为来转义用户输入的数据从而确保用户输入的数据只能被解析成“数据”。

***

```
<textarea>&#60;script&#62;alert(5)&#60;/script&#62;</textarea>
Character entity encoded < and >
```

Answer: The javascript will NOT execute AND the character entities will NOT
be decoded either

> 在标签textarea和title中，实体编码会被解析，但是不会被执行。

***

```
<textarea><script>alert(6)</script></textarea>
```
Answer: The javascript will NOT execute.

> 标签testarea中的内容不会被当作脚本进行执行。

***

## Advanced

```
<button onclick="confirm('7&#39;);">Button</button>
Character entity encoded '
```
Answer: The javascript will execute.
> 标签属性值中的实体字符会被HTML解析器解析，随后经过JS解析器成功执行。

***

```
<button onclick="confirm('8\u0027);">Button</button>
Unicode escape sequence encoded '
```
Answer: The javascript will NOT execute.

> 例子中Unicode编码处于控制字符内，例如单双引号，括号等都属于控制字符，当使用Unicode表示一个控制字符时，他仅仅会被解析成字符串常量，例中导致单引号没有闭合，不会执行。

***

```
<script>&#97;&#108;&#101;&#114;&#116&#40;&#57;&#41;&#59</script>
Character entity encoded alert(9);
```

Answer: The javascript will NOT execute.

> 所有的“script”都属于“原始文本”元素。在“script”的字符编码引用并不会被解析和解码。

***

```
<script>\u0061\u006c\u0065\u0072\u0074(10);</script>
Unicode Escape sequence encoded alert
```
Answer: The javascript will execute.

> 例中Unicode编码位于标识符中，即函数方法的名字中，会被解码成函数名，方法名的一部分。

***

```
<script>\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0031\u0029</script>
Unicode Escape sequence encoded alert(11)
```
Answer: The javascript will NOT execute.

> 对小括号进行Unicode编码会将括号结成字符串，不会作为程序控制的一部分。

***

```
    <script>\u0061\u006c\u0065\u0072\u0074(\u0031\u0032)</script>
    Unicode Escape sequence encoded alert and 12 
```

Answer: The javascript will NOT execute.

> 括号中的内容没有被当作字符串进行解码 ，没有处于‘’内。

***

```
    <script>alert('13\u0027)</script>
    Unicode escape sequence encoded '
```

Answer: The javascript will NOT execute.

> \u0027不会被解码成控股之字符，导致单引号没有闭合。

***

```
<script>alert('14\u000a')</script>
Unicode escape sequence encoded line feed.
```
Answer: The javascript will execute.

 > \u000a是换行符，例中Unicode编码处于字符串中,在JS中Unicode转义将永远不会破环字符串上下文，所以它们只能被解释成字符串常量。



## Bonus
```
<a href="&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;&#x25;&#x35;&#x63;&#x25;&#x37;&#x35;&#x25;&#x33;&#x30;&#x25;&#x33;&#x30;&#x25;&#x33;&#x36;&#x25;&#x33;&#x31;&#x25;&#x35;&#x63;&#x25;&#x37;&#x35;&#x25;&#x33;&#x30;&#x25;&#x33;&#x30;&#x25;&#x33;&#x36;&#x25;&#x36;&#x33;&#x25;&#x35;&#x63;&#x25;&#x37;&#x35;&#x25;&#x33;&#x30;&#x25;&#x33;&#x30;&#x25;&#x33;&#x36;&#x25;&#x33;&#x35;&#x25;&#x35;&#x63;&#x25;&#x37;&#x35;&#x25;&#x33;&#x30;&#x25;&#x33;&#x30;&#x25;&#x33;&#x37;&#x25;&#x33;&#x32;&#x25;&#x35;&#x63;&#x25;&#x37;&#x35;&#x25;&#x33;&#x30;&#x25;&#x33;&#x30;&#x25;&#x33;&#x37;&#x25;&#x33;&#x34;&#x28;&#x31;&#x35;&#x29;"></a>
```
Answer: The javascript will execute.
> 首先，HTML解析器解码实体字符：

    javascript:%5c%75%30%30%36%31%5c%75%30%30%36%63%5c%75%30%30%36%35%5c%75%30%30%37%32%5c%75%30%30%37%34(15)
> URL解析器解码：

    javascript:\u0061\u006c\u0065\u0072\u0074(15)
> JS解析器解码Unicode：

    javascript:alert(15)
