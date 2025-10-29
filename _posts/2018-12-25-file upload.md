
## 1

造成文件上传可能的原因:

- 服务器配置不当
- 开源编辑器上传漏洞
- 本地文件上传限制被绕过
- 过滤不严格被绕过
- 文件解析漏洞导致文件执行
- 文件路径截断

## 服务端绕过汇总

### 黑名单

#### 多中拓展名

web容器可以解析的拓展名:

- ASP/ASPX: asp，aspx，asa，ascx，ashx，asmx，cer，cdx 
- PHP: php，php5，php4，php3，phtml，pht
- JSP: jsp，jspx，jspa，jsw，jsv，jspf，jtml

> iis6.0 中的 asa 和 cer•可能存在大小写绕过漏洞 

#### 上传.htaccess文件绕过黑名单:

.htaccess文件的作用：.htaccess是一个纯文本文件，它里面存放着Apache服务器配置相关的指令。

.htaccess主要的作用有：URL重写、自定义错误页面、MIME类型配置以及访问权限控制等。主要体现在伪静态的应用、图片防盗链、自定义404错误页面、阻止/允许特定IP/IP段、目录浏览与主页、禁止访问指定文件类型、文件密码保护等。

.htaccess的用途范围主要针对当前目录。

#### 上传.user.ini文件绕过

#### 利用大小写绕过

Windows对大小写不敏感 Linux对大小写敏感 
所以Windows系统可以解析.Php、.PHp、.PHP、.pHp、.pHP、.phP扩展名的文件
若网站后端过滤并未统一大小写（将文件扩展名转为小写表示 则会造成绕过

#### 利用空格点绕过

Windows系统默认删除文件后缀的“.”和空格 后端没有过滤末尾的点和空格 就可以进行绕过

JavaServer tomcat jetty resin支持的后缀:jsp jspx jspf

```java
java.util.logging.Logger l=java.util.logging.Logger.getLogger("t");
java.util.logging.FileHandler h=new java.util.logging.FileHandler(pageContext.getServletContext().getRealPath("/")+request.getParameter("f"),true);
h.setFormatter(new java.util.logging.SimpleFormatter());
l.addHandler(h);
l.info(request.getParameter("t"));
```

```java
RandomAccessFile rf = new RandomAccessFile(request.getRealPath("/")+request.getParameter("f"), "rw");
rf.write(request.getParameter("t").getBytes());
rf.close();
```

### javabean


## 解析漏洞

### IIS5.x-6.x解析漏洞
使用 IIS5.x-6.x 版本的服务器，大多为Windows server 2003，网站比较古老，开发语句一般为asp；该解析漏洞也只能解析asp文件，不能解析aspx文件。

目录解析漏洞
IIS6.0中的目录解析漏洞，如果网站目录中有一个 *.asp/ 的文件夹，那么该文件夹下面的一切内容都会被 IIS 当作 asp 脚本来执行，如/xx.asp/xx.jpg

文件解析漏洞
IIS6.0中的分号（;）漏洞，IIS在解析文件名的时候会将分号后面的内容丢弃，那么我们可以在上传的时候给后面加入分号内容来避免黑名单过滤，如 a.asp;jpg

### IIS 7.0/IIS 7.5/Nginx < 8.03

IIS 7.0/7.5，默认 Fast-CGI 开启。如果直接在 url 中图片地址（*.jpg）后面输入/*.php，会把正常图片解析为 php 文件

这个解析漏洞其实是PHP CGI的漏洞，在PHP的配置文件中有一个关键的选项cgi.fix_pathinfo在本机中位于C:wampbinphpphp5.3.10php.ini，默认是开启的，当URL中有不存在的文件，PHP就会向前递归解析

### Nginx空字节漏洞
影响版本：0.5、0.6、0.7<=0.7.65、0.8<= 0.8.37

### Apache（1.x、2.x）解析漏洞

Apache（1.x,2.x）解析文件的原则：Apache在解析文件名的时候是从右向左读，如果遇到不能识别的扩展名则跳过，rar、gif等扩展名是Apache不能识别的，因此就会直接将类型识别为php，从而达到了注入php代码的目的。

假如上传文件1.php.bb.rar，后缀名rar不认识，向前解析；1.php.bb，后缀名bb不认识，向前解析；1.php 最终解析结果为php文件
