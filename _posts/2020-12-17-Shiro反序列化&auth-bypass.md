# Shiro的反序列化漏洞和auth bypass

## shiro反序列化 < 1.2.4

使用shiro是为了让用户在服务器重启后不丢失session,登录成功后shiro会将登录信息`序列化`后加密存在在cookie的rememberme字段中返回给浏览器

下次访问时解密并反序列化rememberme字段,回复用户状态

但是在Shiro 1.2.4版本之前内置了一个默认且固定的加密 Key,导致攻击者可以伪造任意的rememberMe Cookie,进而触发反序列化漏洞

秘钥硬编码位置/org/apache/shiro/mgt/AbstractRememberMeManager.class:
```java
public abstract class AbstractRememberMeManager implements RememberMeManager {
    private static final Logger log = LoggerFactory.getLogger(AbstractRememberMeManager.class);
    private static final byte[] DEFAULT_CIPHER_KEY_BYTES = Base64.decode("kPH+bIxk5D2deZiIxcaaaA==");
    private Serializer<PrincipalCollection> serializer = new DefaultSerializer();
    private CipherService cipherService = new AesCipherService();
    private byte[] encryptionCipherKey;
    private byte[] decryptionCipherKey;
    .......
```

### 环境搭建

#### maven添加依赖

pom.xml文件:shiro-core和shiro-web自身需要导入,顺带导入commons-collections3.1测试其他gadget


```xml
<dependencies>
    <dependency>
      <groupId>org.apache.shiro</groupId>
      <artifactId>shiro-core</artifactId>
      <version>1.2.4</version>
    </dependency>
    <dependency>
      <groupId>org.apache.shiro</groupId>
      <artifactId>shiro-web</artifactId>
      <version>1.2.4</version>
    </dependency>
    <!-- https://mvnrepository.com/artifact/commons-collections/commons-collections -->
    <dependency>
      <groupId>commons-collections</groupId>
      <artifactId>commons-collections</artifactId>
      <version>3.2.1</version>
    </dependency>
  </dependencies>
```

#### 配置web.xml


需要在web.xml中配置shiro的监听器和过滤器:

```xml
<web-app>
  <display-name>Archetype Created Web Application</display-name>
  <listener>
    <listener-class>org.apache.shiro.web.env.EnvironmentLoaderListener</listener-class>
  </listener>

  <filter>
    <filter-name>ShiroFilter</filter-name>
    <filter-class>org.apache.shiro.web.servlet.ShiroFilter</filter-class>
  </filter>

  <filter-mapping>
    <filter-name>ShiroFilter</filter-name>
    <url-pattern>/*</url-pattern>
  </filter-mapping>

  <welcome-file-list>
    <welcome-file>index.jsp</welcome-file>
  </welcome-file-list>
</web-app>
```

#### 配置shiro.ini

配置用户及权限:

```text
[main]
shiro.loginUrl = /login.jsp

[users]
# format: username = password, role1, role2, ..., roleN
root = root,admin
guest = guest,guest

[roles]
# format: roleName = permission1, permission2, ..., permissionN
admin = *

[urls]
# The /login.jsp is not restricted to authenticated users (otherwise no one could log in!), but
# the 'authc' filter must still be specified for it so it can process that url's
# login submissions. It is 'smart' enough to allow those requests through as specified by the
# shiro.loginUrl above.
/login.jsp = authc
/logout = logout
/** = user

```

#### login.jsp&index.jsp

最简单的登录页面login.jsp:

```html

<html>
<body>
<form method="post">
    <h1 >login.jsp</h1>
    <div>
        <label>Username</label>
        <input type="text" placeholder="Username" name="username" required>
    </div>
    <div>
        <label>Password</label>
        <input type="password" placeholder="Password" name="password" required>
    </div>
    <div >
        <label>
            <input type="checkbox" name="rememberMe"> Remember me
        </label>
    </div>
    <button type="submit" name="submit" value="Login">Sign in</button>
</form>
</body>
</html>
```

> 需要在项目内任意java文件内import一个Commons-collections321包,才能在运行时gadget能找到类.

#### jetty启动

在pom.xml的build标签内配置插件:

```xml
<plugin>
    <groupId>org.eclipse.jetty</groupId>
    <artifactId>jetty-maven-plugin</artifactId>
    <version>9.4.35.v20201120</version>
    <configuration>
    <scanIntervalSeconds>10</scanIntervalSeconds>
    <webApp>
        <contextPath>/</contextPath>
    </webApp>
    <httpConnector>
        <port>8888</port>
    </httpConnector>
    </configuration>
</plugin>
```

切换至项目目录,运行`mvn jetty:run`

```text
POST /login.jsp;jsessionid=node01sk4i7ib2xtk9107h44jdt4vro0.node0 HTTP/1.1
Host: 127.0.0.1:8888
User-Agent: Mozilla/5.0 (Linux; Android 9; LM-Q720) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.116 Mobile Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 54
Origin: http://127.0.0.1:8888
Connection: close
Referer: http://127.0.0.1:8888/login.jsp;jsessionid=node01sk4i7ib2xtk9107h44jdt4vro0.node0
Cookie: JSESSIONID=node01sk4i7ib2xtk9107h44jdt4vro0.node0
Upgrade-Insecure-Requests: 1

username=root&password=root&rememberMe=on&submit=Login


HTTP/1.1 302 Found
Connection: close
Date: Sun, 25 Apr 2021 06:28:17 GMT
Set-Cookie: JSESSIONID=node07rn89k0cbwgcnmh6flf9uwbp2.node0; Path=/
Expires: Thu, 01 Jan 1970 00:00:00 GMT
Set-Cookie: rememberMe=deleteMe; Path=/; Max-Age=0; Expires=Sat, 24-Apr-2021 06:28:17 GMT
Set-Cookie: rememberMe=ZYPDeZqHfgs0+w88k4lcJPp5v5uQx/hvFJE2PFdxh4S1/gdR0UAvl/iNXksRpIOh/bTVzWx6icxjOXrSTBQtzlp9kgeantCHOsurhe6P1d72kNI1VB+tpa25u//ybUEvIRjoeyiiuRBuSGaaVdAPk/T7EDtuqfChEOgdI/smAsEJRBMaENRSLeBs1jUWB5MRCXwGcpwFSgAXvlG1AX+n7dIgpvQetSWS9egLw2AdfNR03XMSdkh2gRKFs9rWZHdrb41m94MFpe3/b72UhuYdxg5D6rqaSf/Xa+3MYNx6vwEz9nMbF6Uo+w6ijeKGLE4OEwdxhMI/hYWWzwWIhQv4RZGOZgXJ3j+wnA7h8IN4bxaLQtndcQc42jaIVljcF82Zeq4KRdT7o9LWPTq62hf8oN7SaQRjHoQzHcI49lINxHLcwH1t2J0eAwuMdB+ZomTt60eINjk3zQzDr7d/RzUavdOjH88qWRz8lyrKIWD3OCU0wU+mJFRUj6k5/tpV9iTs; Path=/; Max-Age=31536000; Expires=Mon, 25-Apr-2022 06:28:17 GMT; HttpOnly
Location: http://127.0.0.1:8888/
Server: Jetty(9.4.35.v20201120)
```

发出的登录post会被shiro的拦截器处理,并返回加密的序列化数据在rememberMe中




### Gadget

#### 首先CommonsCollections6

这个利用链主体上是依靠`chainedtransformer`作为最终命令执行的关键

而触发使用的是lazyMap.get()->TiedMapEntry.getValue()->hashMap.readObject()


## Shiro Padding Oracle Attack 反序列化 < 1.4.1

为了保证分组加密时每一组都能保证等长，在加密时需要对最后一组不等长的情况进行填充，缺n位就填n个0x0n

解密过程：当我们提交一个IV时，服务器会用中间值与它异或得值然后先校验填充情况而非直接比对明文。