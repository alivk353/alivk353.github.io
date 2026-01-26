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

> shiro AES加密用的IV附在整段密文的前16字节

### AES CBC模式填充预言攻击(Padding Oracle Attack)

获取密文对应的明文 以及构造任意明文的密文 shiro满足漏洞的利用条件:

- 有完整密文
- 能向服务器发送修改后的密文触发解密
- 服务器响应能够判断解密是否成功,失败的原因时padding异常

###  PKCS#7 填充规则

一般CBC模式分组大小为16字节 128bit 所以不足16byte的部分需要填充 padding

PKCS5/7的填充规则:缺少n个byte, 则填充n个值为n的字节

### AES CBC 加密模式逻辑

- AES加密(明文块1 异或 IV) = 密文块1
- AES加密(明文块2 异或 密文块1) = 密文块2
- AES加密(明文块3 异或 密文块2) = 密文块3

- AES加密(明文块i 异或 密文块i-1) = 密文块i

> 由明文块1和IV向量决定后续的密文


### AES CBC模式 解密

- 明文块1 = AES解密(密文块1) 异或 IV
- 明文块2 = AES解密(密文块2) 异或 密文块1
- 明文块3 = AES解密(密文块3) 异或 密文块2

- 明文块i = AES解密(密文块i) 异或 密文块i-1


0000 0000 0000 0000 -> 1234 1234 1234 1234

> 异或可逆: 如果A XOR B = C, 那么A XOR C = B, 同样B XOR C = A

> 密文块i-1可控, 确定的明文块i, 可以构造出`AES解密(密文块i)`的值


### 利用padding是否合法 

整个流程看作盲注过程, 真假的依据时server对padding校验是否抛异常

正常padding 1个0x01 2个0x02 3个0x03 ... 

有连续的密文c0,c1,c2 且c0为原IV向量, 明文p 解密函数D() 密文块16字节

p2 = D(c2) xor c1 分组加密字节一一对应

p2[15] = D(c2)[15] xor c1[15]

#### 爆破最后一个字节 padding 1个0x01

将c2[0]-c2[14]设置乱码 此时正确的padding p2[15] = 0x01

通过遍历c1[15] 8bit 256种可能值 向server发送 c0 + `c1[0]...c[14] c[15]` + c2 

响应无异常时padding正确, 确定p2[15] = 0x01 = D(c2)[15] xor c1[15]

爆破出 即中间值D(c2)[15] = 0x01 xor c1[15]

> 记录`D(c2)[15]` `p2[15]`值确定

#### 爆破倒数第二个字节 padding 2个0x02

xxxx xxxx xxxx xx22

将c2[0]-c2[13]设置乱码 

c2[15]的值设置为 `D(c2)[15]` 异或 `0x02` 

便利c1[14] 发送到server观察响应 没有异常padding校验通过

p2[14] = 0x02 = D(c2)[14] xor c1[14]

爆破出 D(c2)[14] = 0x02 xor c1[14]

> 记录`D(c2)[14]` `p2[14]` 确定


#### 构造任意明文

在原有密文的后方追加伪造密文 来构造任意明文

shiro构造用户请求凭证时 从cookie字段RememberMe读取Base64编码的加密数据

解密后反序列化校验凭证有效期

在利用padding oracle攻击时 保证padding正确的同时还要确保java反序列化流程顺利

在java序列化数据尾部追加任意数据不会报错 

AES解密时从第一分组开始 (第0分组默认时IV) 解密时先解密当前分组密文 再与上一段密文异或 得到明文

由于受到前一个分组的影响 所以构造明文时从最后一个分组开始生成

最后一个分组C 任意赋值全0 利用padding oracle求分组c的中间值=AES解密(key,C)

通过遍历前一个分组c_prev 求分组c的中间值

每位发送的cookie值: base64(原RememberMe + c_prev + c)

最后将分组c的中间值与分组c对应明文分组p异或 即固定前一个分组的密文

将固定的密文作为下一轮求中间值的C 


## shiro

### org.apache.shiro.web.filter.mgt.DefaultFilter

shiro预置的filter

```java
    anon(AnonymousFilter.class),
    authc(FormAuthenticationFilter.class),
    authcBasic(BasicHttpAuthenticationFilter.class),
    logout(LogoutFilter.class),
    noSessionCreation(NoSessionCreationFilter.class),
    perms(PermissionsAuthorizationFilter.class),
    port(PortFilter.class),
    rest(HttpMethodPermissionFilter.class),
    roles(RolesAuthorizationFilter.class),
    ssl(SslFilter.class),
    user(UserFilter.class); //解析RememberMe 恢复用户session
```

### org.apache.shiro.web.filter.authc.UserFilter

filter子类 通过isAccessAllowed方法 判断是否执行filter逻辑

```java
protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
    if (this.isLoginRequest(request, response)) {
        return true;
    } else {
        Subject subject = this.getSubject(request, response);
        return subject.getPrincipal() != null;
    }
}
```

如果当前路径时ini文件 spring bean配置的login路径 跳过

### org.apache.shiro.mgt.SecurityManager#createSubject 

给当前线程绑定subject 为null则创建

```java
//org.apache.shiro.mgt.DefaultSecurityManager#createSubject 
//预置默认的DefaultSecurityManager
public Subject createSubject(SubjectContext subjectContext) {
        SubjectContext context = this.copy(subjectContext); //为每个线程复制一份context
        context = this.ensureSecurityManager(context); // 保存SecurityManager
        context = this.resolveSession(context); //从cookie的sessionid恢复用户凭证
        context = this.resolvePrincipals(context);//从已经构建的context解析凭证 当前用户的登录信息
        Subject subject = this.doCreateSubject(context);
        this.save(subject);
        return subject;
    }
```

```java
//org.apache.shiro.mgt.DefaultSecurityManager#resolvePrincipals
//恢复用户凭证 凭证报错用户登录信息和权限校验
protected SubjectContext resolvePrincipals(SubjectContext context) {
        PrincipalCollection principals = context.resolvePrincipals();
        if (isEmpty(principals)) {
            log.trace("No identity (PrincipalCollection) found in the context.  Looking for a remembered identity.");
            principals = this.getRememberedIdentity(context); //无法从session回复用户 走RemembereMe
            if (!isEmpty(principals)) {
                log.debug("Found remembered PrincipalCollection.  Adding to the context to be used for subject construction by the SubjectFactory.");
                context.setPrincipals(principals);
            } else {
                log.trace("No remembered identity found.  Returning original context.");
            }
        }
```

### org.apache.shiro.web.mgt.CookieRememberMeManager

cookie key DEFAULT_REMEMBER_ME_COOKIE_NAME = "rememberMe";

getRememberedSerializedIdentity从cookie读取 RemembereMe数据

### org.apache.shiro.mgt.AbstractRememberMeManager#convertBytesToPrincipals

AES解密 反序列化