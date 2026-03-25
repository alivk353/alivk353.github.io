---
title: CTF Tricks Record
date: 2023-03-16 13:30:00 +0800
categories: [record]
tags: [all]
---

### java.security.policy

-Djava.security.policy 是一个系统属性，用于指定**安全策略文件（Policy File）**的路径。它是 Java 沙箱机制（Sandbox）的核心组成部分，决定了代码在运行时拥有哪些权限（如读写文件、访问网络等）

```java
// 授予所有代码基本权限
grant {
    permission java.util.PropertyPermission "java.version", "read";
};

// 授予特定路径下的代码特定权限
grant codeBase "file:/home/app/lib/-" {
    permission java.io.FilePermission "/tmp/*", "read,write";
    permission java.net.SocketPermission "localhost:1024-", "listen,resolve";
};

// 配置不出网策略
grant {
    permission java.lang.RuntimePermission "*";
    permission java.io.FilePermission "<<ALL FILES>>", "read,write,delete,execute";
    permission java.util.PropertyPermission "*", "read,write";
    permission java.net.NetPermission "*";
    permission java.security.SecurityPermission "*";
    permission javax.security.auth.AuthPermission "*";
    permission java.lang.reflect.ReflectPermission "*";

    permission java.net.SocketPermission "*:*", "accept,listen,resolve";
};
```
### spring路由匹配大小写不敏感

PathMatchConfigurer.setCaseSensitive(false)

设置**Pathmacher.caseSensitive = false** 匹配路由path调用`equalsIgnoreCase`

equalsIgnoreCase内部调用**String.regionMatches**按字节先转换大小写在比较:

```java
char u1 = Character.toUpperCase(c1);
char u2 = Character.toUpperCase(c2);
if (u1 == u2) continue; // 第一次尝试：转大写比

// 第二次尝试：为了小语种等特殊情况，再转小写比
if (Character.toLowerCase(u1) == Character.toLowerCase(u2)) {
    continue;
}
```

char经过两次补偿转换:通过先统一升到大写，再降回小写 强行打通那些在 Unicode 映射表里路径怪异的字符分支

在Java中 某些特殊字符 大小写转换并不总是对称的 一些特殊的 unicode 字符 大小写转换的时候会出现差异 比如字符"ı"转大写之后会变成`"I"` 字符"ſ"转换大写之后会变成`"S"`

```java
    "ı".toUpperCase().equals("I"); //true
    "ſ".toUpperCase().equals("S"); //true
```

经典的土耳其语 I问题 主要针对单字符char: 在土耳其语中，大写的` I `小写后是` ı `(无点i) 小写的` i `大写后是` İ `(带点大写I) 

> 正则表达式在开启?i大小写不敏感和?u的时候 会进行先转大写再转小写

### GET请求中 同名parm的解析方式

`GET?param=arg1&param=arg2`的处理方式

当一次请求中有多个参数名字都是`param`时 `spring controller`和Servlet接口处理方式不同

- Servlet接口`request.getParameter("param")` 去第一个url的值

- Controller中获取到的url将是所有url参数以逗号 作为连接符拼接成的完整字符串


### 包含脏字符但又合法的jar/zip

- https://t.zsxq.com/05jfs
- https://t.zsxq.com/UBIMZrB
- https://github.com/phith0n/PaddingZip