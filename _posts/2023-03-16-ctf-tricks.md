---
title: CTF Tricks Record
date: 2023-03-16 13:30:00 +0800
categories: [record]
tags: [all]
---

### GET请求中 同名parm的解析方式

`GET?param=arg1&param=arg2`的处理方式

当一次请求中有多个参数名字都是`param`时 `spring controller`和Servlet接口处理方式不同

- Servlet接口`request.getParameter("param")` 去第一个url的值

- Controller中获取到的url将是所有url参数以逗号 作为连接符拼接成的完整字符串


### 包含脏字符但又合法的jar/zip

- https://t.zsxq.com/05jfs
- https://t.zsxq.com/UBIMZrB
- https://github.com/phith0n/PaddingZip