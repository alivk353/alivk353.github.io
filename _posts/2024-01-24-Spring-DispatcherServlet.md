---
title: Spring DispatcherServlet
date: 2024-01-24 13:30:00 +0800
categories: [record]
tags: [all]
---

入口 **org.springframework.web.servlet.DispatcherServlet#doDispatch**

当 Tomcat 接收到请求并交给 Spring 的 `DispatcherServlet`

寻找处理器：DispatcherServlet 根据 URL 找到对应的 HandlerMethod `mappedHandler = this.getHandler(processedRequest);`

获取适配器 `HandlerAdapter ha = this.getHandlerAdapter(mappedHandler.getHandler());`

执行适配器 `mv = ha.handle(processedRequest, response, mappedHandler.getHandler());`

解析Controller参数 `HandlerMethodArgumentResolverComposite#resolveArgument`

反射创建 Controller 方法参数中的 Bean 实例 `ModelAttributeMethodProcessor#resolveArgument`

`ServletModelAttributeMethodProcessor#bindRequestParameters`

检查规范化参数 `org.springframework.web.bind.WebDataBinder#doBind`

参数绑定到bean `org.springframework.validation.DataBinder#doBind`:

```java
    protected void doBind(MutablePropertyValues mpvs) {
        this.checkAllowedFields(mpvs);
        this.checkRequiredFields(mpvs);
        this.applyPropertyValues(mpvs);
    }
```

Disallowed Fields 检查：过滤掉黑名单字段（如 class.*）

Required Fields 检查：检查必填项

PropertyAccessor 赋值：最终通过反射调用 Setter 或直接修改 Field

调用setter `org.springframework.beans.BeanWrapperImpl.BeanPropertyHandler#setValue`


### 获取Spring Web的核心容器 WebApplicationContext

#### 方式一 基于请求上下文 (RequestContextHolder)

获取 Reuqest `RequestContextHolder.getRequestAttributes()` Spring 会利用 ThreadLocal 存储当前线程的请求属性。通过这个方法可以抓取到当前正在处理的 Request 对象

获取 ServletContext: 从 Request 中拿到 Session，再从 Session 中拿到 ServletContext

```java
ServletContext servletContext = RequestContextHolder.getRequestAttributes().getRequest().getSession().getServletContext()

WebApplicationContext webContent = WebApplicationContextUtils.getWebApplicationContext(servletContext)
```

WebApplicationContextUtils: 这是 Spring 提供的官方工具类。它通过 ServletContext 中存储的特定属性键（org.springframework.web.context.WebApplicationContext.ROOT）来提取出 Spring 容器。


简写同理:

```java
WebApplicationContext context = (WebApplicationContext)RequestContextHolder.currentRequestAttributes().getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT", 0);
```

#### 方式二 基于 LiveBeansView

LiveBeansView : Spring 用于图形化展示 Bean 关系的监控类


