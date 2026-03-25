---
title: Spring DispatcherServlet
date: 2020-12-27 13:30:00 +0800
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





