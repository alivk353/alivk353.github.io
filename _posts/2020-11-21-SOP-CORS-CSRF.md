# 同源策略 SOP

使加载的文档DOM不会被污染，不同源的javascript运行环境独立，不同源的JS不允许互相访问,cookie,localStorage不可以读取

非同源情况下不允许dom操作,发送AJAX请求

当两个页面的协议，域名和端口相同，就可认为同源

## 跨域资源访问

### 相同二级域名下 document.domain

在不设置docuemnt.domain的情况下`a.cc.com`与`b.cc.com`之间非同源,不可以js互相访问

需要在两个页面同时设置`document.domain=cc.com`在可以实现同源

如果只是单一的一方设置,另一方不设置则同源不成立

> chrome下document.domain允许随意更改

#### xss

如果在`a.cc.com/index.html`存在xss漏洞,且`index.cc.com`设置`docmian="cc.com"`时

可以在自己的网站上iframe存在xss漏洞的页面,并设置domain="cc.com",然后再iframe加载`http://a.cc.com/index.html`进行dom修改.

self-xss也可以尝试在自己的网站诱导用户输入,并触发xss

### window.postMessage

html5新增API,跨文档通信API,这个API为window对象新增了一个window.postMessage方法，允许同浏览器下跨窗口通信，不论这两个窗口是否同源。

与jsonp相比,postmessage在前端页面之间的即时通信,jsonp是与跨域服务端通信获取数据.

父窗口http://a.com向子窗口http://b.com发消息，调用postMessage方法就可以:

```js
window.postMessage("hello,world","http://www.a.com/index.html")
```

方法的第一个参数是具体的消息内容，第二个参数是接收消息的窗口的源（origin），即"协议 + 域名 + 端口"。也可以设为*，表示不限制域名，向所有窗口发送。

父窗口和子窗口都可以通过message事件，监听对方的消息。

```js
window.addEventListener('message', function(e) {
  console.log(e.source); //发送消息的窗口
  console.log(e.origin);//调用postMessage时消息发送方窗口的 origin
  console.log(e.data);
},false);
```

一个例子

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>1.html</title>
    <script>
        function send() {
            // var ifs1 = window.frames[0];
            // console.log(window.frames[0]);
            // var ifs1 = window.document.getElementById('ifs1');
            // console.log(ifs1.src);
            var ifs1 = document.getElementById('ifs1').contentWindow;

            var message = 'Hello!  The time is: ' + (new Date().getTime());
            var r = ifs1.postMessage(message, 'http://localtest.com:8888');
            console.log(window.origin);
        }
    </script>
</head>

<body>
    <h1>11111 page</h1>

    <iframe src="http://localtest.com:8888/2.html" frameborder="0" id="ifs1"></iframe>
    <input type="button" value="Update 2.html" onclick="send()"></input>
</body>

</html>
```


```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>2.html</title>
    <script>
        
        window.addEventListener("message", function (e) {
            // console.log(e.source);
            console.log(e.data);
            console.log(e.origin);
        });
        
    </script>
</head>
<body>
    <h1>22222 page</h1>

</body>
</html>
```

> 在父页面1.html中iframe子页面2.html要手动在2.html的js注册message事件结束,在手动触发postmessage()否则会报错.

安全问题:

- postMessage('敏感信息',*)函数的第二个参数为空时,可以伪造接收端获取e.data,也可以e.source获取发送端的窗口句柄
- onmessage事件如果没有对e.origin做判断,或者直接eval(e.data)造成新的xss

### 通过锚点

子iframe通过监听hashchange事件

### window.name

为window.name赋值后,无论是否同源只要在同一窗口下,都可以读取这个值

### AJAX跨域 CORS Cross Oigin Resource Sharing

解决页面与非同源web服务端的数据共享问题

跨域是为了在正常业务情况下,解决sop限制的一种途径,cors则是浏览器和服务器后端针对跨域请求的协商

协商的结果就是服务器会在response的header中添加`Access-Control-Allow-Origin`字段,而浏览器也会根据这个字段解锁同源策略SOP

#### origin

请求时的header添加origin字段,表示这个请求来自哪个域,服务器根据这个值判断是否同意这次请求并给出响应

对于成功的响应包的header会包含以下字段,浏览器根据这些字段判断请求成功

- Access-Control-Allow-Origin: http://xxx.com 表示服务器允许处理请求的域名,可以为*表示接受任意域名
- Access-Control-Allow-Credentials: true 表示cors请求是是否携带cookie 
- Access-Control-Expose-Headers: FooBar 该字段可选。CORS请求时，XMLHttpRequest对象的getResponseHeader()方法只能拿到6个基本字段：Cache-Control、Content-Language、Content-Type、Expires、Last-Modified、Pragma。如果想拿到其他字段，就必须在Access-Control-Expose-Headers里面指定。上面的例子指定，getResponseHeader('FooBar')可以返回FooBar字段的值。

#### CORS和cookie

只是在响应header设置`Access-Control-Allow-Credentials: true`浏览器在发起xhr请求时依旧不会发行cookie,需要手动设置withCredentials属性

```javascript
var x = new XMLHttpRequest();
x.withCredentials = true;

```

> 当`Access-Control-Allow-Origin`为*时,无论withCredentials为任何值,浏览器都不会发送cookie和响应set-cookie

#### 简单请求

会有一种情况浏览器会直接将request发送至服务器:

- 请求方法使用 GET、POST 或 HEAD
- Content-Type 设为 application/x-www-form-urlencoded、multipart/form-data 或 text/plain

一旦不满足上面两个条件则会发起预检request


#### 预检请求

不符合上面简单请求条件的request会被浏览器拦截,会先发送预检option请求询问服务器是否接受当前源的跨域请求

例如`application/json `的post请求会被浏览器拦截,发送pus请求也会内拦截

当浏览器发起GET,POST,HEAD之外的跨域请求时,会先发送一个预检请求,询问服务器能否处理请求

预检请求方法为OPTIONS,origin表示请求来自哪个域 ,`Access-Control-Request-Method`表示本次请求的方法,`Access-Control-Request-Headers`表示本次请求自定义添加的字段

```text
OPTIONS /put HTTP/1.1
host:api.com
origin:http://a.com
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: X-Custom-Header
......
```

##### 预检的响应

服务器根据origin,`Access-Control-Request-Method`,`Access-Control-Request-Headers`判断是否响应这个请求,如果允许侧返回相应字段

```text
HTTP/1.1 200 OK
data:
server:
Access-Control-Allow-Origin: http://a.com 
Access-Control-Allow-Methods: GET, POST, PUT
Access-Control-Allow-Headers: X-Custom-Header

```
如果服务器不允许此请求则不会附带上述字段

# CORS in JAVA

因为设置`Access-Control-Allow-Origin:*`的同时`Access-Control-Allow-Credentials`的值不能为true,否则浏览器会报错

```
已拦截跨源请求：同源策略禁止读取位于 ‘http://localhost:9000/cors/index’ 的远程资源。（原因：凭据不支持，如果 CORS 头 ‘Access-Control-Allow-Origin’ 为 ‘*’）。
```

所以当`Access-Control-Allow-Origin:*`的同时`Access-Control-Allow-Credentials:false`这样任何网站都可以获取该服务端的任何数据

在spring中存在多种配置cors请求的方式:

### spring security

全局配置只允许特定源的跨域请求:

```java
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.csrf().disable();
        http.cors();
        http.headers().disable();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("localtest.com"));
        configuration.setAllowedMethods(Arrays.asList("GET","POST"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/cors/**", configuration);
        return source;
    }
}
```

### 在方法内单独配置

如下的配置的网站的Access-Control-Allow-Origin的设置并不是固定的,而是根据用户跨域请求header的Origin动态设置的 

这时,不管Access-Control-Allow-Credentials设置true还是false

任何网站都可以发起请求,并读取对这些请求的响应:

```java
    @GetMapping("/origin")
    public String getUserInfo(HttpServletRequest request, HttpServletResponse response) {
        String origin = request.getHeader("origin");
        response.setHeader("Access-Control-Allow-Origin", origin); // set origin from header
        response.setHeader("Access-Control-Allow-Credentials", "true");  // allow cookie
        return userinfo;
    }
```


### spring的@CrossOrigin注解

针对当一方法的配置:

在DefaultCorsProcessor.class类中有spring对OPTION预检请求的支持

也可以重重写在DefaultCorsProcessor类的checkOrigin来获取更自定义的配置

```java
    @CrossOrigin(origins = {"http://localtest.com"})
    @GetMapping("/corsOrigin")
    public String corsOrigin(){
        return info;
    }
```
###  WebMvcConfigurer

Spring也支持全局来配置cors:



## JSONP

利用`<script>`标签的跨域加载特性进行数据交换,缺点是只能使用GET方法,不能进行复杂的数据传输

JSONP请求时提供一个callback参数,服务器支持jsonp跨域请求的话,会将数据放在callback函数的参数位置

客户端在会执行`script`的内容,直接调用自身已经加载的callback函数使用数据

### jsonp劫持

构造恶意的jsonp调用页面,诱导用户访问触发jsonp请求

增加referer验证和随机token

 
## cookie

由于cookie机制的诞生早于同源策略,所以cookie有一套自己的安全机制,这也是很多前端安全隐患的原因

浏览器会根据cookie机制的4个属性决定此次请求是否携带cookie,以及js当前页面的js能否读取cookie

- domain 可以是set-cookie字段设置的域,也可以是js手动设置
- path
- http-only 设置Cookie在哪个PATH下才能被读取
- secure 设置Cookie只能在https页面中被传输与读取


JavaScript在哪些情况下，能或不能读取`document.cookie`：

- `http://example.com`可以读取`http://example.com:8080`的Cookie
- `https://example.com`可以读取`http://example.com`的Cookie
- `cookie_secure=true`的情况下，`http://example.com`不能读取`https://example.com`的Cookie
- `cookie_httponly=true`的情况下，JavaScript不能读取这个Cookie
- `cookie_path=/admin/`的情况下，`http://example.com/`不能读取`http://example.com/admin/`的Cookie
- `cookie_domain=.example.com`的情况下，`http://a.example.com`可以读取`http://b.example.com`的Cookie

### cookie的sameSite属性 

cookie的SameSite属性用来限制第三方Cookie，从而减少安全风险(防止CSRF)

SameSite可以有下面三种值：

- Strict 仅允许一方请求携带Cookie，即浏览器将只发送相同站点请求的Cookie，即当前网页URL与请求目标URL完全一致。
- Lax 允许部分第三方请求携带Cookie
- None 无论是否跨站都会发送Cookie

在chrome 80版本之后，谷歌把cookie的SameSite属性，从None改成了Lax

# CSRF

- 同源策略（Same-origin policy，简称 SOP）
- 跨站请求伪造（Cross-site request forgery，简称 CSRF）
- 跨域资源共享（Cross-Origin Resource Sharing，简称 CORS）


浏览器在SOP策略下允许加载iframe,img,js文件,也就是说SOP允许通过hHTML标签跨域加载数据,但是不允许开发者和用户对其进行操作

如果要在浏览器下发送ajax的跨域的get/post请求,会被SOP限制,限制的方法不是拦截request而是拦截response

几种常见的,涉及SOP的,跨域场景:

- 开发过程中需要请求第三方的数据接口
- 在页面内引入iframe,以及iframe与父页面的通信
- 对跨域获取的img进行修改操作

ajax的跨域方法:

- jsonp 
- cors 通过在服务器后端进行origin设置白名单 来限制跨域请求

iframe的跨域方法:

- window.location.hash
- window.name
- postMessage


### 跨站请求伪造 CSRF

是指在A网站正常登录后,cookies存储凭证信息,在B网站调用A网站接口进行操作,请求A时浏览器会自动带上cookie

在B网站上调用A的接口明显会被SOP策略限制,但是CSRF漏洞要达到的目的不会被SOP影响,有两点:

- SOP允许HTML标签跨域加载数据,CSRF可以利用img提交GET,from提交POST
- SOP不会拦截跨域请求而是会拦截对response的解析,但此时CSRF请求已经被服务器解析

所以SOP不能作为CSRF的防范方法.

> 那么SOP的终极目的就是不让你用js对跨域request的response进行操作

### CSRF的防范方法

SOP的一些策略对csrf还是起到了一些限制:

sop策略下发起跨域请求虽然会自动带上cookie 但是却无法使用js读取cookie内的信息

所以应对CSRF的思路可以是:

可以将csrfToken存放在cookie中,在调用接口时js将其从cookie中读取,放到query,body,header中,在后端验证参数或者字段,如果正确那一定是本域发来的请求

当然也可以在后端渲染dom是将token写入页面


#### sameSite 

cookie的SameSite属性用来限制第三方Cookie，从而减少安全风险(防止CSRF)

SameSite可以有下面三种值：

- Strict 仅允许一方请求携带Cookie，即浏览器将只发送相同站点请求的Cookie，即当前网页URL与请求目标URL完全一致。
- Lax 允许部分第三方请求携带Cookie
- None 无论是否跨站都会发送Cookie

在chrome 80版本之后，谷歌把cookie的SameSite属性，从None改成了Lax

## 跨站的解释

- `http://a.demo.com`和`http://b.demo.com`属于同站
- `http://a.demo.com`和`http://a.demo2.com`属于跨站

> 注意和跨域做比较: `http://a.demo.com`和`http://b.demo.com`属于跨域

## CSRF in JAVA

搭建目前常见springboot的测试环境 spring security提供两种方法防范csrf:

- csrfRoken
- 在cookie中设置sameSite属性 `Set-Cookie: JSESSIONID=randomid; Domain=bank.example.com; Secure; HttpOnly; SameSite=Lax`

以下使用spring-security的csrf模块配合thymeleaf模板进行csrf校验:






