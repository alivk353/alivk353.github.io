# 主角是JWT--JSON Web Token

## session 传统的用户认证机制

由于HTTP是无状态的协议，无法判断请求究竟是来自哪一个用户，才会有将sessionId放在cookie中传统认证机制

- 通常保存在内存中。随着用户的增加，服务器的负担也在增加
- 分布式的微服务应用session需要在不同服务器上同步，开销增加
- 存在csrf危险

## JWT

是一串带有用户认证信息的加密字符串，由3部分构成

- header
- payload
- signature