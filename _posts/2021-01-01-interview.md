# 到时候了

## HTTPS 秘钥交换过程/四次握手

HTTPS = HTTP + SSL

- client请求server的443端口 (第一次握手)
- server发送证书(公钥)给client (第二次握手)
- client通过CA验证证书是否合法性,否,则弹出提示,是,则用公钥加密随机秘钥发送至server (第三次握手)
- server通过私钥解密出随机秘钥,以此作为对称加密的秘钥加密数据 (第四次握手)