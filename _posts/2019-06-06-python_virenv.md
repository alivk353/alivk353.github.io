# Python virtualenv

1. python
    - linux包路径:/usr/local/lib

2. install
    - pip install virtualenv virtualenvwrapper
    - pip freeze 
3. 环境变量
    - export VIRTUALENVWRAPPER_PYTHON=/usr/bin/python3 >> .bashrc
    - export WORKON_HOME=$HOME/.virtualenvs >> .bashrc
    - /usr/local/bin/virtualenvwrapper.sh

    生效.bashrc
    - source .bashrc

4. create virenv
    - mkvirtualenv -p python3 blog_django_2.2

    退出当前虚拟环境
    - deactivate
    进入虚拟环境
    - workon blog_django_2.2

    删除环境
    - rmvirtualenv blog_django_2.2

# WSGI Web Server Gateway Interface

WSGI是一种Python标准，它的接口定义非常简单，它只要求Web开发者实现一个函数:

```python
def application(environ, callback):
    start_response('200 OK', [('Content-Type', 'text/html')])
    return [b'<h1>Hello,world.</h1>']
```

上面的application()函数就是符合WSGI标准的一个HTTP处理函数，接收两个参数：

- environ：一个包含所有HTTP请求信息的dict对象。
- callback：一个发送HTTP响应的回调函数，用来告知WSGI服务器该请求的响应码和header信息。

整个application()函数本身没有涉及到任何解析HTTP的部分，我们只需要用python来编写body中的html数据。

## uWSGI

uWSGI是一种WSGI实现:
> the web client <-> the web server <-> the socket <-> uwsgi <-> Django

### 安装uWSGI以及Python支持

在基于Debian的发行版上
```
apt-get install build-essential python3.7-dev
pip install uwsgi
```

### 运行uWSGI

```bash
uwsgi --http 0.0.0.0:8080 
    --home /home/blog/Env/myproject 
    --chdir /home/blog/myproject -w myproject.wsgi
    --module django_blog.wsgi
```

- module xxxx.wsgi: 加载指定的wsgi模块
- --home 指定虚拟环境路径
- --chdir 指定项目代码路径
> uWSGI将http请求解析后交给django程序，会直接在项目的urls.py匹配路径，由于在urls.py内没有对静态文件做路由，导致无法解析静态文件，这里需要nginx来解决静态文件的处理。

### custom uwsgi_django_blog.ini

```bash
[uwsgi]
chdir = /home/blog_test/django_blog
home = /home/blog_test/django_blog
module = django_blog.wsgi:application

master = True
process = 4
harakiri = 60 #请求超时时间
max_requests = 5000

socket =  127.0.0.1:8001
uid = 33
god = 33

pidfile = /home/blog_test/uwsgi/master.pid # 用来重启和停止uwsgi服务
stats=%(chdir)/uwsgi/uwsgi.status # 用来查看uwsgi状态
daemonize = /home/blog_test/django_blog.log # 后台运行设置日志文件
vacuum = True
```

启动
- uwsgi --ini uwsgin.ini

重启和停止
- uwsgi --reload uwsgi/uwsgi.pid
- uwsgi --stop uwsgi/uwsgi.pid

查看状态
- uwsgi --connect-and-readuwsgi/uwsgi.status

# Nginx

## config

```bash
tree /etc/nginx
.
├── conf.d
├── nginx.conf
├── sites-available
│   ├── default
│   └── django_blog.conf
├── sites-enabled
│   ├── default -> /etc/nginx/sites-available/default
│   └── django_blog.conf -> /etc/nginx/sites-available/django_blog.conf
├── uwsgi_params
└── win-utf
```

```bash
vim /etc/nginx/sites-available/django_blog.conf

server {
    listen 80;
    server_name *;
    charset utf-8;

    client_max_body_size 75M;

    location /static {
        alias /home/blog_test/django_blog/static;
    }

    location /media {
        alias /home/blog_test/django_blog/media;
    }

    location / {
        uwsgi_pass 127.0.0.1:8001;
        include /etc/nginx/uwsgi_params;
    }
}
```

> 这里删除sites-enabled下的默认配置文件软连接，也可以直接覆盖default。

# Docker


## Dockerfile

Dockerfile分为四部分：基础镜像信息、维护者信息、镜像操作指令、容器启动执行指令。第一部分必须指明基础镜像名称；第二部分通常说明维护者信息；第三部分是镜像操作指令，例如RUN指令，每执行一条RUN 指令，镜像添加新的一层，并提交；第四部分是CMD指令，指明运行容器时的操作命令。

```bash
#第一行必须指定基础镜像信息
FROM python:3.7
# 维护者信息
MAINTAINER docker_user docker_user@email.com
# 镜像操作指令 每执行一条RUN 指令，镜像添加新的一层，并提交；
RUN yum install -y nginx
# 容器启动执行指令
CMD /usr/sbin/nginx
```

### RUN

在镜像的构建过程中执行特定的命令，并生成一个中间镜像。

```bash
#shell格式
RUN <command>
#exec格式
RUN ["executable", "param1", "param2"]
```

RUN命令将在当前image中执行任意合法命令并提交执行结果。命令执行提交后，就会自动执行Dockerfile中的下一个指令。
RUN指令创建的中间镜像会被缓存，并会在下次构建中使用。如果不想使用缓存镜像，可以在构建时指定--no-cache参数，如：docker build --no-cache。

### CMD指令

CMD用于指定在容器启动时所要执行的命令。CMD有三种写法：

```bash
CMD ["executable","param1","param2"]
CMD ["param1","param2"]
CMD command param1 param2
```

### VOLUME

指令用于创建挂载点，即向基于所构建镜像创始的容器添加卷.

```bash
VOLUME ["/data"]
```

VOLUME可以将源代码、数据或其它内容添加到镜像中，而不提交到镜像中，并使多个容器间共享数据。

## docker compose

Docker-Compose将所管理的容器分为三层，分别是工程（project），服务（service）以及容器（container）。

Docker-Compose运行目录下的所有文件（docker-compose.yml，extends文件或环境变量文件等）组成一个工程，若无特殊指定工程名即为当前目录名。一个工程当中可包含多个服务，每个服务中定义了容器运行的镜像，参数，依赖。一个服务当中可包括多个容器实例.

### docker-compose build

构建（重新构建）项目中的服务容器。

```bash
docker-compose build [options] [--build-arg key=val...] [SERVICE...]
```

- –compress 通过gzip压缩构建上下环境
- –force-rm 删除构建过程中的临时容器
- –no-cache 构建镜像过程中不使用缓存
- –pull 始终尝试通过拉取操作来获取更新版本的镜像
- -m, –memory MEM为构建的容器设置内存大小
- –build-arg key=val为服务设置build-time变量

> 服务容器一旦构建后，将会带上一个标记名。可以随时在项目目录下运行docker-compose build来重新构建服务


### docker-compose up

```bash
docker-compose up [options] [--scale SERVICE=NUM...] [SERVICE...]
```

- -d 在后台运行服务容器
- -no-deps 不启动服务所链接的容器
- -force-recreate 强制重新创建容器，不能与–no-recreate同时使用
- -no-recreate 如果容器已经存在，则不重新创建，不能与–force-recreate同时使用
- -no-build 不自动构建缺失的服务镜像
- -build 在启动容器前构建服务镜像
- -abort-on-container-exit 停止所有容器，如果任何一个容器被停止，不能与-d同时使用
- -t, -timeout TIMEOUT 停止容器时候的超时（默认为10秒）
- -remove-orphans 删除服务中没有在compose文件中定义的容器

### docker-compose pull

拉取服务依赖的镜像。

### docker-compose ps

列出项目中目前的所有容器

```bash
docker-compose ps [options] [SERVICE...]
docker-compose ps
```

### docker-compose down

停止和删除容器、网络、卷、镜像。

```bash
docker-compose down [options]
docker-compose down
```

- –rmi type，删除镜像，type必须是：all，删除compose文件中定义的所有镜像；local，删除镜像名为空的镜像
- -v, –volumes，删除已经在compose文件中定义的和匿名的附在容器上的数据卷
- –remove-orphans，删除服务中没有在compose中定义的容器

### docker-compose run

在指定服务上执行一个命令。

```bash
docker-compose run [options] [-v VOLUME...] [-p PORT...] [-e KEY=VAL...] SERVICE [COMMAND] [ARGS...]
docker-compose run ubuntu ping www.baidu.com # 在指定容器上执行一个ping命令。
```

### docker-compose scale

设置指定服务运行的容器个数。通过service=num的参数来设置数量

```bash
docker-compose scale web=3 db=2
```

### docker-compose port

显示某个容器端口所映射的公共端口。

```bash
docker-compose port [options] SERVICE PRIVATE_PORT
```

- –protocol=proto，指定端口协议，TCP（默认值）或者UDP
- –index=index，如果同意服务存在多个容器，指定命令对象容器的序号（默认为1）

### links
链接到其它服务中的容器。使用服务名称（同时作为别名），或者“服务名称:服务别名”（如 SERVICE:ALIAS）
```yaml
links:
    - db
    - db:database
    - redis
# 使用别名将会自动在服务容器中的/etc/hosts里创建。例如：
172.17.2.186  db
172.17.2.186  database
172.17.2.187  redis
```

## docker-compose.yml

docker-compose.yml一般包含version、services、networks 三大部分

```yaml
version: '2'

services:
  nginx:
    image: nginx
    ports:
      - '8080:80'
    container_name: "web1"
  django:
    build:
      content: /path/to/DockerFile/dir
      dockerfile: /path/of/dokcerfile
    depends_on:
      - db
      - redis
    ports:
      - '8001:8001'

network:
  


```

- depends_on 用于解决容器的依赖、启动先后的问题。
- command 使用command可以覆盖容器启动后默认执行的命令。
- ports 用于映射端口的标签。使用host:container格式;只是指定容器的端口，宿主机会随机映射端口。
- expose 暴露端口，但不映射到宿主机，只允许能被连接的服务访问。
- volumes 用于挂载一个本机目录到容器，使用 [host:container]格式，或者使用[host:container:ro]格式，后者对于容器来说，数据卷是只读的，可以有效保护宿主机的文件系统。

```yaml
volumes:
  - /var/lib/mysql # 只是指定一个路径，Docker会自动在创建一个数据卷（这个路径是容器内部的）
  - /opt/data:/var/lib/mysql # 使用绝对路径挂载数据卷
  - ./cache:/tmp/cache # 以 Compose 配置文件为中心的相对路径作为数据卷挂载到容器。
  - ~/configs:/etc/configs/:ro # 使用用户的相对路径。
  - datavolume:/var/lib/mysql # 已经存在的命名的数据卷。
```

- volumes_from 从另一个服务或容器挂载其数据卷：

## 部署我的Django_blog

使用docker-compose管理整个工程，要设置各个服务之间的依赖关系和数据共享，构建的服务有：

- Nginx服务
- Web服务
- MySQL服务

### 目录结构

```bash
├── blog
│   ├── accounts
│   ├── blog
│   ├── comments
│   ├── django_blog
│   ├── Dockerfile
│   ├── gunicron.conf
│   ├── manage.py
│   ├── requirements.txt
│   ├── run.sh
│   ├── static
│   └── templates
├── docker-compose.yml
├── nginx
│   ├── django_blog.conf
│   └── Dockerfile
└── README.md
```

### Django配置文件

Dockerfile

```bash
FROM python:3.7 # 基于python3构建
RUN mkdir /blog
WORKDIR /blog
ADD . /blog
RUN pip install -i https://pypi.doubanio.com/simple/ -r requirements.txt
EXPOSE 80 8000 8001 5000
ENV SPIDER=/blog

```