### 概述
微服务的核心是基于无状态的Http 的Rest服务，在这个章节中列举了几种常见的接口认证方案的原理及代码实现，通过对这些方案的了解，选择适项目的方案。

### 前提
本系列设计的代码运行环境如下
- jdk 1.6
- maven 3.2.1
- spring boot 1.5.9.RELEASE

### Http Basic
#### 说明
Basic认证是HTTP协议中规定的认证方式之一（另一种是Digest认证），这两种方式都属于无状态认证方式，即服务器端不会在会话中保存信息，客户端每次请求都要将用户名和密码放置在http header中发给服务器端

#### 示例
> Authorization: Basic YWRtaW46YWRtaW4= 

其中Authorization是Http  Header的名称，value必须是Basic开头，后面跟一个空格，空格后面是具体的值，格式为(base64(user:password))

#### 过程
- 客户端发送http(s)请求到服务器端，服务器端验证用户是否已经登录过了，如果没有登录，返回401 Unauthozied给客户端，并且在Response的Header中添加"WWW-Authenticate"
- 浏览器接收到401 Unauthozied后，会弹出登录框

    ![https://note.youdao.com/yws/public/resource/e5bb1aa758439bbedce6c5dd9a73a81c/xmlnote/EEB2EF9E4A6F4E90BC03003FF4C6E55C/76855](https://note.youdao.com/yws/public/resource/e5bb1aa758439bbedce6c5dd9a73a81c/xmlnote/EEB2EF9E4A6F4E90BC03003FF4C6E55C/76855)
- 用户在登录框中输入用户名密码后，浏览器会对用户名密码进行base64编码，编码规则为base64(name:password)，并把编码后的信息放在header中，Header中的数据示例如下
    > Authorization: Basic YWRtaW46YWRtaW4=
- 服务器接收到请求后，取出header中的认证信息，进行base64解码，然后做用户名密码的验证，进而做下一步的操作
#### 演示
发起请求--不带认证信息:

![https://note.youdao.com/yws/public/resource/e5bb1aa758439bbedce6c5dd9a73a81c/xmlnote/EEB2EF9E4A6F4E90BC03003FF4C6E55C/76855](https://note.youdao.com/yws/public/resource/e5bb1aa758439bbedce6c5dd9a73a81c/xmlnote/EEB2EF9E4A6F4E90BC03003FF4C6E55C/76855)


返回结果：
```
Status Code: 401 Unauthorized
Content-Length: 0
Date: Tue, 22 May 2018 05:19:35 GMT
Server: Apache-Coyote/1.1
WWW-Authenticate: Basic Realm="test"
```

输入用户名密码后，查看请求数据：
![https://note.youdao.com/yws/public/resource/e5bb1aa758439bbedce6c5dd9a73a81c/xmlnote/060C6AFCE2574EAB80D16C0E87773293/77036](https://note.youdao.com/yws/public/resource/e5bb1aa758439bbedce6c5dd9a73a81c/xmlnote/060C6AFCE2574EAB80D16C0E87773293/77036)

**注意**:当通过浏览器输入过一次正确的用户名密码后，再请求该链接，将不会弹出登录框登录，这是因为浏览器默认会技术正确的帐号密码，以后请求的时候会自动添加请求的header中了

#### 服务器端代码实现(基于Spring Boot)
请参考[http-basic](https://github.com/kwang2003/rest-auth/tree/master/http-basic)模块的代码实现