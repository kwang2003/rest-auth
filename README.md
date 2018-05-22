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

![https://note.youdao.com/yws/public/resource/e5bb1aa758439bbedce6c5dd9a73a81c/xmlnote/1C7D22AD8E134FB595D430F24E6A0733/77077](https://note.youdao.com/yws/public/resource/e5bb1aa758439bbedce6c5dd9a73a81c/xmlnote/1C7D22AD8E134FB595D430F24E6A0733/77077)

#### 服务器端代码实现(基于Spring Boot)
请参考[http-basic](https://github.com/kwang2003/rest-auth/tree/master/http-basic)模块的代码实现