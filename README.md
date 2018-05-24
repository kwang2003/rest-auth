### 0.概述
微服务的核心是基于无状态的Http 的Rest服务，在这个章节中列举了几种常见的接口认证方案的原理及代码实现，通过对这些方案的了解，选择适项目的方案。

#### 前提
本系列设计的代码运行环境如下
- jdk 1.6
- maven 3.2.1
- spring boot 1.5.9.RELEASE

### 1.Http Basic认证
#### 1.1 说明
Basic认证是HTTP协议中规定的认证方式之一（另一种是Digest认证），这两种方式都属于无状态认证方式，即服务器端不会在会话中保存信息，客户端每次请求都要将用户名和密码放置在http header中发给服务器端

#### 1.2 示例
> Authorization: Basic YWRtaW46YWRtaW4= 

其中Authorization是Http  Header的名称，value必须是Basic开头，后面跟一个空格，空格后面是具体的值，格式为(base64(user:password))

#### 1.3 过程

![https://note.youdao.com/yws/public/resource/e5bb1aa758439bbedce6c5dd9a73a81c/xmlnote/1C7D22AD8E134FB595D430F24E6A0733/77077](https://note.youdao.com/yws/public/resource/e5bb1aa758439bbedce6c5dd9a73a81c/xmlnote/1C7D22AD8E134FB595D430F24E6A0733/77077)

#### 1.4 服务器端代码实现
请参考[http-basic](https://github.com/kwang2003/rest-auth/tree/master/http-basic)模块的拦截器[HttpBasicInterceptor.java](http-basic/src/main/java/com/pachiraframework/httpbasic/interceptor/HttpBasicInterceptor.java)代码实现
```java
package com.pachiraframework.httpbasic.interceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import lombok.extern.slf4j.Slf4j;

import org.springframework.stereotype.Component;
import org.springframework.util.Base64Utils;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import com.google.common.base.Strings;

@Slf4j
@Component
public class HttpBasicInterceptor extends HandlerInterceptorAdapter {
	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
		// 从header中取Basic认证信息
		// Authorization: Basic YWRtaW46YWRtaW4=
		String auth = request.getHeader("Authorization");  
		log.info("auth:{}",auth);
		if(Strings.isNullOrEmpty(auth)){
			response.setStatus(401);
			response.addHeader("WWW-Authenticate", "Basic Realm=\"test\"");
			return false;
		}else{
			// 截取Basic 之后的字符
			String authInfo = auth.substring(6,auth.length());
			String userPassword = new String(Base64Utils.decodeFromString(authInfo));
			log.info(userPassword);
			String[] strs = userPassword.split(":");
			if(passwordMatch(strs[0], strs[1])){
				return true;
			}
			return false;
		}
	}
	
	private boolean passwordMatch(String user,String password){
		if("admin".equals(user) && "123456".equals(password)){
			return true;
		}
		return false;
	}
}

```

#### 1.5 运行代码
- 运行[Application.java](/http-basic/src/main/java/com/pachiraframework/httpbasic/Application.java)
- 访问链接：[http://localhost:8080/demo.json](http://localhost:8080/demo.json)
- 输入用户名密码（第一次访问时输入）admin  123456

### 2.HTTP Digest(摘要认证)
#### 2.1 说明
Digest认证是HTTP协议自带的另一种认证方式，可以看做是加强版的Basic认证， 使用随机数+密码进行md5，防止截取 header直接解码获得用户密码。Digest认证中用到的一些参数含义及说明|如下：
|参数名|含义|备注
|:-|:-|:-
|username|用户名|登录帐号
|password|密码|
|realm|领域|由服务器端返回，通常是域名
|method|请求方法|get/post/put/delete等
|nonce|服务器端生成并返回给客户端的随机字符串|
|nc|nonceCount|请求的次数,用于标记、计数、防止重放攻击
|cnonce|clientNonce|客户端发送给服务器端的随机数
|qop|质量保证参数，通常是auth或auth-init|影响摘要算法
|uri|请求的uri|举例   /order/list.html?a=b
|response|服务器端根据算法算出的摘要值|

#### 2.2 Digest算法
认证变量由如下变量组成（HA1、HA2、A1、及A2为字符串变量的名称）

HA1:
> HA1=MD5(A1)=MD5(username:realm:password)

HA2：
> 
> 如果qop为"auth"或空:
> 
> HA2=MD5(A2)=MD5(method:digestURI)
> 
> 如果qop为"auth-int"：
> 
> HA2=MD5(A2)=MD5(method:digestURI:MD5(entiryBody))

response：
> 如果qop为"auth"或"auth-int"：
>
> response=MD5(HA1:nonce:nonceCount:clientNonce:qop:HA2)
>
> 如果qop未指定:
> 
> response=MD5(HA1:nonce:HA2)

#### 示例
> Authorization: Digest username="admin", realm="testrealm@host.com", nonce="51522d56-17f2-45cb-9ba4-1feb7b3ef190", uri="/dir/index.html", response="3f9dbfd7d3a018a82a9fde3b044aa267", opaque="1153b141-2e9c-4126-bfe2-6dfbe2106573"

和Basic认证类似Digest是表示采用摘要认证
#### 2.3 过程
![https://note.youdao.com/yws/public/resource/e5bb1aa758439bbedce6c5dd9a73a81c/xmlnote/CBA530BAA3E44FBBB363FDC248BB2261/77441](https://note.youdao.com/yws/public/resource/e5bb1aa758439bbedce6c5dd9a73a81c/xmlnote/CBA530BAA3E44FBBB363FDC248BB2261/77441)
#### 2.4 服务器端代码实现(基于Spring Boot)
```java
package com.pachiraframework.httpdigest.interceptor;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import lombok.extern.slf4j.Slf4j;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.Maps;
import com.google.common.hash.Hashing;
import com.google.common.io.CharStreams;

/**
 * 实现<a href="https://tools.ietf.org/html/rfc2617">RFC 2617</a> 的
 * <a href="https://zh.wikipedia.org/w/index.php?title=HTTP%E6%91%98%E8%A6%81%E8%AE%A4%E8%AF%81&action=edit&section=1s">HTTP摘要认证</a>
 * @author Kevin Wang
 *
 */
@Slf4j
@Component
public class HttpDigestInterceptor extends HandlerInterceptorAdapter {
    public static String SERVER_REALM = "serverrealm";
    public static String NONCE_KEY= "servernoncekey";
    public static int NONCE_VALIDITY_SECONDS = 30;
    private static final String REALM = "testrealm@host.com";
	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse httpServletResponse, Object handler) throws Exception {
		String auth = request.getHeader("Authorization");  
		log.info("auth:{}",auth);
		if(Strings.isNullOrEmpty(auth)){
			httpServletResponse.setStatus(401);
			String nonce = UUID.randomUUID().toString();
			String opaque = UUID.randomUUID().toString();
			httpServletResponse.addHeader("WWW-Authenticate", "Digest Realm=\""+REALM+"\",qop=\"auth\",nonce=\""+nonce+"\",opaque=\""+opaque+"\"");
//			sendWWWAuthenticateDigestMessage(response);
			return false;
		}else{
			// 截取Basic 之后的字符
			String authInfo = auth.substring(7,auth.length());
			Map<String, String> authMap = parseDigestAuthorizationHeader(authInfo);
	        String username = authMap.get("username");
	        String realm = authMap.get("realm");
	        String nonce = authMap.get("nonce");
//	        String uri = authMap.get("uri");
	        String resp = authMap.get("response");
	        String qop = authMap.get("qop");
	        String nc = authMap.get("nc");
			String cnonce = authMap.get("cnonce");
			
			if(!realm.equals(REALM)){
				return false;
			}
			
			boolean userExist = this.userMap().containsKey(username);
			if(!userExist){
				log.info("用户{}不存在",username);
				return false;
			}
			
			String ha1 = Hashing.md5().hashString(username+":"+REALM+":"+this.userMap().get(username), Charset.defaultCharset()).toString();
			String ha2 = null;
			if(Strings.isNullOrEmpty(qop)||"auth".equals(qop)){
				//HA2 = MD5(A2)=MD5(method:uri)
				ha2 = Hashing.md5().hashString(request.getMethod()+":"+request.getRequestURI(), Charset.defaultCharset()).toString();
			}else if("auth-int".equals(qop)){
				// HA2=MD5(A2)=MD5(method:digestURI:MD5(entiryBody))
				BufferedReader reader = new BufferedReader(new InputStreamReader(request.getInputStream()));
				String body = CharStreams.toString(reader);
				String bodyMd5 = Hashing.md5().hashString(body,Charset.defaultCharset()).toString();
				ha2 = Hashing.md5().hashString(request.getMethod()+":"+request.getRequestURI()+":"+bodyMd5, Charset.defaultCharset()).toString();
			}
			String response = null;
			if(Strings.isNullOrEmpty(qop)){
				//response=MD5(HA1:nonce:HA2)
				response = Hashing.md5().hashString(ha1+":"+nonce+":"+ha2,Charset.defaultCharset()).toString();
			}else if("auth".equals(qop)||"auth-int".endsWith(qop)){
				//response=MD5(HA1:nonce:nonceCount:clientNonce:qop:HA2)
				response = Hashing.md5().hashString(ha1+":"+nonce+":"+nc+":"+cnonce+":"+qop+":"+ha2,Charset.defaultCharset()).toString();
			}
			log.info("response:{}",response);
			if(response.equals(resp)){
				return true;
			}
			return false;
		}
	}
    
	private Map<String, String> parseDigestAuthorizationHeader(String authorizationHeader){
		Map<String, String> map = Maps.newHashMap();
		Iterator<String> iterator = Splitter.on(',').split(authorizationHeader).iterator();
		while(iterator.hasNext()){
			String input = iterator.next();
			Iterator<String> it = Splitter.on('=').split(input).iterator();
			String key = it.next();
			String value = it.next();
			if(!Strings.isNullOrEmpty(value)){
				if(value.startsWith("\"")){
					value = value.substring(1,value.length());
				}
				if(value.endsWith("\"")){
					value = value.substring(0,value.length()-1);
				}
			}
			map.put(key.trim(), value.trim());
		}
		return map;
	}
	
	
	private Map<String, String> userMap(){
		Map<String, String> map = Maps.newHashMap();
		map.put("admin", "123456");
		return map;
	}
}
```

#### 2.5 运行代码
- 运行[Application.java](http-digest/src/main/java/com/pachiraframework/httpdigest/Application.java)类
- 访问链接[http://localhost:8080/dir/index.html](http://localhost:8080/dir/index.html) GET/POST都可以
- 输入用户名密码（第一次访问时输入）admin  123456

**注意**：

部分浏览器并不支持auth-int参数，但是都支持auth，浏览器对auth-int的支持参考[浏览器实现](https://zh.wikipedia.org/wiki/HTTP%E6%91%98%E8%A6%81%E8%AE%A4%E8%AF%81#浏览器实现)

### 参考资料：
- [HTTP摘要认证](https://zh.wikipedia.org/w/index.php?title=HTTP%E6%91%98%E8%A6%81%E8%AE%A4%E8%AF%81&action=edit&section=1)
- [RFC 2167](https://tools.ietf.org/html/rfc2617)
- [http digest](https://www.jianshu.com/p/18fb07f2f65e)