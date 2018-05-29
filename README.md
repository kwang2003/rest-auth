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
Digest认证是HTTP协议自带的另一种认证方式，可以看做是加强版的Basic认证， 使用随机数+密码进行md5，防止截取 header直接解码获得用户密码。Digest认证中用到的一些参数含义及说明如下：

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

### 3.APPKEY+签名认证
#### 3.1 说明
APPKEY+签名方式被广泛用于各大商家的开放平台，如[淘宝开放平台](http://open.taobao.com/doc.htm?spm=a219a.7629065.1.21.WlHEjQ#?treeId=477&docId=73&docType=1)，通过为每个调用端分配不同的APPKEY和密钥，根据appkey和密钥对请求参数进行签名，服务器端使用同样的签名算法对调用放传递的签名进行校验，由于每个调用放的密钥是保存在各自服务器上的，只要密钥不泄漏，签名就没法伪造篡改，从而达到安全传输的目的。
#### 3.2 示例
```java
package com.pachiraframework.appkeysign;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import java.nio.charset.Charset;
import java.util.Map.Entry;
import java.util.TreeMap;

import org.junit.Test;

import com.github.kevinsawicki.http.HttpRequest;
import com.google.common.hash.Hashing;

public class AppkeySignTest {
	@Test
	public void testHttpBasic(){
		String template = "http://localhost:8080/demo.json?name=%s&channel=%s&timestamp=%s&appkey=%s&sign=%s";
		long timestamp = System.currentTimeMillis();
		String name = "admin";
		String channel = "1";
		String appkey = "appkey1";
		String secret = "secret1";
		TreeMap<String, String> params = new TreeMap<String,String>();
		params.put("name", name);
		params.put("channel", channel);
		params.put("appkey", appkey);
		params.put("timestamp", timestamp+"");
		StringBuffer buffer = new StringBuffer(secret);
		for(Entry<String, String> entry : params.entrySet()){
			buffer.append(entry.getKey());
			buffer.append(entry.getValue());
		}
		buffer.append(secret);
		String sign = Hashing.md5().hashString(buffer.toString(), Charset.defaultCharset()).toString();
		String url = String.format(template, name,channel,timestamp,appkey,sign);
		
		String body = HttpRequest.get(url).body();
		assertThat(body, equalTo("demo"));
	}
}

```
#### 3.3 认证流程计算法
![https://note.youdao.com/yws/public/resource/e5bb1aa758439bbedce6c5dd9a73a81c/xmlnote/ECAAA67D2D1A47DC861BFDEA8FF632A6/77510](https://note.youdao.com/yws/public/resource/e5bb1aa758439bbedce6c5dd9a73a81c/xmlnote/ECAAA67D2D1A47DC861BFDEA8FF632A6/77510)
![https://note.youdao.com/yws/public/resource/e5bb1aa758439bbedce6c5dd9a73a81c/xmlnote/EB5202902F4146ACB28815E853D11C0A/77511](https://note.youdao.com/yws/public/resource/e5bb1aa758439bbedce6c5dd9a73a81c/xmlnote/EB5202902F4146ACB28815E853D11C0A/77511)
几个常见疑问及解答：
- 为什么要把请求参数做排序处理？

    为了调用方生成sign和服务器端生成sign一致用的，因此请求中的参数如a=1&t=3&c=34顺序可以是任意的，接收方接收到参数的顺序也可能和发送方的顺序不一致，因为要签名中要把参数拼接成如bar2foo1foo_bar3这种格式，同样的参数不同的顺序，也会导致产生不同的签名。
- 为何要采用timestamp时间戳？

    为了保证接口请求没法被重发。如API请求[http://localhost:8080/demo.json?name=admin&channel=1&timestamp=1527299323388&appkey=appkey1&sign=b7ccf1a47b2f445cc9e8b33513bbb5c2](http://localhost:8080/demo.json?name=admin&channel=1&timestamp=1527299323388&appkey=appkey1&sign=b7ccf1a47b2f445cc9e8b33513bbb5c2)是合法的，但是是过去某个时间的请求，如果不加限制，一旦这个请求地址泄漏出去，有可能被恶意用户再次请求获得数据，服务器端通过获取timestamp参数和本地时间做对比，一旦这个时差超过指定时间如30秒，则认为是非法请求，从而达到保护数据的目的。

#### 3.4 服务器端代码实现(基于Spring Boot)
```java
package com.pachiraframework.appkeysign.controller;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.util.Map;
import java.util.TreeSet;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import lombok.extern.slf4j.Slf4j;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.google.common.collect.Maps;
import com.google.common.hash.Hashing;

/**
 * @author kevin wang
 * 
 */
@Slf4j
@RestController
public class DemoController {
	@RequestMapping(path = "/demo.json", method = RequestMethod.GET)
	public String auth(HttpServletRequest request, HttpServletResponse response) throws UnsupportedEncodingException {
		TreeSet<String> params = new TreeSet<String>();
		params.add("timestamp");
		params.add("name");
		params.add("appkey");
		params.add("channel");
		StringBuffer buffer = new StringBuffer();
		for(String param : params){
			buffer.append(param);
			buffer.append(request.getParameter(param));
		}
		log.info("{}",buffer);
		String encoded = new String(buffer.toString().getBytes("UTF-8"));
		String appkey = request.getParameter("appkey");
		String secret = appkeySecret().get(appkey);
		String input = new StringBuffer(secret).append(encoded).append(secret).toString();
		String newSign = Hashing.md5().hashString(input, Charset.defaultCharset()).toString();
		log.info("new sign :{}",newSign);
		
		//验证是否已经过期，防止重放
		Long timestamp = Long.valueOf(request.getParameter("timestamp"));
		long now = System.currentTimeMillis();
		if(now-timestamp > 10*60*1000L){//超过10分钟
			log.warn("该请求已经过期");
			//return "请求过期";
		}
		//签名匹配校验
		String sign = request.getParameter("sign");
		if(sign.equals(newSign)){
			//请求合法
			return "demo";
		}
		return "error";
	}

	private Map<String, String> appkeySecret() {
		Map<String, String> map = Maps.newHashMap();
		map.put("appkey1", "secret1");
		map.put("appkey2", "secret2");
		return map;
	}
}

```
#### 3.5 运行代码
- 前提 有两个appkey和secret分别是appkey1/secret1  appkey2/secrent2
- 运行[Application.java](appkey-sign/src/main/java/com/pachiraframework/appkeysign/Application.java)类
- 访问链接[http://localhost:8080/demo.json?name=admin&channel=1&timestamp=1527299323388&appkey=appkey1&sign=b7ccf1a47b2f445cc9e8b33513bbb5c2](http://localhost:8080/demo.json?name=admin&channel=1&timestamp=1527299323388&appkey=appkey1&sign=b7ccf1a47b2f445cc9e8b33513bbb5c2) 

### 4.JWT Token认证
#### 4.1 说明
JWT(Json Web Token)是一种基于JSON的，作为一个开放的标准（[RFC 7519](https://link.jianshu.com/?t=https://tools.ietf.org/html/rfc7519)），定义了一种简洁的，自包含的方法用于通信双方之间以Json对象的形式安全的传递信息。因为签名的存在,这些信息是可信任的，JWT可以使用HMAC算法或者是RSA的公私秘钥对进行签名。简洁(Compact): 可以通过URL，POST参数或者在HTTP header发送，因为数据量小，传输速度也很快，自包含(Self-contained)：负载中包含了所有用户所需要的信息。
![https://note.youdao.com/yws/public/resource/e5bb1aa758439bbedce6c5dd9a73a81c/xmlnote/A3558277560A46119A1270B19AAF25FC/77666](https://note.youdao.com/yws/public/resource/e5bb1aa758439bbedce6c5dd9a73a81c/xmlnote/A3558277560A46119A1270B19AAF25FC/77666)
#### 4.2 JWT结构
![https://note.youdao.com/yws/public/resource/e5bb1aa758439bbedce6c5dd9a73a81c/xmlnote/E90E4C328B864F27B5D1B7D5A2C460BB/77668](https://note.youdao.com/yws/public/resource/e5bb1aa758439bbedce6c5dd9a73a81c/xmlnote/E90E4C328B864F27B5D1B7D5A2C460BB/77668)
JWT包含了三个部分:header.body.signature，这三个部分使用'.'分割
##### 4.2.1 header
通常包含两个部分，token类型和加密算法，举例：
> { "alg": "HS256", "typ": "JWT"} 

然后对这个部分进行base64编码得到JWT的header部分
##### 4.2.2 body
包含三种类型的内容，JWT规范中并不强制使用这些内容，但是推荐使用，分别是
- reserved
    - iss TOKEN签发者
    - exp TOKEN到期时间
    - sub 面向客户
    - aud 接收方
    - iat 签发时间
- public

     公共的声明可以添加任何的信息，一般添加用户的相关信息或其他业务需要的必要信息.但不建议添加敏感信息，因为该部分在客户端可解密.
- private
    
     私有声明是提供者和消费者所共同定义的声明，一般不建议存放敏感信息，因为base64是对称解密的，意味着该部分信息可以归类为明文信息。
说明：
个人感觉，除了reserved JWT规范约定的几个名称外，public和private之间的约定并没有严格的界限，只要不重复即可。
##### 4.2.3 signature
根据base64编码后的header和body以及一个密钥，私用header中约定的签名算法进行签名，如要使用HMAC SHA256算法，则
> signature=HMACSHA256(base64URLEncode(header))+"."+base64URLEncode(body),secret)

#### 4.3 JWT使用案例
#### 4.3.1 案例说明
这个案例案例使用jwt作为两个系统之间单点登录解决方案，A系统生成token，然后传递到B系统中，B系统接收token，并验证token有效性（jwt框架自带的api），如果token则认为是合法token
#### 4.3.2 示例核心代码
- [SSOCallbackController.java](token-jwt/src/main/java/com/pachiraframework/token/jwt/controller/SSOCallbackController.java)
    
    使用JWT作为单点登录方案的核心代码，接收传递过来的token字符串，模拟本地调用数据库中查询用户，然后把用户信息写入到session中（模拟通过用户名密码方式登录 ）

    ```java
    package com.pachiraframework.token.jwt.controller;
    
    import io.jsonwebtoken.Claims;
    import io.jsonwebtoken.ExpiredJwtException;
    import io.jsonwebtoken.Jwts;
    import io.jsonwebtoken.SignatureException;
    
    import javax.servlet.http.HttpServletRequest;
    
    import lombok.extern.slf4j.Slf4j;
    
    import org.springframework.beans.factory.annotation.Autowired;
    import org.springframework.stereotype.Controller;
    import org.springframework.web.bind.annotation.RequestMapping;
    
    import com.pachiraframework.token.jwt.SessionConstant;
    import com.pachiraframework.token.jwt.model.UserInfo;
    import com.pachiraframework.token.jwt.service.UserService;
    
    /**
     * 其他系统通过sso进行登陆的额操作
     * @author kevin wang
     *
     */
    @Slf4j
    @Controller
    @RequestMapping(path="/pc")
    public class SSOCallbackController {
    	//和SSO服务提供方约定的数据加密方式，不能泄漏
    	private static final String SECRET_KEY = "123456";
    	
    	@Autowired
    	private UserService userService;
    	@RequestMapping(path="/sso_callback")
    	public String callback(HttpServletRequest request) {
    		//校验access_token的合法性，并从里面解析出有价值的数据（例如mobile字段）
    		String accessToken = request.getParameter("access_token");
    		try {
    			String mobile = this.parseToken(accessToken);
    			UserInfo userInfo = userService.getByMobile(mobile);
    			//模拟登录过程
    			request.getSession().setAttribute(SessionConstant.USER_ID, userInfo.getUserId());
    			request.getSession().setAttribute(SessionConstant.USER_NAME, userInfo.getName());
    		}catch (ExpiredJwtException e) {
    			log.error("token已经过期");
    		}catch(SignatureException e){
    			log.error("签名错误");
    		}
    		
    //		String redirectUril = request.getParameter("redirect_uri");
    		String redirectUril = "http://localhost:8080/index";
    		return "redirect:"+redirectUril;
    	}
    	
    	private String parseToken(String jwt) {
    		log.info("JWT:{}",jwt);
    		//解析JWT字符串中的数据，并进行最基础的验证
            Claims claims = Jwts.parser()
                    .setSigningKey(SECRET_KEY)//SECRET_KEY是加密算法对应的密钥，jjwt可以自动判断机密算法
                    .parseClaimsJws(jwt)//jwt是JWT字符串
                    .getBody();
            log.info("JWT CLAIMS:"+claims);
            //验证issuer和audience是否匹配
            return (String)claims.get("mobile");
    	}
    }
    
    ```
- [LoginController.java](token-jwt/src/main/java/com/pachiraframework/token/jwt/controller/LoginController.java) 

    用户通过在系统内正常通过用户名密码登录的代码逻辑
- [IndexController.java](token-jwt/src/main/java/com/pachiraframework/token/jwt/controller/IndexController.java)

    需要登录后才能访问的资源
- [LonginInterceptor.java](token-jwt/src/main/java/com/pachiraframework/token/jwt/interceptor/LoginInterceptor.java)
    
    登录拦截器

#### 4.4运行代码
- 运行[Application.java](token-jwt/src/main/java/com/pachiraframework/token/jwt/Application.java)

A)方式1：通过普通用户名密码方式访问受保护的资源
- 访问[http://localhost:8080/](http://localhost:8080/)    admin  123456

  ![https://note.youdao.com/yws/public/resource/e5bb1aa758439bbedce6c5dd9a73a81c/xmlnote/E332CFB85AC74DAB8B5BE3A4757F1188/77722](https://note.youdao.com/yws/public/resource/e5bb1aa758439bbedce6c5dd9a73a81c/xmlnote/E332CFB85AC74DAB8B5BE3A4757F1188/77722)
- 登录成功后到首页

  ![https://note.youdao.com/yws/public/resource/e5bb1aa758439bbedce6c5dd9a73a81c/xmlnote/74953C7874CC453F92C04041A105B1B6/77724](https://note.youdao.com/yws/public/resource/e5bb1aa758439bbedce6c5dd9a73a81c/xmlnote/74953C7874CC453F92C04041A105B1B6/77724)

B)方式B:通过jwt token方式单点登录到系统，然后访问受保护的资源
- 生成jwt格式的token(通常是另一个系统中)，示例中通过单元测试代码提供了一个token的方法[JwtTest.java](token-jwt/src/test/java/com/pachiraframework/token/jwt/JwtTest.java),这里我们通过该方法生成的token为
    > eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjMwMDAwMTUyNzU4Mzg2NCwiaXNzIjoia3VhaXhpYW4iLCJhdWQiOiJocCIsInVzZXJfaWQiOiIxMjMiLCJtb2JpbGUiOiIxODUxMjM0NTY3OCIsImxvZ2luX2lkIjoiYWRtaW4ifQ.9dociKzn1w1uaRpRwJWsRVaRDSwDklNKSMZCPajebJE
    
    ```java
    package com.pachiraframework.token.jwt;
    
    import io.jsonwebtoken.Jwts;
    import io.jsonwebtoken.SignatureAlgorithm;
    
    import java.util.Date;
    
    import lombok.extern.slf4j.Slf4j;
    
    import org.junit.Test;
    
    @Slf4j
    public class JwtTest {
    	private static final String SECRET_KEY = "123456";
    	@Test
    	public void testJwt(){
    		//为了掩饰，生成一个长生命周期的token，生产环境下sso操作时token的周期尽可能小
    		long minutes = 5000000000000L;
    		//5分钟token过期
    		Date exp = new Date(System.currentTimeMillis()+minutes*60*1000);
    	    String jwt = Jwts.builder()
    	            .signWith(SignatureAlgorithm.HS256,SECRET_KEY)//SECRET_KEY是加密算法对应的密钥，这里使用额是HS256加密算法
    	            .setExpiration(exp)
    	            .setIssuer("kuaixian")
    	            .setAudience("hp")
    	            .claim("user_id","123")//该方法是在JWT中加入值为vaule的key字段
    	            .claim("mobile","18512345678")
    	            .claim("login_id", "admin")
    	            .compact();
    	    log.info(jwt);
    	}
    }

    ```

- 访问通用单点登录链接[http://localhost:8080/pc/sso_callback?access_token=eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjMwMDAwMTUyNzU4Mzg2NCwiaXNzIjoia3VhaXhpYW4iLCJhdWQiOiJocCIsInVzZXJfaWQiOiIxMjMiLCJtb2JpbGUiOiIxODUxMjM0NTY3OCIsImxvZ2luX2lkIjoiYWRtaW4ifQ.9dociKzn1w1uaRpRwJWsRVaRDSwDklNKSMZCPajebJE](http://localhost:8080/pc/sso_callback?access_token=eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjMwMDAwMTUyNzU4Mzg2NCwiaXNzIjoia3VhaXhpYW4iLCJhdWQiOiJocCIsInVzZXJfaWQiOiIxMjMiLCJtb2JpbGUiOiIxODUxMjM0NTY3OCIsImxvZ2luX2lkIjoiYWRtaW4ifQ.9dociKzn1w1uaRpRwJWsRVaRDSwDklNKSMZCPajebJE) 自动实现用户识别登录跳转

### 参考资料：
- [HTTP摘要认证](https://zh.wikipedia.org/w/index.php?title=HTTP%E6%91%98%E8%A6%81%E8%AE%A4%E8%AF%81&action=edit&section=1)
- [RFC 2167](https://tools.ietf.org/html/rfc2617)
- [http digest](https://www.jianshu.com/p/18fb07f2f65e)
- [关于 RESTFUL API 安全认证方式的一些总结](https://www.cnblogs.com/Irving/p/4964489.html)
- [淘宝开放平台-API调用方法详解](http://open.taobao.com/doc.htm?spm=a219a.7629065.1.21.WlHEjQ#?treeId=477&docId=101617&docType=1)
- [初步理解JWT并实践使用](https://blog.csdn.net/qq_40081976/article/details/79046825)
- [基于jwt的token验证](https://blog.csdn.net/weixin_38568779/article/details/76833848)