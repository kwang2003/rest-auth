package com.pachiraframework.httpdigest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.nio.charset.Charset;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import lombok.extern.slf4j.Slf4j;

import org.junit.Test;

import com.github.kevinsawicki.http.HttpRequest;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.hash.Hashing;
import com.google.common.io.CharStreams;

@Slf4j
public class HttpDigestTest {
	@Test
	public void testHttpDigest() throws IOException{
		String username = "admin";
		String password = "123456";
		HttpRequest request = HttpRequest.get("http://localhost:8080/dir/index.html");
		Map<String,List<String>> headers = request.headers();
		int code = request.code();
		assertThat(code, is(401));
		List<String> authenticates = headers.get("WWW-Authenticate");
		String authenticate = authenticates.get(0);
		authenticate = authenticate.substring(7,authenticate.length());
		Iterator<String> iterator = Splitter.on(",").split(authenticate).iterator();
		String realm = null;
		String qop=null;
		String nonce = null;
		String opaque = null;
		while(iterator.hasNext()){
			String pair = iterator.next();
			Iterator<String> it = Splitter.on("=").split(pair).iterator();
			String key = it.next();
			String value = it.next();
			if("realm".equalsIgnoreCase(key)){
				realm = trimQuata(value);
			}else if("opaque".equalsIgnoreCase(key)){
				opaque = trimQuata(value);
			}else if("nonce".equalsIgnoreCase(key)){
				nonce = trimQuata(value);
			}else if("qop".equalsIgnoreCase(key)){
				qop = trimQuata(value);
			}
			log.info(pair);
		}
		
		String ha1 = Hashing.md5().hashString(username+":"+realm+":"+password, Charset.defaultCharset()).toString();
		String ha2 = null;
		if(Strings.isNullOrEmpty(qop)||"auth".equals(qop)){
			//HA2 = MD5(A2)=MD5(method:uri)
			ha2 = Hashing.md5().hashString("GET"+":"+"/dir/index.html", Charset.defaultCharset()).toString();
		}else if("auth-int".equals(qop)){
			// HA2=MD5(A2)=MD5(method:digestURI:MD5(entiryBody))
			BufferedReader reader = new BufferedReader(new StringReader("a=123"));
			String body = CharStreams.toString(reader);
			String bodyMd5 = Hashing.md5().hashString(body,Charset.defaultCharset()).toString();
			ha2 = Hashing.md5().hashString("GET"+":"+"/dir/index.html"+":"+bodyMd5, Charset.defaultCharset()).toString();
		}
		
		String response = null;
		String nc = "0000001";
		String cnonce = UUID.randomUUID().toString();
		if(Strings.isNullOrEmpty(qop)){
			//response=MD5(HA1:nonce:HA2)
			log.info("原始:{}",ha1+":"+nonce+":"+ha2);
			response = Hashing.md5().hashString(ha1+":"+nonce+":"+ha2,Charset.defaultCharset()).toString();
		}else if("auth".equals(qop)||"auth-int".endsWith(qop)){
			//response=MD5(HA1:nonce:nonceCount:clientNonce:qop:HA2)
			log.info("原始:{}",ha1+":"+nonce+":"+nc+":"+cnonce+":"+"auth"+":"+ha2);
			response = Hashing.md5().hashString(ha1+":"+nonce+":"+nc+":"+cnonce+":"+"auth"+":"+ha2,Charset.defaultCharset()).toString();
		}
		log.info("ha1={}",ha1);
		log.info("ha2={}",ha2);
		log.info("response={}",response);
		StringBuffer authHeader = new StringBuffer();
		authHeader.append("Digest username=\""+username+"\",realm="+realm+",qop=auth,"+"nonce="+nonce+",opaque="+opaque+",uri=/dir/index.html,response="+response+",nc="+nc+",cnonce="+cnonce);
		String body = HttpRequest.get("http://localhost:8080/dir/index.html").authorization(authHeader.toString()).body();
		assertThat(body, equalTo("demo"));
		log.info("{}",authenticate);
	}
	
	private String trimQuata(String value){
		String rs = value;
		if(rs.startsWith("\"")){
			rs= rs.substring(1,rs.length());
		}
		if(rs.endsWith("\"")){
			rs = rs.substring(0,rs.length()-1);
		}
		return rs;
	}
	
	@Test
	public void testHttpDigestWithoutAuthorization(){
		int code = HttpRequest.get("http://localhost:8080/dir/index.html").code();
		assertThat(code, is(401));
	}
}
