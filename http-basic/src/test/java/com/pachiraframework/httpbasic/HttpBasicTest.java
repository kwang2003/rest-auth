package com.pachiraframework.httpbasic;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import org.junit.Test;
import org.springframework.util.Base64Utils;

import com.github.kevinsawicki.http.HttpRequest;

public class HttpBasicTest {
	@Test
	public void testHttpBasic(){
		String name = "admin";
		String password = "123456";
		String base64 = Base64Utils.encodeToString((name+":"+password).getBytes());
		String body = HttpRequest.get("http://localhost:8080/demo.json").header("Authorization", "Basic "+base64).body();
		assertThat(body, equalTo("demo"));
		body = HttpRequest.get("http://localhost:8080/demo.json").basic(name, password).body();
		assertThat(body, equalTo("demo"));
		body = HttpRequest.get("http://localhost:8080/demo.json").authorization("Basic "+base64).body();
		assertThat(body, equalTo("demo"));
	}
	
	@Test
	public void testHttpBasicWithoutAuthorization(){
		int code = HttpRequest.get("http://localhost:8080/demo.json").code();
		assertThat(code, is(401));
	}
}
