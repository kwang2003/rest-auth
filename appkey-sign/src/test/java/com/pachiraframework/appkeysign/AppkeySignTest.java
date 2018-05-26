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
