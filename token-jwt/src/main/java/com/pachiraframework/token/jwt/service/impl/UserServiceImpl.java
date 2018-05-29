package com.pachiraframework.token.jwt.service.impl;

import org.springframework.stereotype.Service;

import com.pachiraframework.token.jwt.model.UserInfo;
import com.pachiraframework.token.jwt.service.UserService;

/**
 * 用户服务接口默认实现--默认数据集，没有实际链接数据库操作
 * @author kevin
 *
 */
@Service
public class UserServiceImpl implements UserService {

	@Override
	public UserInfo doLogin(String loginId, String password) {
		UserInfo userInfo = mockUserInfo();
		return userInfo;
	}
	
	private UserInfo mockUserInfo() {
		UserInfo userInfo = new UserInfo();
		userInfo.setEmail("12708826@qq.com");
		userInfo.setLoginId("admin");
		userInfo.setMobile("18512345678");
		userInfo.setName("王先生");
		userInfo.setUserId(555L);
		return userInfo;
	}

	@Override
	public UserInfo getById(Long userId) {
		UserInfo userInfo = mockUserInfo();
		return userInfo;
	}

	@Override
	public UserInfo getByMobile(String mobile) {
		UserInfo userInfo = mockUserInfo();
		return userInfo;
	}

}
