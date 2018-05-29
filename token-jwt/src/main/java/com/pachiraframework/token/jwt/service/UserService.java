package com.pachiraframework.token.jwt.service;

import com.pachiraframework.token.jwt.model.UserInfo;

/**
 * 模拟用户service
 * @author kevin wang
 *
 */
public interface UserService {
	public UserInfo doLogin(String loginId,String password);
	
	public UserInfo getById(Long userId);
	
	public UserInfo getByMobile(String mobile);
}
