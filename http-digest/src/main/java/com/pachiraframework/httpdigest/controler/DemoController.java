package com.pachiraframework.httpdigest.controler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author kevin wang
 *
 */
@RestController
public class DemoController {
	@RequestMapping(path="/demo.json",method=RequestMethod.GET)
	public String auth(HttpServletRequest request,HttpServletResponse response){
		return "demo";
	}
}
