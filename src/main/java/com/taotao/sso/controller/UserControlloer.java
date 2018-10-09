package com.taotao.sso.controller;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.taotao.common.util.CookieUtils;
import com.taotao.sso.bean.User;
import com.taotao.sso.service.UserService;

@Controller
@RequestMapping("user")
public class UserControlloer extends ExceptionHanlingController {
	
	private static final String COOKIE_NAME = "TAOTAO_TOKEN";//cookie中token的key
	
	private static final String REAL_REQUEST_URL = "REAL_REQUEST_URL";
	
	private static final int TOKEN_FROM_COOKIE_SECONDS = 60 * 30;// cookie中token的存活时长：30分钟
	
	@Autowired
	private UserService userService;
	
	/**
	 * 这里只是简单的做页面跳转，跳转到注册页面。
	 * @IgnoreCheckoutToken:加了该注解，表示忽略验证token。
	 */
	@RequestMapping(value = "register", method = RequestMethod.GET)
	public String register(){
		return "register";
	}
	
	/**
	 * 这里只是简单的做页面跳转，跳转到注册页面。
	 */
	@RequestMapping(value = "login", method = RequestMethod.GET)
	public String login(){
		return "login";
	}
	
	/**
	 * 检查数据是否可用。
	 * http://sso.taotao.com/user/{param}/{type}
	 * param是校验的数据，type为类型，可选参数1、2、3分别代表username、phone、email
	 */
	@RequestMapping(value = "{param}/{type}", method = RequestMethod.GET)
	public ResponseEntity<Boolean> check(@PathVariable("param")String param, 
			@PathVariable("type")Integer type){
		Boolean bool = this.userService.check(param, type);
		if(null == bool){
			//参数有误：
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
		}else{
			//本来bool值true是代表数据不存在，可用的；false是代表数据已存在，不可用的。
			//为了兼容前端逻辑，作出妥协！！！现在进行取反：true代表不可用，false代表可用。
			//如：zhangsan已经存在了，查询结果是不为null，userService中返回false，现在controller返回时进行取反，返回true，表示不可用。
			return ResponseEntity.ok(!bool);
		}
	}
	
	/**
	 * 注册
	 * url:http://sso.taotao.com/service/user/doRegister
	 * 1.因为不管怎样，都得返回有数据的map，所以直接返回map，不用ResponseEntity了。此时方法就一定需要加@ResponseBody注解。
	 * 2.手动try-catch的原因：出异常了也是注册失败了，也得返回map，而不能返回其他的。
	 * 3.@Valid校验user中的参数是否合法。
	 * 4.springmvc会将校验结果写入到BindingResult对象中。
	 * 5.通过BindingResult判断，如果校验失败，自定义执行什么逻辑。
	 */
	@RequestMapping(value = "doRegister", method = RequestMethod.POST)
	@ResponseBody
	public Map<String, Object> doRegister(@Valid User user, BindingResult bindingResult){
		
		Map<String, Object> map = new HashMap<>();
		
		//没有通过校验
		if(bindingResult.hasErrors()){
			map.put("status", "400");
			//收集错误信息：
			StringBuilder errorMessage = new StringBuilder();
			List<ObjectError> list = bindingResult.getAllErrors();
			for(ObjectError error : list){
				errorMessage.append(error.getDefaultMessage());
			}
			map.put("data", "参数有误！" + errorMessage);
			return map;
		}
		
		//没有错误，即通过了校验：
		try {
			Boolean bool = this.userService.doRegister(user);
			if(bool){
				map.put("status", "200");//这里的200是业务状态码
			}else {
				map.put("status", "500");//前端没有要求非得写多少，只要不是200就成
				map.put("data", "哈哈哈哈~~~");
			}
			return map;
		} catch (Exception e) {
			e.printStackTrace();
			map.put("status", "500");
			map.put("data", "哈哈哈哈");
		}
		return map;
	}

	/**
	 * 登录
	 */
	@RequestMapping(value = "doLogin", method = RequestMethod.POST)
	@ResponseBody
	public Map<String, Object> login(User user, HttpServletRequest request, HttpServletResponse response){
		Map<String, Object> result = new HashMap<>();
		try {
			String token = this.userService.doLogin(user.getUsername(), user.getPassword());
			//登录成功：将token放入cookie中：
			if(StringUtils.isNotEmpty(token)){
				/**
				 * 获取boolean com.taotao.web.interceptor.CheckLoginInterceptor.preHandle(HttpServletRequest request, 
				 * HttpServletResponse response, Object handler) throws Exception方法中放入cookie的REAL_REQUEST_URL：
				 */
				String realRequestURLValue = CookieUtils.getCookieValue(request, REAL_REQUEST_URL);
				if(StringUtils.isNotEmpty(realRequestURLValue)){
					result.put(REAL_REQUEST_URL, realRequestURLValue);
					//拿到REAL_REQUEST_URL后就将cookie中的REAL_REQUEST_URL值删除：
					//注意，老师给的CookieUtils工具类中的delete()方法并不能删除掉cookie，详见delete()方法。
//					CookieUtils.setCookie(request, response, REAL_REQUEST_URL, null, 0);
					CookieUtils.myDeleteCookie(request, response, REAL_REQUEST_URL);//改进后的delete()方法。
				}
				result.put("status", "200");
				/**
				 * 这里是将token放入了".taotao.com"域名的cookie中，而非sso.taotao.com的。
				 * 原因：
				 * 1.和nginx相关：nginx.conf文件中配置了proxy_set_header Host $host;
				 *   见G:\nginx\nginx-1.5.1\conf\nginx.conf文件
				 * 2.和CookieUtils.setCookie()方法的执行逻辑相关;
				 * 	   见String com.taotao.common.util.CookieUtils.getDomainName(HttpServletRequest request)
				 */
				CookieUtils.setCookie(request, response, COOKIE_NAME, token, TOKEN_FROM_COOKIE_SECONDS);
			}else{//登录失败：
				result.put("status", "400");
			}
			return result;
		} catch (Exception e) {//登录失败：
			e.printStackTrace();
			result.put("status", "500");
			return result;
		}
	}
	
	/**
	 * 服务端根据用户cookie中的token到Redis中比对token，并返回用户信息。
	 * 这里的校验交给了boolean com.taotao.sso.interceptor.CheckoutInterceptor.preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception
	 */
	@RequestMapping(value = "/checkoutToken", method = RequestMethod.GET)
	public ResponseEntity<User> queryUserByToken(HttpServletRequest request) throws Exception{
		//没用dubbo之前，是通过下面这些被注释掉的代码来实现“通过token查询到user对象并返回”这一功能的：
//		User user = (User)request.getAttribute(USER_FROM_REDIS);
//		if(null == user){
//			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
//		}else{
//			return ResponseEntity.ok(user);
//		}
		//用了dubbo之后，该接口就被废弃了，所以响应404：
		User user = new User();
		user.setUsername("该接口已经被废弃了，往后都别再调用该接口了，请访问‘ssoquery.taotao.com/user’或dubbo中的服务。");
		return ResponseEntity.status(HttpStatus.NOT_FOUND).body(user);
	}
	
	/**
	 * 退出登录
	 * @throws IOException 
	 * @throws JsonMappingException 
	 * @throws JsonParseException 
	 */
	@RequestMapping(value = "/logout", method = RequestMethod.GET)
	public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) throws JsonParseException, JsonMappingException, IOException{
		this.userService.logout(request, response);
		return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
	}
}
