package com.taotao.sso.service;

import java.io.IOException;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.taotao.common.bean.RedisKeyConstant;
import com.taotao.common.util.CookieUtils;
import com.taotao.sso.bean.User;
import com.taotao.sso.mapper.UserMapper;

@Service
public class UserService {

	@Autowired
	private UserMapper userMapper;

	@Autowired
	private StringRedisTemplate stringRedisTemplate;

	private static final long REDIS_SECONDS = 60 * 30;// 30分钟

	private static final String COOKIE_TOKEN = "TAOTAO_TOKEN";

	private static final ObjectMapper MEPPER = new ObjectMapper();

	/**
	 * 校验用户名、手机号码、邮箱是否已被注册
	 */
	public Boolean check(String param, Integer type) {

		User record = new User();

		// 判断type是否为1、2、3
		switch (type) {
		case 1:// 用户名
			record.setUsername(param);
			break;
		case 2:// 手机号
			record.setPhone(param);
			break;
		case 3:// 邮箱
			record.setEmail(param);
			break;
		default:// 参数有误
			return null;
		}

		// 体会下面的代码 和 最终返回的代码：
		// if(null == this.userMapper.selectOne(record)){
		// return true;//数据可用
		// }else{
		// return false;//数据不可用
		// }
		return null == this.userMapper.selectOne(record);
	}

	/**
	 * 注册
	 */
	public Boolean doRegister(User user) {
		// user对象的初始化处理：
		user.setId(null);
		user.setCreated(new Date());
		user.setUpdated(user.getCreated());
		// 密码需要进行加密处理，采用Apache提供的加密解密工具包进行加密（pom中有导包），加密方式：MD5
		user.setPassword(DigestUtils.md5Hex(user.getPassword()));
		return this.userMapper.insert(user) == 1;
	}

	/**
	 * 登录 1.两种查询用户名+密码是否正确的方法： （1）where username = "……" and password = "……"
	 * （2）先查数据库中是否存在username="……"条件的用户，有就返回，再比对密码是否一致。
	 * 推荐使用第二种：查询的时候，查询条件越少，查询速度越快。
	 * 2.MEPPER.writeValueAsString(user)有异常，是抛，还是捕获？
	 * 应该捕获，因为这里Redis不是作为缓存，而是作为内存数据库来使用的。
	 * 
	 * @throws JsonProcessingException
	 */
	public String doLogin(String username, String password) throws Exception {
		User record = new User();
		record.setUsername(username);
		User user = this.userMapper.selectOne(record);
		// 用户存在：
		if (null != user) {
			// 密码也对，登录成功！
			if (StringUtils.equals(DigestUtils.md5Hex(password), user.getPassword())) {
				// 看Redis中是否存有该用户的userId-token键值对【防止30分钟内反复登录】
				String tokenByUserId = this.stringRedisTemplate.opsForValue().get(RedisKeyConstant.getUserId(user.getId()));
				// 存在userId-token键值对：
				if (StringUtils.isNotEmpty(tokenByUserId)) {
					this.stringRedisTemplate.delete(tokenByUserId);
				}
				// 生成token:
				String token = DigestUtils.md5Hex(username + System.currentTimeMillis());
				/**
				 * 为什么不直接声明token是就拼上"TOKEN_"，而是存到Redis中的有拼上"TOKEN_"，方法返回的却是没有拼"TOKEN_"的呢？
				 * 因为最好不要再网络中传输id或类似token这种key，这样不安全：
				 * id一旦被人拿到，他连上数据库后，就能根据id拿到数据;token被人拿到，他也可能连接Redis根据token拿到value。
				 */
				// 存token到Redis中：
				this.stringRedisTemplate.opsForValue().set(RedisKeyConstant.getToken(token), MEPPER.writeValueAsString(user), REDIS_SECONDS, TimeUnit.SECONDS);
				// 存"记录了token的key"的userId到Redis中：
				this.stringRedisTemplate.opsForValue().set(RedisKeyConstant.getUserId(user.getId()),RedisKeyConstant.getToken(token), REDIS_SECONDS, TimeUnit.SECONDS);
				return token;
			} 
		}
		return null;
	}

	/**
	 * 退出登录。
	 * 
	 * @throws IOException
	 * @throws JsonMappingException
	 * @throws JsonParseException
	 */
	public void logout(HttpServletRequest request, HttpServletResponse response)
			throws JsonParseException, JsonMappingException, IOException {
		Cookie[] cookies = request.getCookies();
		String token = null;
		for (int i = 0; i < cookies.length; i++) {
			Cookie cook = cookies[i];
			if (cook.getName().equalsIgnoreCase(COOKIE_TOKEN)) {// 获取键
				token = cook.getValue();// 获取值
				break;
			}
		}
		if (null != token) {
			String jsonData = this.stringRedisTemplate.opsForValue().get(RedisKeyConstant.getToken(token));
			User user = MEPPER.readValue(jsonData, User.class);
			this.stringRedisTemplate.delete(RedisKeyConstant.getToken(token));// 删除redis中的token
			this.stringRedisTemplate.delete(user.getId().toString());// 删除"记录了token的key"的userId
			CookieUtils.myDeleteCookie(request, response, COOKIE_TOKEN);//删除cookie中的token
		}
	}

}
