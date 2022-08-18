#  项目简介

此项目为RuoYi-Vue集成cas。

# 集成步骤

## 一、后端配置

### 1、添加cas依赖

在common模块pom添加spring-security-cas依赖：

~~~xml
<!-- spring security cas-->
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-cas</artifactId>
</dependency>
~~~

### 2、修改配置文件

 在admin模块下的application.yml配置文件中添加：

~~~yml
#CAS
cas:
  server:
    host:
      #CAS服务地址
      url: http://localhost:8888/cas
      #CAS服务登录地址
      login_url: ${cas.server.host.url}/login
      #CAS服务登出地址
      logout_url: ${cas.server.host.url}/logout?service=${app.server.host.url}
# 应用访问地址
app:
  #开启cas
  casEnable: true
  server:
    host:
      url: http://localhost:${server.port}
  #应用登录地址
  login_url: /
  #应用登出地址
  logout_url: /logout
  #前端登录地址
  web_url: http://localhost/index
~~~

### 3、修改LoginUser.java

 由于CAS认证需要authorities属性，此属性不能为空，此处为了方便直接new HashSet(): 

~~~java
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities()
    {
        return new HashSet();
    }
~~~

### 4、修改Constants.java

 添加CAS认证成功标识： 

~~~java
	/**
     * CAS登录成功后的后台标识
     */
    public static final String CAS_TOKEN = "cas_token";

    /**
     * CAS登录成功后的前台Cookie的Key
     */
    public static final String WEB_TOKEN_KEY = "Admin-Token";
~~~

### 5、添加 CasProperties.java

 读取cas配置信息： 

~~~java
package com.ruoyi.framework.config.properties;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * CAS的配置参数
 */
@Component
public class CasProperties {
	@Value("${cas.server.host.url}")
	private String casServerUrl;

	@Value("${cas.server.host.login_url}")
	private String casServerLoginUrl;

	@Value("${cas.server.host.logout_url}")
	private String casServerLogoutUrl;

	@Value("${app.casEnable}")
	private boolean casEnable;

	@Value("${app.server.host.url}")
	private String appServerUrl;

	@Value("${app.login_url}")
	private String appLoginUrl;

	@Value("${app.logout_url}")
	private String appLogoutUrl;

	@Value("${app.web_url}")
	private String webUrl;

	public String getWebUrl() {
		return webUrl;
	}

	public String getCasServerUrl() {
		return casServerUrl;
	}

	public void setCasServerUrl(String casServerUrl) {
		this.casServerUrl = casServerUrl;
	}

	public String getCasServerLoginUrl() {
		return casServerLoginUrl;
	}

	public void setCasServerLoginUrl(String casServerLoginUrl) {
		this.casServerLoginUrl = casServerLoginUrl;
	}

	public String getCasServerLogoutUrl() {
		return casServerLogoutUrl;
	}

	public void setCasServerLogoutUrl(String casServerLogoutUrl) {
		this.casServerLogoutUrl = casServerLogoutUrl;
	}

	public boolean isCasEnable() {
		return casEnable;
	}

	public void setCasEnable(boolean casEnable) {
		this.casEnable = casEnable;
	}

	public String getAppServerUrl() {
		return appServerUrl;
	}

	public void setAppServerUrl(String appServerUrl) {
		this.appServerUrl = appServerUrl;
	}

	public String getAppLoginUrl() {
		return appLoginUrl;
	}

	public void setAppLoginUrl(String appLoginUrl) {
		this.appLoginUrl = appLoginUrl;
	}

	public String getAppLogoutUrl() {
		return appLogoutUrl;
	}

	public void setAppLogoutUrl(String appLogoutUrl) {
		this.appLogoutUrl = appLogoutUrl;
	}

}
~~~

### 6、添加CasUserDetailsService.java

 在framework模块下添加： 

~~~java
package com.ruoyi.framework.web.service;

import com.ruoyi.common.core.domain.entity.SysUser;
import com.ruoyi.common.core.domain.model.LoginUser;
import com.ruoyi.common.enums.UserStatus;
import com.ruoyi.common.exception.ServiceException;
import com.ruoyi.common.utils.StringUtils;
import com.ruoyi.system.service.ISysUserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * 用于加载用户信息 实现UserDetailsService接口，或者实现AuthenticationUserDetailsService接口
 */

@Service
public class CasUserDetailsService implements AuthenticationUserDetailsService<CasAssertionAuthenticationToken> {

	private static final Logger log = LoggerFactory.getLogger(UserDetailsServiceImpl.class);

	@Autowired
	private ISysUserService userService;

	@Autowired
	private SysPermissionService permissionService;

	@Override
	public UserDetails loadUserDetails(CasAssertionAuthenticationToken token) throws UsernameNotFoundException {
		String username = token.getName();
		SysUser user = userService.selectUserByUserName(username);
		if (StringUtils.isNull(user)) {
			log.info("登录用户：{} 不存在.", username);
			throw new ServiceException("登录用户：" + username + " 不存在");
		} else if (UserStatus.DELETED.getCode().equals(user.getDelFlag())) {
			log.info("登录用户：{} 已被删除.", username);
			throw new ServiceException("对不起，您的账号：" + username + " 已被删除");
		} else if (UserStatus.DISABLE.getCode().equals(user.getStatus())) {
			log.info("登录用户：{} 已被停用.", username);
			throw new ServiceException("对不起，您的账号：" + username + " 已停用");
		}

		return createLoginUser(user);
	}

	public UserDetails createLoginUser(SysUser user) {
		return new LoginUser(user.getUserId(), user.getDeptId(), user, permissionService.getMenuPermission(user));
	}
}
~~~

### 7、添加CasAuthenticationSuccessHandler.java

在framework模块下添加：

~~~java
package com.ruoyi.framework.security.handle;

import com.ruoyi.common.constant.Constants;
import com.ruoyi.common.core.domain.model.LoginUser;
import com.ruoyi.framework.config.properties.CasProperties;
import com.ruoyi.framework.web.service.TokenService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;


@Service
public class CasAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

	protected final Log logger = LogFactory.getLog(this.getClass());

	private RequestCache requestCache = new HttpSessionRequestCache();

	@Autowired
	private TokenService tokenService;

	@Autowired
	private CasProperties casProperties;

	/**
	 * 令牌有效期（默认30分钟）
	 */
	@Value("${token.expireTime}")
	private int expireTime;

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
										Authentication authentication) throws ServletException, IOException {
		String targetUrlParameter = getTargetUrlParameter();
		if (isAlwaysUseDefaultTargetUrl()
				|| (targetUrlParameter != null && StringUtils.hasText(request.getParameter(targetUrlParameter)))) {
			requestCache.removeRequest(request, response);
			super.onAuthenticationSuccess(request, response, authentication);
			return;
		}
		clearAuthenticationAttributes(request);
		LoginUser userDetails = (LoginUser) authentication.getPrincipal();
		String token = tokenService.createToken(userDetails);
		//往Cookie中设置token
		Cookie casCookie = new Cookie(Constants.WEB_TOKEN_KEY, token);
		casCookie.setMaxAge(expireTime * 60);
		response.addCookie(casCookie);
		//设置后端认证成功标识
		HttpSession httpSession = request.getSession();
		httpSession.setAttribute(Constants.CAS_TOKEN, token);
		//登录成功后跳转到前端登录页面
		getRedirectStrategy().sendRedirect(request, response, casProperties.getWebUrl());
	}
}
~~~

### 8、修改SecurityConfig

 添加cas的处理逻辑： 

~~~java
package com.ruoyi.framework.config;

import com.ruoyi.framework.config.properties.CasProperties;
import com.ruoyi.framework.security.handle.CasAuthenticationSuccessHandler;
import com.ruoyi.framework.web.service.CasUserDetailsService;
import org.jasig.cas.client.session.SingleSignOutFilter;
import org.jasig.cas.client.validation.Cas20ServiceTicketValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.filter.CorsFilter;
import com.ruoyi.framework.security.filter.JwtAuthenticationTokenFilter;
import com.ruoyi.framework.security.handle.AuthenticationEntryPointImpl;
import com.ruoyi.framework.security.handle.LogoutSuccessHandlerImpl;

/**
 * spring security配置
 * 
 * @author ruoyi
 */
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter
{
    @Autowired
    private CasProperties casProperties;

    @Autowired
    private CasUserDetailsService customUserDetailsService;

    @Autowired
    private CasAuthenticationSuccessHandler casAuthenticationSuccessHandler;
    
    /**
     * 自定义用户认证逻辑
     */
    @Autowired
    private UserDetailsService userDetailsService;

    /**
     * 认证失败处理类
     */
    @Autowired
    private AuthenticationEntryPointImpl unauthorizedHandler;

    /**
     * 退出处理类
     */
    @Autowired
    private LogoutSuccessHandlerImpl logoutSuccessHandler;

    /**
     * token认证过滤器
     */
    @Autowired
    private JwtAuthenticationTokenFilter authenticationTokenFilter;

    /**
     * 跨域过滤器
     */
    @Autowired
    private CorsFilter corsFilter;


    /**
     * 解决 无法直接注入 AuthenticationManager
     *
     * @return
     * @throws Exception
     */
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /**
     * anyRequest          |   匹配所有请求路径
     * access              |   SpringEl表达式结果为true时可以访问
     * anonymous           |   匿名可以访问
     * denyAll             |   用户不能访问
     * fullyAuthenticated  |   用户完全认证可以访问（非remember-me下自动登录）
     * hasAnyAuthority     |   如果有参数，参数表示权限，则其中任何一个权限可以访问
     * hasAnyRole          |   如果有参数，参数表示角色，则其中任何一个角色可以访问
     * hasAuthority        |   如果有参数，参数表示权限，则其权限可以访问
     * hasIpAddress        |   如果有参数，参数表示IP地址，如果用户IP和参数匹配，则可以访问
     * hasRole             |   如果有参数，参数表示角色，则其角色可以访问
     * permitAll           |   用户可以任意访问
     * rememberMe          |   允许通过remember-me登录的用户访问
     * authenticated       |   用户登录后可访问
     */
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {

        if (!casProperties.isCasEnable()) {
            httpSecurity
                    // CSRF禁用，因为不使用session
                    .csrf().disable()
                    // 认证失败处理类
                    .exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()
                    // 基于token，所以不需要session
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                    // 过滤请求
                    .authorizeRequests()
                    // 对于登录login 注册register 验证码captchaImage 允许匿名访问
                    .antMatchers("/login", "/register", "/captchaImage").anonymous()
                    .antMatchers(
                            HttpMethod.GET,
                            "/",
                            "/*.html",
                            "/**/*.html",
                            "/**/*.css",
                            "/**/*.js",
                            "/profile/**"
                    ).permitAll()
                    .antMatchers("/common/download**").anonymous()
                    .antMatchers("/common/download/resource**").anonymous()
                    .antMatchers("/swagger-ui.html").anonymous()
                    .antMatchers("/swagger-resources/**").anonymous()
                    .antMatchers("/webjars/**").anonymous()
                    .antMatchers("/*/api-docs").anonymous()
                    .antMatchers("/druid/**").anonymous()
                    .antMatchers("/websocket/**").anonymous()
                    .antMatchers("/magic/web/**").anonymous()
                    // 除上面外的所有请求全部需要鉴权认证
                    .anyRequest().authenticated()
                    .and()
                    .headers().frameOptions().disable();
            httpSecurity.logout().logoutUrl("/logout").logoutSuccessHandler(logoutSuccessHandler);
            // 添加JWT filter
            httpSecurity.addFilterBefore(authenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);
            // 添加CORS filter
            httpSecurity.addFilterBefore(corsFilter, JwtAuthenticationTokenFilter.class);
            httpSecurity.addFilterBefore(corsFilter, LogoutFilter.class);
        }

        //开启cas
        if (casProperties.isCasEnable()) {
            httpSecurity
                    // CSRF禁用，因为不使用session
                    .csrf().disable()
                    // 基于token，所以不需要session
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                    // 过滤请求
                    .authorizeRequests()
                    // 对于登录login 验证码captchaImage 允许匿名访问
                    //.antMatchers("/login", "/captchaImage").anonymous()
                    .antMatchers(
                            HttpMethod.GET,
                            "/*.html",
                            "/**/*.html",
                            "/**/*.css",
                            "/**/*.js"
                    ).permitAll()
                    .antMatchers("/profile/**").anonymous()
                    .antMatchers("/common/download**").anonymous()
                    .antMatchers("/common/download/resource**").anonymous()
                    .antMatchers("/swagger-ui.html").anonymous()
                    .antMatchers("/swagger-resources/**").anonymous()
                    .antMatchers("/webjars/**").anonymous()
                    .antMatchers("/*/api-docs").anonymous()
                    .antMatchers("/druid/**").anonymous()
                    .antMatchers("/websocket/**").anonymous()
                    .antMatchers("/magic/web/**").anonymous()
                    // 除上面外的所有请求全部需要鉴权认证
                    .anyRequest().authenticated()
                    .and()
                    .headers().frameOptions().disable();
            //单点登录登出
            httpSecurity.logout().permitAll().logoutSuccessHandler(logoutSuccessHandler);
            // Custom JWT based security filter
            httpSecurity.addFilter(casAuthenticationFilter())
                    .addFilterBefore(authenticationTokenFilter, CasAuthenticationFilter.class)
                    //.addFilterBefore(casLogoutFilter(), LogoutFilter.class)
                    .addFilterBefore(singleSignOutFilter(), CasAuthenticationFilter.class).exceptionHandling()
                    //认证失败
                    .authenticationEntryPoint(casAuthenticationEntryPoint());

            // 添加CORS filter
            httpSecurity.addFilterBefore(corsFilter, JwtAuthenticationTokenFilter.class);
            httpSecurity.addFilterBefore(corsFilter, LogoutFilter.class);
            // disable page caching
            httpSecurity.headers().cacheControl();
        }
    }

    /**
     * 强散列哈希加密实现
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 身份认证接口
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        if (!casProperties.isCasEnable()) {
            auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder());
        }
        // cas
        if (casProperties.isCasEnable()) {
            super.configure(auth);
            auth.authenticationProvider(casAuthenticationProvider());
        }
    }


    /**
     * 认证的入口
     */
    @Bean
    public CasAuthenticationEntryPoint casAuthenticationEntryPoint() {
        CasAuthenticationEntryPoint casAuthenticationEntryPoint = new CasAuthenticationEntryPoint();
        casAuthenticationEntryPoint.setLoginUrl(casProperties.getCasServerLoginUrl());
        casAuthenticationEntryPoint.setServiceProperties(serviceProperties());
        return casAuthenticationEntryPoint;
    }

    /**
     * 指定service相关信息
     */
    @Bean
    public ServiceProperties serviceProperties() {
        ServiceProperties serviceProperties = new ServiceProperties();
        serviceProperties.setService(casProperties.getAppServerUrl() + casProperties.getAppLoginUrl());
        serviceProperties.setAuthenticateAllArtifacts(true);
        return serviceProperties;
    }

    /**
     * CAS认证过滤器
     */
    @Bean
    public CasAuthenticationFilter casAuthenticationFilter() throws Exception {
        CasAuthenticationFilter casAuthenticationFilter = new CasAuthenticationFilter();
        casAuthenticationFilter.setAuthenticationManager(authenticationManager());
        casAuthenticationFilter.setFilterProcessesUrl(casProperties.getAppLoginUrl());
        casAuthenticationFilter.setAuthenticationSuccessHandler(casAuthenticationSuccessHandler);
        return casAuthenticationFilter;
    }

    /**
     * cas 认证 Provider
     */
    @Bean
    public CasAuthenticationProvider casAuthenticationProvider() {
        CasAuthenticationProvider casAuthenticationProvider = new CasAuthenticationProvider();
        casAuthenticationProvider.setAuthenticationUserDetailsService(customUserDetailsService);
        casAuthenticationProvider.setServiceProperties(serviceProperties());
        casAuthenticationProvider.setTicketValidator(cas20ServiceTicketValidator());
        casAuthenticationProvider.setKey("casAuthenticationProviderKey");
        return casAuthenticationProvider;
    }

    @Bean
    public Cas20ServiceTicketValidator cas20ServiceTicketValidator() {
        return new Cas20ServiceTicketValidator(casProperties.getCasServerUrl());
    }

    /**
     * 单点登出过滤器
     */
    @Bean
    public SingleSignOutFilter singleSignOutFilter() {
        SingleSignOutFilter singleSignOutFilter = new SingleSignOutFilter();
        singleSignOutFilter.setCasServerUrlPrefix(casProperties.getCasServerUrl());
        singleSignOutFilter.setIgnoreInitConfiguration(true);
        return singleSignOutFilter;
    }

    /**
     * 请求单点退出过滤器
     */
    @Bean
    public LogoutFilter casLogoutFilter() {
        LogoutFilter logoutFilter = new LogoutFilter(casProperties.getCasServerLogoutUrl(),
                new SecurityContextLogoutHandler());
        logoutFilter.setFilterProcessesUrl(casProperties.getAppLogoutUrl());
        return logoutFilter;
    }
}
~~~

### 9、启动后端

访问后端地址成功跳转cas登录页

完整代码：[ RuoYi-Vue集成cas ](https://gitee.com/ggxforever/RuoYi-Vue-cas)

![1631356596644](https://gitee.com/ggxforever/ImageBed/raw/master/RuoYi-Vue-cas/1631356596644.png)

## 二、前端配置

### 1、修改settings.js

 添加cas登录和登出地址： 

~~~javascript
 	/**
     * 开启cas
     */
    casEnable: true,

    /**
     * 单点登录url
     */
    casloginUrl: 'http://localhost:8888/cas/login?service=http://localhost:8080',

    /**
     * 单点登出url
     */
    caslogoutUrl: 'http://localhost:8888/cas/logout?service=http://localhost:8080',
~~~

### 2、修改permission.js

 判断没有token时访问cas登录页面： 

~~~javascript
import router from './router'
import store from './store'
import { Message } from 'element-ui'
import NProgress from 'nprogress'
import 'nprogress/nprogress.css'
import { getToken } from '@/utils/auth'

NProgress.configure({ showSpinner: false })

const whiteList = ['/login', '/auth-redirect', '/bind', '/register']
const defaultSettings = require('@/settings.js')

router.beforeEach((to, from, next) => {
    NProgress.start()
    if (getToken()) {
        to.meta.title && store.dispatch('settings/setTitle', to.meta.title)
            /* has token*/
        if (to.path === '/login') {
            next({ path: '/' })
            NProgress.done()
        } else {
            if (store.getters.roles.length === 0) {
                // 判断当前用户是否已拉取完user_info信息
                store.dispatch('GetInfo').then(() => {
                    store.dispatch('GenerateRoutes').then(accessRoutes => {
                        // 根据roles权限生成可访问的路由表
                        router.addRoutes(accessRoutes) // 动态添加可访问路由表
                        next({...to, replace: true }) // hack方法 确保addRoutes已完成
                    })
                }).catch(err => {
                    store.dispatch('LogOut').then(() => {
                        Message.error(err)
                        next({ path: '/' })
                    })
                })
            } else {
                next()
            }
        }
    } else {
        // 没有token
        if (whiteList.indexOf(to.path) !== -1) {
            // 在免登录白名单，直接进入
            next()
        } else {
            if (!defaultSettings.casEnable) {
                next(`/login?redirect=${to.fullPath}`) // 否则全部重定向到登录页
            }
            //开启cas
            if (defaultSettings.casEnable) {
                window.location.href = defaultSettings.casloginUrl // 否则全部重定向到登录页
            }
            NProgress.done()
        }
    }
})

router.afterEach(() => {
    NProgress.done()
})
~~~

### 3、修改request.js、Navbar.vue

 登出后不做响应： 

~~~javascript
import axios from 'axios'
import { Notification, MessageBox, Message } from 'element-ui'
import store from '@/store'
import { getToken } from '@/utils/auth'
import errorCode from '@/utils/errorCode'

axios.defaults.headers['Content-Type'] = 'application/json;charset=utf-8'
const defaultSettings = require('@/settings')

// 创建axios实例
const service = axios.create({
        // axios中请求配置有baseURL选项，表示请求URL公共部分
        baseURL: process.env.VUE_APP_BASE_API,
        // 超时
        timeout: 10000
    })
    // request拦截器
service.interceptors.request.use(config => {
    // 是否需要设置 token
    const isToken = (config.headers || {}).isToken === false
    if (getToken() && !isToken) {
        config.headers['Authorization'] = 'Bearer ' + getToken() // 让每个请求携带自定义token 请根据实际情况自行修改
    }
    // get请求映射params参数
    if (config.method === 'get' && config.params) {
        let url = config.url + '?';
        for (const propName of Object.keys(config.params)) {
            const value = config.params[propName];
            var part = encodeURIComponent(propName) + "=";
            if (value !== null && typeof(value) !== "undefined") {
                if (typeof value === 'object') {
                    for (const key of Object.keys(value)) {
                        if (value[key] !== null && typeof(value[key]) !== 'undefined') {
                            let params = propName + '[' + key + ']';
                            let subPart = encodeURIComponent(params) + '=';
                            url += subPart + encodeURIComponent(value[key]) + '&';
                        }
                    }
                } else {
                    url += part + encodeURIComponent(value) + "&";
                }
            }
        }
        url = url.slice(0, -1);
        config.params = {};
        config.url = url;
    }
    return config
}, error => {
    console.log(error)
    Promise.reject(error)
})

// 响应拦截器
service.interceptors.response.use(res => {
        // 未设置状态码则默认成功状态
        const code = res.data.code || 200;
        // 获取错误信息
        const msg = errorCode[code] || res.data.msg || errorCode['default']
        if (code === 401) {
            MessageBox.confirm('登录状态已过期，您可以继续留在该页面，或者重新登录', '系统提示', {
                confirmButtonText: '重新登录',
                cancelButtonText: '取消',
                type: 'warning'
            }).then(() => {
                store.dispatch('LogOut').then(() => {
                    if (!defaultSettings.casEnable) {
                        location.href = '/index';
                    }
                })
            }).catch(() => {});
            return Promise.reject('无效的会话，或者会话已过期，请重新登录。')
        } else if (code === 500) {
            Message({
                message: msg,
                type: 'error'
            })
            return Promise.reject(new Error(msg))
        } else if (code !== 200) {
            Notification.error({
                title: msg
            })
            return Promise.reject('error')
        } else {
            return res.data
        }
    },
    error => {
        console.log('err' + error)
        let { message } = error;
        if (message == "Network Error") {
            message = "后端接口连接异常";
        } else if (message.includes("timeout")) {
            message = "系统接口请求超时";
        } else if (message.includes("Request failed with status code")) {
            message = "系统接口" + message.substr(message.length - 3) + "异常";
        }
        Message({
            message: message,
            type: 'error',
            duration: 5 * 1000
        })
        return Promise.reject(error)
    }
)

export default service
~~~

~~~javascript
import { mapGetters } from "vuex";
import Breadcrumb from "@/components/Breadcrumb";
import TopNav from "@/components/TopNav";
import Hamburger from "@/components/Hamburger";
import Screenfull from "@/components/Screenfull";
import SizeSelect from "@/components/SizeSelect";
import Search from "@/components/HeaderSearch";
import RuoYiGit from "@/components/RuoYi/Git";
import RuoYiDoc from "@/components/RuoYi/Doc";
import settings from "@/settings";

export default {
  components: {
    Breadcrumb,
    TopNav,
    Hamburger,
    Screenfull,
    SizeSelect,
    Search,
    RuoYiGit,
    RuoYiDoc,
  },
  computed: {
    ...mapGetters(["sidebar", "avatar", "device"]),
    setting: {
      get() {
        return this.$store.state.settings.showSettings;
      },
      set(val) {
        this.$store.dispatch("settings/changeSetting", {
          key: "showSettings",
          value: val,
        });
      },
    },
    topNav: {
      get() {
        return this.$store.state.settings.topNav;
      },
    },
  },
  methods: {
    toggleSideBar() {
      this.$store.dispatch("app/toggleSideBar");
    },
    async logout() {
      this.$confirm("确定注销并退出系统吗？", "提示", {
        confirmButtonText: "确定",
        cancelButtonText: "取消",
        type: "warning",
      })
        .then(() => {
          this.$store.dispatch("LogOut").then(() => {
            if (!settings.casEnable) {
              location.href = this.$router.options.base + "/index";
            }
          });
        })
        .catch(() => {});
    },
  },
};
~~~

### 4、修改user.js

 登出后跳转到cas登出页面： 

~~~javascript
	// 退出系统
        LogOut({ commit, state }) {
            return new Promise((resolve, reject) => {
                logout(state.token).then(() => {
                    commit('SET_TOKEN', '')
                    commit('SET_ROLES', [])
                    commit('SET_PERMISSIONS', [])
                    removeToken()
                    resolve()
                    window.location.href = defaultSettings.caslogoutUrl
                }).catch(error => {
                    reject(error)
                })
            })
        },
~~~

### 5、启动前端

访问首页跳转登录页，测试cas是否正常登录登出。

完整代码：[ RuoYi-Vue集成cas ](https://gitee.com/ggxforever/RuoYi-Vue-cas)

![1631357903966](https://gitee.com/ggxforever/ImageBed/raw/master/RuoYi-Vue-cas/1631357903966.png)

![1631357979941](https://gitee.com/ggxforever/ImageBed/raw/master/RuoYi-Vue-cas/1631357979941.png)

### 6、关闭cas

casEnable设置为false，则不启用cas登录。

前后端配置casEnable需要保持一致。

