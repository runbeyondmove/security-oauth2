package cn.merryyou.security.security;

import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

//import cn.merryyou.security.handler.AppLogoutSuccessHandler;

/**
 * Created on 2018/1/19.
 *
 * @author zlf
 * @since 1.0
 */
@Configuration
@EnableWebSecurity
//@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
public class SecurityConfig extends WebSecurityConfigurerAdapter{

    /**
     * 默认实现：http.authorizeRequests().anyRequest().authenticated().and().formLogin().and().httpBasic();
     * 	* 要求访问应用的所有用户都要被验证
     *  * 允许所有用户可以通过表单进行验证
     *  * 允许所有请求通过Http Basic 验证
     *
     *  WebSecurityConfigurerAdapter   @Order(100)
     *
     *  执行的顺序按照此值从小到大执行，即值小优先级高
     *
     *
     *  WebSecurityConfigurerAdapter是默认情况下spring security的http配置  >>>>>>order=100
     *  ResourceServerConfigurerAdapter是默认情况下spring security oauth2的http配置  >>>>>>order=3(硬编码，不可改变的)
     *
     *  官方文档：https://docs.spring.io/spring-security/site/docs/5.1.6.BUILD-SNAPSHOT/reference/htmlsingle/#tutorial-sample
     *
     * 特别是权限配置不清楚的最好看官方案例
     *
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // Java配置中的and()方法类似于xml配置中的结束标签，and()方法返回的对象还是HttpSecurity，方便我们继续对HttpSecurity进行配置。
        /*http.formLogin()
                .permitAll()
                .and()
                    .authorizeRequests()
                    .antMatchers("/session/invalid")
                    .permitAll()
                    .anyRequest()
                    .authenticated()
                .and()
                    .sessionManagement()
                    .invalidSessionUrl("/session/invalid")
                    .maximumSessions(1)
                    .maxSessionsPreventsLogin(true)
    //                .expiredSessionStrategy(new MyExpiredSessionStrategy())
                    .sessionRegistry(sessionRegistry())
                .and()
                //.logout()
                //.permitAll().logoutSuccessHandler(appLoginInSuccessHandler)
                .and()
                .csrf().disable();*/


        /**
         * 以下是权限表达式的案例
         *
         * Spring Security其实就是一组过滤器链，可以了解一下它的原理
         *
         * 可以在authorizeRequests() 后定义多个antMatchers()配置器来控制不同的url接受不同权限的用户访问
         *
         * **/
        //http
        //            // 头部缓存
        //            .headers()
        //            .cacheControl()
        //        .and()
        //            // 防止网站被人嵌套
        //            .frameOptions()
        //            .sameOrigin()
        //        .and()
        //            .authorizeRequests()  // 表示后面都是授权请求（自定义哪些URL需要权限验证，哪些不需要）
        //            .antMatchers("/resources","/favicon.ico").permitAll() // 表示指定的路径都放行，不需要权限认证
        //            .antMatchers("/permitAll").permitAll()
        //            //.antMatchers( "/admin/**").hasRole("ADMIN" ) // 拥有admin角色才能访问指定的路径
        //            //.antMatchers( "/db/**").access("hasRole('ADMIN') and hasRole('DBA')") // 拥有两个角色才能访问
        //            .antMatchers("/js/**","css/**","/fonts/**","/static/**","/images/**").permitAll()
        //            .anyRequest() // 表示除开上面定义的路径，其他的路径
        //            .authenticated()  // 其他所有路径都需要认证
        //              // 总结就是：以上的路径可以根据角色或者权限放行，其他路径都需要认证
        //        .and()
        //            .formLogin() // 内部注册 UsernamePasswordAuthenticationFilter
        //            //.loginPage("/login.html") //表单登录页面地址
        //            //.loginProcessingUrl("/login")//form表单POST请求url提交地址，默认为/login
        //            //.passwordParameter("password")//form表单用户名参数名
        //            //.usernameParameter("username") //form表单密码参数名
        //            //.successForwardUrl("/success.html")  //登录成功跳转地址
        //            //.failureForwardUrl("/error.html") //登录失败跳转地址
        //            //.defaultSuccessUrl()//如果用户没有访问受保护的页面，默认跳转到页面
        //            //.failureUrl()
        //            //.failureHandler(AuthenticationFailureHandler)
        //            //.successHandler(AuthenticationSuccessHandler)
        //            //.failureUrl("/login?error")
        //            .permitAll()//允许所有用户都有权限访问登录页面，否则验证流程就会进入死循环
        //        .and()
        //            .csrf().disable()//默认开启，这里先显式关闭
        //        .cors(); //跨域支持


        //// 这里只控制一个登陆页面是可以放行的，其他的控制在资源管理器上
        //http.formLogin()
        //        .permitAll().and()
        //        // default protection for all resources (including /oauth/authorize)
        //        .authorizeRequests() .anyRequest().authenticated();



        //http.
        //        requestMatchers()
        //        // /oauth/authorize link org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint
        //        // 必须登录过的用户才可以进行 oauth2 的授权码申请
        //        .antMatchers("/", "/login","/oauth/authorize")
        //        .and()
        //        .authorizeRequests()
        //        .anyRequest().permitAll()
        //        .and()
        //        .formLogin()
        //        .and()
        //        .httpBasic()
        //        .disable()
        //        .exceptionHandling()
        //        .accessDeniedPage("/login?authorization_error=true")
        //        .and()
        //        // TODO: put CSRF protection back into this endpoint
        //        .csrf()
        //        .requireCsrfProtectionMatcher(new AntPathRequestMatcher("/oauth/authorize"))
        //        .disable();

        http
                    .requestMatchers()
                    .antMatchers("/oauth/authorize")
                .and()
                    .authorizeRequests().anyRequest().authenticated()
                .and()
                    .formLogin()
                .and()
                    .csrf().disable();
    }

    @Bean
    public SessionRegistry sessionRegistry() {
        SessionRegistry sessionRegistry = new SessionRegistryImpl();
        return sessionRegistry;
    }

    @Bean
    public static ServletListenerRegistrationBean httpSessionEventPublisher() {
        return new ServletListenerRegistrationBean(new HttpSessionEventPublisher());
    }

    /*@Bean
    protected LogoutSuccessHandler appLogoutSuccessHandler() {
        return new AppLogoutSuccessHandler();
    }*/

    /**
     * Spring Boot 2 配置，这里要bean 注入
     * springboot2.0 的自动配置发生略微的变更，原先的自动配置现在需要通过@Bean暴露，否则你会得到AuthenticationManager找不到的异常
     */
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        AuthenticationManager manager = super.authenticationManagerBean();
        return manager;
    }

    /**
     * Spring Boot 2，实际是spring security 5.0版本以上解决以下错误
     * java.lang.IllegalArgumentException: There is no PasswordEncoder mapped for the id "null"
     * @return
     */
    //@Bean
    //public PasswordEncoder passwordEncoder() {
    //    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    //}

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
