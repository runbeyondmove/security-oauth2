package cn.merryyou.security.server;

import cn.merryyou.security.config.AuthExceptionEntryPoint;
import cn.merryyou.security.permit.PermitAllSecurityConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/**
 * Created on 2018/1/17.
 *
 * 配置资源服务器
 *
 * EnableResourceServer注解：Oauth2 资源服务器的便利方法，开启了一个spring security的filter，这个filter通过一个Oauth2的token进行认证请求。
 * 主要流程：ResourceServerConfiguration#configure --> new ResourceServerSecurityConfigurer() --> new OAuth2AuthenticationProcessingFilter()
 *      OAuth2AuthenticationProcessingFilter：用来作为认证令牌（Token）的一个处理流程过滤器。只有当过滤器通过之后，请求者才能获得受保护的资源
 *
 * 使用者应该增加这个注解，并提供一个ResourceServerConfigurer类型的Bean(例如通过ResouceServerConfigurerAdapter)来指定资源(url路径和资源id)的细节。
 * 为了利用这个filter，你必须在你的应用中的某些地方EnableWebSecurity，或者使用这个注解的地方，或者其他别的地方。
 *
 * 这个注解创建了一个WebSecurityConfigurerAdapter，且自带了硬编码的order=3（可以查看EnableResourceServer注解）. 在spring中，由于技术原因不能立即改变order的顺序，
 * 因此你必须在你的spring应用中避免使用order=3的其他WebSecurityConfigurerAdapter。
 *
 *  特别注意：如果你的应用程序中既包含授权服务又包含资源服务的话，那么这里实际上是另一个的低优先级的过滤器来控制资源接口的，
 *  这些接口是被保护在了一个访问令牌（access token）中，所以请挑选一个URL链接来确保你的资源接口中有一个不需要被保护的链接用来取得授权，
 *  就如 /login 链接，你需要在 WebSecurityConfigurer配置对象中（子类）进行设置。
 *  一句话就是：资源服务器（MerryyouResourceServerConfig）的优先级比SecurityConfig的优先级高
 *
 * 参考文章：
 * https://www.cnblogs.com/davidwang456/p/6480681.html
 * https://www.cnblogs.com/cjsblog/p/9184173.html
 *
 * @author zlf
 * @since 1.0
 */
@Configuration
@EnableResourceServer // 标记为资源服务器，开启了一个spring security的filter，这个filter通过一个Oauth2的token进行认证请求
public class MerryyouResourceServerConfig extends ResourceServerConfigurerAdapter {
    /**
     * 自定义登录成功处理器
     */
    @Autowired
    private AuthenticationSuccessHandler appLoginInSuccessHandler;

    @Autowired
    private AuthenticationFailureHandler appLoginFailureHandler;

    @Autowired
    private PermitAllSecurityConfig permitAllSecurityConfig;

    /**
     * 配置资源的访问权限
     *
     * @param http
     * @throws Exception
     */
    @Override
    public void configure(HttpSecurity http) throws Exception {

        // @formatter:off
        http.formLogin().permitAll()
                .successHandler(appLoginInSuccessHandler)//登录成功处理器
                //.failureHandler(appLoginFailureHandler)
                //.and()
                //    .exceptionHandling().authenticationEntryPoint(new AuthExceptionEntryPoint())
                //.and()
                //    .apply(permitAllSecurityConfig)
                .and()
                    .authorizeRequests()
                    .antMatchers("/user").hasRole("USER")
                    .antMatchers("/forbidden").hasRole("ADMIN")
                    .antMatchers("/permitAll").permitAll()
                    .anyRequest().authenticated()
                .and()
                    .csrf().disable();



//        http.formLogin().permitAll()
//                //.successHandler(appLoginInSuccessHandler)//登录成功处理器
////                .sessionManagement()
////                    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
////                    .and()
////                .requestMatchers()
////                // 保险起见，防止被主过滤器链路拦截，控制登陆后才能访问
////                .antMatchers("/")
//                .and()
//                    .authorizeRequests()
//                    .antMatchers("/user").hasRole("USER")
//                    .antMatchers("/forbidden").hasRole("ADMIN")
//                    .antMatchers("/permitAll").permitAll()
//                    .anyRequest().authenticated()
//                .and()
//                    .csrf().disable();
        // @formatter:ON
    }

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.authenticationEntryPoint(new AuthExceptionEntryPoint());
    }
}
