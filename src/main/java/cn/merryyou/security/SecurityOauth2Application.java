package cn.merryyou.security;

import cn.merryyou.security.properties.OAuth2Properties;
import cn.merryyou.security.utils.JsonUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;

/**
 * 入口
 */
@RestController
@SpringBootApplication
@Slf4j
public class SecurityOauth2Application {

    @Autowired
    private OAuth2Properties oAuth2Properties;

    public static void main(String[] args) {
        SpringApplication.run(SecurityOauth2Application.class, args);
    }

    @GetMapping("/user")
    public Object getCurrentUser1(Authentication authentication, HttpServletRequest request) throws UnsupportedEncodingException {
        log.info("【SecurityOauth2Application】 getCurrentUser1 authenticaiton={}", JsonUtil.toJson(authentication));

        String header = request.getHeader("Authorization");
        String token = StringUtils.substringAfter(header, "bearer ");

        Claims claims = Jwts.parser().setSigningKey(oAuth2Properties.getJwtSigningKey().getBytes("UTF-8")).parseClaimsJws(token).getBody();
        String blog = (String) claims.get("blog");
        log.info("【SecurityOauth2Application】 getCurrentUser1 blog={}", blog);

        return authentication;
    }

    @GetMapping("/forbidden")
    public String getForbidden() {
        return "forbidden";
    }

    @GetMapping("/permitAll")
    public String getPermitAll() {
        return "permitAll";
    }

    @GetMapping("/aa")
    public String index() {
        return "aa";
    }
}
