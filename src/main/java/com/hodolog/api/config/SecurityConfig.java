package com.hodolog.api.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

@Configuration
@EnableWebSecurity(debug = true)
// debug 달면 log가 더 잘뜬다. 운영환경에선 사용하면 안된다.
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception{
        http.authorizeHttpRequests((authz) -> {
            try {
                authz
                        .requestMatchers(new MvcRequestMatcher(introspector,"/auth/login")).permitAll()
                        //애는 권한 없이도 허용
                        .anyRequest().authenticated()
                        //나머지는 인증해
                        .and()
                        //csrf쪽으로는 builder가 이어지지 않기 때문에 and로 이어준다.
                        .csrf(AbstractHttpConfigurer::disable);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        return http.build();
    }
}
