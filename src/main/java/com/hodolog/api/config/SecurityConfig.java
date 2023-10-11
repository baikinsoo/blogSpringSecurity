package com.hodolog.api.config;

import com.hodolog.api.domain.User;
import com.hodolog.api.repository.UserRepository;
import org.springframework.cglib.proxy.NoOp;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.RememberMeConfigurer;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toH2Console;

@Configuration
@EnableWebSecurity(debug = true)
// debug 달면 log가 더 잘뜬다. 운영환경에선 사용하면 안된다.
public class SecurityConfig {

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return new WebSecurityCustomizer() {
            @Override
            public void customize(WebSecurity web) {
                web.ignoring()
                        .requestMatchers("/favicon.ico")
                        .requestMatchers("/error")
                        .requestMatchers(toH2Console());
            }
        };
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        return http
                .authorizeHttpRequests()
//                    .requestMatchers(HttpMethod.POST,"/auth/login").permitAll()
//                    .requestMatchers(HttpMethod.POST,"/auth/signup").permitAll()
                //위의 방법을 사용하면 무한 페이지 리다이렉트 될 수 있다...?
                    .requestMatchers("/auth/login").permitAll()
                    .requestMatchers("/auth/signup").permitAll()
//                .requestMatchers("/user").hasRole("USER")
                .requestMatchers("/user").hasAnyRole("USER", "ADMIN")
                // 관리자는 사용자 페이지도 접근 가능해야 하기 때문에 hasAnyRole을 통해 여러 권한을 줄 수 있다.
//                .requestMatchers("/admin").hasRole("ADMIN")
                //이건 일반적인 경우 사용
                .requestMatchers("/admin").access(new WebExpressionAuthorizationManager("hasRole('ADMIN') AND hasAuthority('WRITE')"))
                //역할과 권한을 둘 다 조건으로 줘야 할 때
                //hasRole과 hasAuthority가 있다.
                //여기서는 ROLE를 붙일 필요는 굳이 없다.
                    //애는 권한 없이도 허용
                    .anyRequest().authenticated()
                    //나머지는 인증해
                .and()
                .formLogin()
                    .loginPage("/auth/login")
                    //로그인 페이지 주소
                    .loginProcessingUrl("/auth/login")
                    //실제 post로 값을 받아서 검증을 하는 주소
                    .usernameParameter("username")
                    .passwordParameter("password")
                    .defaultSuccessUrl("/")
                //성공한 뒤 이동하는 페이지
                .and()
                .rememberMe(new Customizer<RememberMeConfigurer<HttpSecurity>>() {
                                @Override
                                public void customize(RememberMeConfigurer<HttpSecurity> rm) {
                                    rm.rememberMeParameter("remember")
                                            .alwaysRemember(false)
                                            .tokenValiditySeconds(2592000);
                                }
                            }
                        )
                //로그인 기억하기 위한 메서드
//                .userDetailsService(userDetailsService())
                //-> 안넣어도 아래 Bean으로 등록하면 알아서 적용된다?
                //csrf쪽으로는 builder가 이어지지 않기 때문에 and로 이어준다.
                .csrf(AbstractHttpConfigurer::disable)
                .build();
    }

    @Bean
    public UserDetailsService userDetailsService(UserRepository userRepository) {
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                //로그인 페이지에서 username으로 넘어오는 값 즉, id에 해당하는 값을 받아서
                User user = userRepository.findByEmail(username)
                        //DB에서 해당 값을 찾는다.
                        .orElseThrow(() -> new UsernameNotFoundException(username + "을 찾을 수 없습니다."));
                return new UserPrincipal(user);
            }
        };
//        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
//        UserDetails user = User.withUsername("bis")
//                .password("1234")
//                .roles("ADMIN")
//                .build();
//        manager.createUser(user);
//        return manager;
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new SCryptPasswordEncoder(
                16,
                8,
                1,
                32,
                64
        );
    }

//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception{
//        http.authorizeHttpRequests((authz) -> {
//            try {
//                authz
//                        .requestMatchers(new MvcRequestMatcher(introspector,"/auth/login")).permitAll()
//                        //애는 권한 없이도 허용
//                        .anyRequest().authenticated()
//                        //나머지는 인증해
//                        .and()
//                        //csrf쪽으로는 builder가 이어지지 않기 때문에 and로 이어준다.
//                        .csrf(AbstractHttpConfigurer::disable);
//            } catch (Exception e) {
//                throw new RuntimeException(e);
//            }
//        });
//        return http.build();
//    }
}
