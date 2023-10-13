package com.hodolog.api.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hodolog.api.config.filter.EmailPasswordAuthFilter;
import com.hodolog.api.config.handler.Http401Handler;
import com.hodolog.api.config.handler.Http403Handler;
import com.hodolog.api.config.handler.LoginFailHandler;
import com.hodolog.api.config.handler.LoginSuccessHandler;
import com.hodolog.api.domain.User;
import com.hodolog.api.repository.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cglib.proxy.NoOp;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
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
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.session.security.web.authentication.SpringSessionRememberMeServices;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.io.IOException;
import java.net.URL;

import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toH2Console;

@Slf4j
@Configuration
@EnableWebSecurity(debug = true)
@RequiredArgsConstructor
@EnableMethodSecurity
//이것만 달아주면 메서드 시큐리티가 가능하다.
// debug 달면 log가 더 잘뜬다. 운영환경에선 사용하면 안된다.
public class SecurityConfig {

    private final ObjectMapper objectMapper;
    private final UserRepository userRepository;

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

//                    .requestMatchers("/auth/login").permitAll()
//                    .requestMatchers("/auth/signup").permitAll()
                .anyRequest().permitAll()
                // 모든 사람들을 허용하기 위해 변경한다.

//                .requestMatchers("/user").hasRole("USER")
//                .requestMatchers("/user").hasAnyRole("USER", "ADMIN")
                // 관리자는 사용자 페이지도 접근 가능해야 하기 때문에 hasAnyRole을 통해 여러 권한을 줄 수 있다.
//                .requestMatchers("/admin").hasRole("ADMIN")
                // 컨트롤러에서 역할을 부여할 것이다.

                //이건 일반적인 경우 사용
//                .requestMatchers("/admin").access(new WebExpressionAuthorizationManager("hasRole('ADMIN') AND hasAuthority('WRITE')"))
                //역할과 권한을 둘 다 조건으로 줘야 할 때
                //hasRole과 hasAuthority가 있다.
                //여기서는 ROLE를 붙일 필요는 굳이 없다.
                    //애는 권한 없이도 허용
                    //나머지는 인증해
                .and()

//                .formLogin()
//                    .loginPage("/auth/login")
//                    //로그인 페이지 주소
//                    .loginProcessingUrl("/auth/login")
//                    //실제 post로 값을 받아서 검증을 하는 주소
//                    .usernameParameter("username")
//                    .passwordParameter("password")
//                    .defaultSuccessUrl("/")
//                //성공한 뒤 이동하는 페이지
//                    .failureHandler(new LoginFailHandler(objectMapper))
//                //로그인 실패시 발생하는 핸들러
//                .and()

                .addFilterBefore(emailPasswordAuthFilter(), UsernamePasswordAuthenticationFilter.class)
                // 새롭게 구현한 email~~() filter가 User~~() filter 이전에 실행되도록 한다.

                .exceptionHandling(e -> {
                    e.accessDeniedHandler(new Http403Handler(objectMapper));
                    e.authenticationEntryPoint(new Http401Handler(objectMapper));
                            //로그인이 필요한 페이지인데 로그인이 안된 상태에서 접근 했을 때
                })
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
    public EmailPasswordAuthFilter emailPasswordAuthFilter() {
        EmailPasswordAuthFilter filter = new EmailPasswordAuthFilter("/auth/login", objectMapper);
        filter.setAuthenticationManager(authenticationManager());
//        filter.setAuthenticationSuccessHandler(new SimpleUrlAuthenticationSuccessHandler("/"));
        filter.setAuthenticationSuccessHandler(new LoginSuccessHandler(objectMapper));
        filter.setAuthenticationFailureHandler(new LoginFailHandler(objectMapper));
        filter.setSecurityContextRepository(new HttpSessionSecurityContextRepository());
        //실제로 인증이 완료되었을 때 요청 내에서 인증이 유효하도록 이게 있어야 세션이 발급된다.

        SpringSessionRememberMeServices rememberMeServices = new SpringSessionRememberMeServices();
        rememberMeServices.setAlwaysRemember(true);
        rememberMeServices.setValiditySeconds(3600 * 24 * 30);
        filter.setRememberMeServices(rememberMeServices);
        return filter;
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService(userRepository));
        provider.setPasswordEncoder(passwordEncoder());
        return new ProviderManager(provider);
        //ProviderManager 얘를 기본적으로 사용한다.
    }
//

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
