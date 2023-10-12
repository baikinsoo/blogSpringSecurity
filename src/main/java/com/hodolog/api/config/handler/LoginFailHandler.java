package com.hodolog.api.config.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hodolog.api.response.ErrorResponse;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Slf4j
@RequiredArgsConstructor
public class LoginFailHandler implements AuthenticationFailureHandler {

    private final ObjectMapper objectMapper;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
      log.error("[인증오류] 아이디 혹은 비밀번호가 올바르지 않습니다.");

        ErrorResponse errorResponse = ErrorResponse.builder()
                .code("400")
                .message("아이디 혹은 비밀번호가 올바르지 않습니다.")
                .build();

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        //응답 한글이 꺠지는 것을 해결하기 위함 -> 좀 알아봐야 할듯

        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        //스프링도 오류와 관련된 enum이 있다.

//        String json = objectMapper.writeValueAsString(errorResponse);
//        response.getWriter().write(json);

        objectMapper.writeValue(response.getWriter(), errorResponse);
        //위에 2개를 합친 코드가 위와 같다.

    }
}
