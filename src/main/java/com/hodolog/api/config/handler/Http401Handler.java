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
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Slf4j
@RequiredArgsConstructor
public class Http401Handler implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        log.error("[인증오류] 로그인이 필요합니다.");

        //HttpServletRequest,Response를 가지고 응답값을 활용해서 전달하면 해결이 될 것이다.

        ErrorResponse errorResponse = ErrorResponse.builder()
                .code("401")
                .message("로그인이 필요합니다.")
                .build();

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        //응답 한글이 꺠지는 것을 해결하기 위함 -> 좀 알아봐야 할듯

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        //스프링도 오류와 관련된 enum이 있다.

//        String json = objectMapper.writeValueAsString(errorResponse);
//        response.getWriter().write(json);

        objectMapper.writeValue(response.getWriter(), errorResponse);
        //위에 2개를 합친 코드가 위와 같다.
    }
}
