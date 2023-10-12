package com.hodolog.api.config;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.List;

public class UserPrincipal extends User {

    private final Long userId;

    // role: 역할 -> 관리자, 사용자, 매니저
    // authority: 권한 -> 글쓰기, 글 읽기, 사용자정지시키기


    public UserPrincipal(String username, String password, Collection<? extends GrantedAuthority> authorities, Long userId) {
        super(username, password, authorities);
        this.userId = userId;
    }
    //super을 통해 username, password, authorities를 넘긴다.

    public UserPrincipal(com.hodolog.api.domain.User user) {
        super(user.getEmail(), user.getPassword(),
                List.of(new SimpleGrantedAuthority("ROLE_USER")
        //이건 사실 역할이 아니라 권한이다. -> 위는 권한이기 때문에 ROLE을 붙이면 알아서 ROLE로 바꿔준다.
        //1. 역할 권한 둘 다 필요할때 권한만 있으면 정삭적인 접근이 안된다.
//                        new SimpleGrantedAuthority("READ")
//                        new SimpleGrantedAuthority("WRITE")
                ));
        this.userId = user.getId();
    }

    public Long getUserId() {
        return userId;
    }
}
