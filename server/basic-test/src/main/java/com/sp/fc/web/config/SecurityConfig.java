package com.sp.fc.web.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

//@Order(1)
// SecurityConfig 작동순서 1부터...
@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().
                withUser(
                User.builder()
                        .username("user2")
                        .password(passwordEncoder().encode("2"))
                        .roles("USER")
                ).withUser(
                        User.builder()
                                .username("admin")
                                .password(passwordEncoder().encode("1"))
                                .roles("ADMIN")
                )
        ;
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests((requests) -> {
//            ((
//                    ExpressionUrlAuthorizationConfigurer.AuthorizedUrl)requests
//                    .antMatchers("/").permitAll()
//                    .anyRequest()).authenticated();
//        });
        http.antMatcher("/api/**");
        http.formLogin();
        http.httpBasic();
        http.headers().disable()
                .csrf().disable()
                .logout().disable()
                .requestCache().disable()
                ;
    }
}
