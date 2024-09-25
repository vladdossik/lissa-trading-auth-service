package lissa.trading.auth.service.security;

import lissa.trading.auth.service.details.CustomUserDetails;
import lissa.trading.auth.service.details.CustomUserDetailsService;
import lissa.trading.auth.service.security.internal.InternalTokenFilter;
import lissa.trading.auth.service.security.internal.InternalTokenService;
import lissa.trading.auth.service.security.jwt.AuthTokenFilter;
import lissa.trading.auth.service.security.jwt.JwtService;
import lissa.trading.lissa.auth.lib.security.BaseAuthTokenFilter;
import lissa.trading.lissa.auth.lib.security.BaseWebSecurityConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableMethodSecurity
public class WebSecurityConfig extends BaseWebSecurityConfig {

    private final CustomUserDetailsService userDetailsService;
    private final AuthEntryPointJwt unauthorizedHandler;
    private final InternalTokenService internalTokenService;
    private final JwtService jwtService;

    public WebSecurityConfig(BaseAuthTokenFilter<CustomUserDetails> authTokenFilter,
                             CustomUserDetailsService userDetailsService,
                             AuthEntryPointJwt unauthorizedHandler, InternalTokenService internalTokenService, JwtService jwtService) {
        super(authTokenFilter);
        this.userDetailsService = userDetailsService;
        this.unauthorizedHandler = unauthorizedHandler;
        this.internalTokenService = internalTokenService;
        this.jwtService = jwtService;
    }

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter(jwtService, userDetailsService);
    }

    @Bean
    public InternalTokenFilter internalTokenFilter() {
        return new InternalTokenFilter(internalTokenService);
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configureHttpSecurity(HttpSecurity http) throws Exception{
        http.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/v1/auth/signin").permitAll()
                        .requestMatchers("/v1/auth/signup").permitAll()
                        .requestMatchers("/v1/auth/refresh-token").permitAll()
                        .requestMatchers("/v1/internal/**").hasRole("INTERNAL_SERVICE")
                        .anyRequest().authenticated()
                );

        http.authenticationProvider(authenticationProvider());
        http.addFilterBefore(internalTokenFilter(), UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}