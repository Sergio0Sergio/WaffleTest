package com.example.waffletest.security;

import com.example.waffletest.security.waffle.CustomNegotiateSecurityFilter;
import com.example.waffletest.security.waffle.CustomPreAuthSecurityFilter;
import com.example.waffletest.security.waffle.WindowsAuthenticationProviderWrapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import waffle.servlet.spi.BasicSecurityFilterProvider;
import waffle.servlet.spi.NegotiateSecurityFilterProvider;
import waffle.servlet.spi.SecurityFilterProvider;

import waffle.servlet.spi.SecurityFilterProviderCollection;
import waffle.spring.NegotiateSecurityFilter;
import waffle.spring.NegotiateSecurityFilterEntryPoint;
import waffle.windows.auth.impl.WindowsAuthProviderImpl;

import javax.servlet.Filter;
import java.util.ArrayList;
import java.util.List;

public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // Authentication manager configuration

    private WindowsAuthenticationProviderWrapper authProvider;
    private AuthenticationManagerBuilder auth;
    private WindowsAuthProviderImpl waffleAuthProvider;
    private NegotiateSecurityFilterProvider negotiateSecurityFilterProvider;
    private BasicSecurityFilterProvider basicSecurityFilterProvider;
    private waffle.servlet.spi.SecurityFilterProviderCollection negotiateSecurityFilterProviderCollection;
    private waffle.spring.NegotiateSecurityFilterEntryPoint negotiateSecurityFilterEntryPoint;
    private Filter customPreAuthSecurityFilter;
    private waffle.spring.NegotiateSecurityFilter waffleNegotiateSecurityFilter;
    private Filter customNegotiateSecurityFilter;

    @Autowired
    public SecurityConfig(WindowsAuthenticationProviderWrapper authProvider, AuthenticationManagerBuilder auth, WindowsAuthProviderImpl waffleAuthProvider, NegotiateSecurityFilterProvider negotiateSecurityFilterProvider, BasicSecurityFilterProvider basicSecurityFilterProvider, SecurityFilterProviderCollection negotiateSecurityFilterProviderCollection, NegotiateSecurityFilterEntryPoint negotiateSecurityFilterEntryPoint, Filter customPreAuthSecurityFilter, NegotiateSecurityFilter waffleNegotiateSecurityFilter, Filter customNegotiateSecurityFilter) {
        this.authProvider = authProvider;
        this.auth = auth;
        this.waffleAuthProvider = waffleAuthProvider;
        this.negotiateSecurityFilterProvider = negotiateSecurityFilterProvider;
        this.basicSecurityFilterProvider = basicSecurityFilterProvider;
        this.negotiateSecurityFilterProviderCollection = negotiateSecurityFilterProviderCollection;
        this.negotiateSecurityFilterEntryPoint = negotiateSecurityFilterEntryPoint;
        this.customPreAuthSecurityFilter = customPreAuthSecurityFilter;
        this.waffleNegotiateSecurityFilter = waffleNegotiateSecurityFilter;
        this.customNegotiateSecurityFilter = customNegotiateSecurityFilter;
    }

    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authProvider);
    }

    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return auth.getObject();
    }

    // Waffle configuration
    @Bean
    public Filter customPreAuthSecurityFilter() {
        return new CustomPreAuthSecurityFilter();
    }

    @Bean
    public Filter customNegotiateSecurityFilter() {
        return new CustomNegotiateSecurityFilter();
    }

    @Bean
    public WindowsAuthProviderImpl waffleAuthProvider(){
        return new WindowsAuthProviderImpl();
    }

    @Bean(name="negotiateSecurityFilterProvider")
    @Autowired
    public NegotiateSecurityFilterProvider negotiateSecurityFilterProvider(){
        NegotiateSecurityFilterProvider bean = new NegotiateSecurityFilterProvider(waffleAuthProvider);
        List<String> protocols = new ArrayList<>();
        protocols.add("Negotiate");
        bean.setProtocols(protocols);
        return bean;
    }

    @Bean
    public BasicSecurityFilterProvider basicSecurityFilterProvider(){
        return new BasicSecurityFilterProvider(waffleAuthProvider);
    }

    @Bean(name="waffleSecurityFilterProviderCollection")
    @Autowired
    public waffle.servlet.spi.SecurityFilterProviderCollection negotiateSecurityFilterProviderCollection() {
        final List<SecurityFilterProvider> lsp = new ArrayList<>();
        lsp.add(negotiateSecurityFilterProvider);
        lsp.add(basicSecurityFilterProvider);
        return new waffle.servlet.spi.SecurityFilterProviderCollection(lsp.toArray(new SecurityFilterProvider[]{}));
    }

    @Bean(name="negotiateSecurityFilterEntryPoint")
    @Autowired
    public waffle.spring.NegotiateSecurityFilterEntryPoint negotiateSecurityFilterEntryPoint() {
        final waffle.spring.NegotiateSecurityFilterEntryPoint ep = new waffle.spring.NegotiateSecurityFilterEntryPoint();
        ep.setProvider(negotiateSecurityFilterProviderCollection);
        return ep;
    }

    @Bean(name="negotiateSecurityFilter")
    @Autowired
    public waffle.spring.NegotiateSecurityFilter waffleNegotiateSecurityFilter(){
        waffle.spring.NegotiateSecurityFilter bean = new waffle.spring.NegotiateSecurityFilter();
        bean.setRoleFormat("both");
        bean.setPrincipalFormat("fqn");
        bean.setAllowGuestLogin(false);
        bean.setProvider(negotiateSecurityFilterProviderCollection);
        return bean;
    }

    // Static Mappings
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/assets/**");
    }

    // Security filter chain
    // The custom filters can be removed if you only use waffle
    // but this is how we added them
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // A user needs to have the role user and has to be authenticated
        http.exceptionHandling()
                .authenticationEntryPoint(negotiateSecurityFilterEntryPoint).and()
                .addFilterBefore(customPreAuthSecurityFilter, BasicAuthenticationFilter.class)
                .addFilterAfter(waffleNegotiateSecurityFilter, BasicAuthenticationFilter.class)
                .addFilterAfter(customNegotiateSecurityFilter, BasicAuthenticationFilter.class)
                .authorizeRequests().anyRequest().fullyAuthenticated();
    }
}
