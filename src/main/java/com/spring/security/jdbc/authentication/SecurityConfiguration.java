package com.spring.security.jdbc.authentication;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.authentication.UserServiceBeanDefinitionParser;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	/**
	 * H2 is auto-wired
	 * https://docs.spring.io/spring-security/site/docs/current/reference/html5/#user-schema
	 */
	@Autowired
	DataSource dataSource;
	
	/**
	 * Configures JDBC authentication to in-memory DB
	 * Since H2 is added as an embedded dependency, spring boot creates the datasource for us
	 */
	
	/**
	 * This method shows how to just hard code users and roles. we dont need to code 
	 * sql files in reosurces folder for this to work
	 */
//	@Override
//	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//		auth.jdbcAuthentication()
//		.dataSource(dataSource)
//		.withDefaultSchema() //Spring security creates default schema to have user details for any DB configured
//		.withUser(User.withUsername("user").password("pass").roles("USER"))
//		.withUser(User.withUsername("admin").password("pass").roles("ADMIN"));	
//	}
	
	/**
	 * This method shows how to use tables created and user data inserted using 
	 * queries in schema and data sqls in resources
	 */
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.jdbcAuthentication()
		.dataSource(dataSource);	
	}
	
	/**
	 * This method shows hot to use custom tables to validate users and roles
	 */
	//@Override
//	protected void configure1(AuthenticationManagerBuilder auth) throws Exception {
//		auth.jdbcAuthentication()
//		.dataSource(dataSource)
//		.usersByUsernameQuery("select username, password, enabled from custom_user where username=?")
//		.authoritiesByUsernameQuery("select username, authority from custom_user where username=?");
//	}
	
	/**
	 * Configures authorization
	 * Authorizing user and admin page requests, but not homepage requests
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
		.antMatchers("/admin").hasRole("ADMIN")
		.antMatchers("/user").hasRole("USER")
		.antMatchers("/").permitAll()
		.and().formLogin();
	}
	
	@Bean
	public PasswordEncoder getPasswordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}
	
	
}
