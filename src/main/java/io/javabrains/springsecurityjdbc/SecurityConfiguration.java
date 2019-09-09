package io.javabrains.springsecurityjdbc;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter{

	@Autowired
	DataSource dataSource;
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.jdbcAuthentication().dataSource(dataSource);

/* declaring queries to be used if schema is not the default one
 * 				.usersByUsernameQuery("select username, password, enabled "
 *				+ "from users "
 *				+ "where username = ?")
 *		.authoritiesByUsernameQuery("select username, authority"
 *				+ "from authorities"
 *				+ "where username = ?") 
 */
/* declaring users/passwords in the code
 * 
 *		.withDefaultSchema()
 *		.withUser(User.withUsername("user").password("user").roles("USER"))
 *		.withUser(User.withUsername("admin").password("admin").roles("ADMIN"));
*/
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
		.antMatchers("/admin").hasRole("ADMIN")
		.antMatchers("/user").hasAnyRole("USER", "ADMIN")
		.antMatchers("/").permitAll()
		.and().formLogin();
	}
	
	@Bean
	public PasswordEncoder getPasswordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}
	

}
