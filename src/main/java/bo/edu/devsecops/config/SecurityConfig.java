package bo.edu.devsecops.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                // CSRF sigue activo; solo se exime la API JSON (sin sesion de navegador ni formularios).
                .csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"))
                .authorizeHttpRequests(auth -> auth
                        // Publicos: API del laboratorio y el health check del contenedor
                        .requestMatchers("/actuator/health", "/api/auth/login",
                                "/api/products/**", "/api/comments/**").permitAll()
                        // Todo lo demas (incluido /api/admin/**) exige autenticacion
                        .anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults())
                .build();
    }
}
