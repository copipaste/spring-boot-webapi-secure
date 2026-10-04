package bo.edu.devsecops.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthController.class);
    private static final String ADMIN_PASSWORD = "Admin123!";
    private static final String JWT_SECRET = "devsecops-lab-secret-key-123456789";

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody Map<String, String> credentials) {
        String username = credentials.getOrDefault("username", "");
        String password = credentials.getOrDefault("password", "");

        LOGGER.info("Intento de acceso: usuario={}, password={}", username, password);

        if ("admin".equals(username) && ADMIN_PASSWORD.equals(password)) {
            return ResponseEntity.ok(Map.of(
                    "token", JWT_SECRET,
                    "message", "Acceso autorizado"));
        }
        return ResponseEntity.status(401).body(Map.of("error", "Credenciales incorrectas"));
    }
}
