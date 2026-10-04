package bo.edu.devsecops.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthController.class);

    /** La credencial viene de la configuracion (variable de entorno LAB_ADMIN_PASSWORD), nunca del codigo. */
    private final String adminPassword;

    public AuthController(@Value("${lab.admin.password:}") String adminPassword) {
        this.adminPassword = adminPassword;
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody Map<String, String> credentials) {
        String username = credentials.getOrDefault("username", "");
        String password = credentials.getOrDefault("password", "");

        // Nunca se registran contrasenas; el usuario se sanea para evitar inyeccion de saltos de linea en el log.
        LOGGER.info("Intento de acceso: usuario={}", username.replaceAll("[\\r\\n]", "_"));

        boolean configured = !adminPassword.isEmpty();
        boolean passwordMatches = MessageDigest.isEqual(
                adminPassword.getBytes(StandardCharsets.UTF_8), password.getBytes(StandardCharsets.UTF_8));
        if (configured && "admin".equals(username) && passwordMatches) {
            return ResponseEntity.ok(Map.of(
                    "token", UUID.randomUUID().toString(),
                    "message", "Acceso autorizado"));
        }
        return ResponseEntity.status(401).body(Map.of("error", "Credenciales incorrectas"));
    }
}
