package dev.oudom.identity.features.user;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/public")
public class PublicController {

    @GetMapping("/welcome")
    public ResponseEntity<?> helloSpringSecurity() {
        return ResponseEntity.ok(
                Map.of("message", "Welcome to Spring Security")
        );
    }

}
