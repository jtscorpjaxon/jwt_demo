package jwt.praktikum.demo.web.rest;

import jwt.praktikum.demo.domain.User;
import jwt.praktikum.demo.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class UserResource {

    private final UserService userService;

    public UserResource(UserService userService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity create(@RequestBody User user) {
        User result = userService.save(user);
        return ResponseEntity.ok(result);
    }

    @GetMapping("/users")
    public ResponseEntity getAll() {
        return ResponseEntity.ok(userService.findAll());
    }
}
