package jwt.praktikum.demo.service;

import jwt.praktikum.demo.domain.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import jwt.praktikum.demo.repository.UserRepository;

import java.util.List;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordEncoder encoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, PasswordEncoder encoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.encoder = encoder;
    }

    public User save(User user) {
        String password = encoder.encode(user.getPassword());
        user.setPassword(password);
        return userRepository.save(user);
    }

    public List<User> findAll() {
        return userRepository.findAll();
    }
}
