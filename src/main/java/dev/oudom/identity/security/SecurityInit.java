package dev.oudom.identity.security;

import dev.oudom.identity.domain.Role;
import dev.oudom.identity.domain.User;
import dev.oudom.identity.features.user.UserRepository;
import dev.oudom.identity.role.RoleRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Component
@RequiredArgsConstructor
@Slf4j
public class SecurityInit {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    @PostConstruct
    public void init() {
        if (userRepository.count() == 0) {
            User user = new User();
            user.setUuid(UUID.randomUUID().toString());
            user.setUsername("oudom");
            user.setPassword(passwordEncoder.encode("qwer"));
            user.setEmail("oudom.istad@gmail.com");
            user.setDob(LocalDate.of(2008, 1, 1));
            user.setGender("Male");
            user.setProfileImage("default_profile.jpg");
            user.setCoverImage("default_cover.jpg");
            user.setFamilyName("Phoem");
            user.setGivenName("Oudom");
            user.setPhoneNumber("077459947");
            user.setAccountNonExpired(true);
            user.setAccountNonLocked(true);
            user.setCredentialsNonExpired(true);
            user.setIsEnabled(true);

            // Assign role to user
            Set<Role> roles = new HashSet<>();
            roles.add(roleRepository.findByName("SUPER_ADMIN"));
            roles.add(roleRepository.findByName("USER"));
            user.setRoles(roles);

            userRepository.save(user);
            log.info("User has been saved: {}", user.getId());
        }
    }
}
