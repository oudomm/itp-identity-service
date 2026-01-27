package dev.oudom.identity.security;

import dev.oudom.identity.domain.Role;
import dev.oudom.identity.domain.User;
import dev.oudom.identity.features.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // Load or find user from database
        User loggedInUser = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(username));

        // Build UserDetails object
        String[] roles = loggedInUser.getRoles().stream()
                .map(Role::getName)
                .toArray(String[]::new);

        // Important for user authorities
        List<GrantedAuthority> authorities = new ArrayList<>();
        loggedInUser.getRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getName()));
            role.getPermissions().forEach(permission -> {
                authorities.add(new SimpleGrantedAuthority(permission.getName()));
            });
        });

        UserDetails userSecurity = org.springframework.security.core.userdetails.User.builder()
                .username(loggedInUser.getUsername())
                .password(loggedInUser.getPassword())
                .authorities(authorities)
                .build();
        log.info("UserDetailsServiceImpl loadUserByUsername = {}", userSecurity.getAuthorities());
        log.info("UserDetailsServiceImpl loadUserByUsername = {}", userSecurity.getUsername());

        return userSecurity;
    }
}
