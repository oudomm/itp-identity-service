package dev.oudom.identity.config.oidc;

import dev.oudom.identity.domain.Role;
import dev.oudom.identity.features.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.stream.Collectors;

@Configuration
@RequiredArgsConstructor
public class TokenCustomizerConfig {

    private final UserRepository userRepository;

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return context -> {
            // Only customize ID token (OIDC)
            if (!OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
                return;
            }

            String username = context.getPrincipal().getName();

            var userOpt = userRepository.findByUsername(username);
            if (userOpt.isEmpty()) return;

            var u = userOpt.get();

            var roles = (u.getRoles() == null ? java.util.Set.<String>of() :
                    u.getRoles().stream()
                            .filter(r -> r != null && r.getName() != null)
                            .map(Role::getName)
                            .collect(Collectors.toSet())
            );

            System.out.println("IAM roles for " + username + " = " + roles);

            context.getClaims().claims(claims -> {
                claims.put("uuid", u.getUuid());
                claims.put("username", u.getUsername());
                claims.put("email", u.getEmail());
                claims.put("family_name", u.getFamilyName());
                claims.put("given_name", u.getGivenName());
                claims.put("full_name", u.getGivenName() + " " + u.getFamilyName());
                claims.put("phone_number", u.getPhoneNumber());
                claims.put("gender", u.getGender());
                claims.put("birthdate", u.getDob() != null ? u.getDob().toString() : null);
                claims.put("picture", u.getProfileImage());
                claims.put("cover_image", u.getCoverImage());
                claims.put("roles", roles);

            });
        };
    }
}
