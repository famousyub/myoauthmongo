

package com.microservice.springsecurityoauth2mongodb.security;

import com.microservice.springsecurityoauth2mongodb.document.User;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class CustomTokenEnhancer extends JwtAccessTokenConverter {



    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {

        DefaultOAuth2AccessToken customAccessToken = new DefaultOAuth2AccessToken(accessToken);

        User user = (User) authentication.getPrincipal();

        Map<String, Object> info = new LinkedHashMap<>(accessToken.getAdditionalInformation());

        info.put("id", user.getId());
        info.put("email", user.getEmail());
        info.put("fullname", String.format("%s %s", user.getUsername(), user.getEmail()));
        info.put("roles", user.getRoles().stream().map(role -> String.format("ROLE_%s", role).toUpperCase())
                .collect(Collectors.toList()));

        customAccessToken.setAdditionalInformation(info);
        return super.enhance(customAccessToken, authentication);
    }



}
