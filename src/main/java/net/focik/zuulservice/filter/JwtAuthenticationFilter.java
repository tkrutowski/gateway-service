package net.focik.zuulservice.filter;

import com.auth0.jwt.exceptions.JWTVerificationException;
import lombok.RequiredArgsConstructor;
import net.focik.zuulservice.utility.JwtTokenProvider;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.function.Predicate;

import static net.focik.zuulservice.utility.JwtTokenProvider.AUTHORITIES;
import static net.focik.zuulservice.utility.JwtTokenProvider.TOKEN_PREFIX;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@RequiredArgsConstructor
@Component
public class JwtAuthenticationFilter implements  GatewayFilter {

    private final JwtTokenProvider tokenProvider;


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();


        final List<String> apiEndpoints = List.of("/api/auth/login");

        Predicate<ServerHttpRequest> isApiSecured = r -> apiEndpoints.stream()
                .noneMatch(uri -> r.getURI().getPath().contains(uri));


        if (isApiSecured.test(request)) {
            if (!request.getHeaders().containsKey(AUTHORIZATION)) {
                ServerHttpResponse response = exchange.getResponse();
                response.setStatusCode(HttpStatus.UNAUTHORIZED);

                return response.setComplete();
            }

            String token = "";
            String authorizationHeader = request.getHeaders().getOrEmpty(AUTHORIZATION).get(0);
            if (authorizationHeader.startsWith(TOKEN_PREFIX)) {

             token = authorizationHeader.substring(TOKEN_PREFIX.length());

                try {
//                jwtUtil.validateToken(token);
                    tokenProvider.isTokenValid(token);
                } catch (JWTVerificationException e) {
                    e.printStackTrace();
//
                    ServerHttpResponse response = exchange.getResponse();
                    response.setStatusCode(HttpStatus.UNAUTHORIZED);

//
                    return response.setComplete();
                }
            }


//            final String token = request.getHeaders().getOrEmpty("Authorization").get(0);

            String[] claims = tokenProvider.getClaimsFromToken(token);
//
//            Claims claims = jwtUtil.getClaims(token);
           exchange.getRequest().mutate().header(AUTHORITIES, claims).build();
            System.out.println();
        }

        return chain.filter(exchange);
    }
}
