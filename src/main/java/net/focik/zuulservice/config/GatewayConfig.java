package net.focik.zuulservice.config;

import lombok.RequiredArgsConstructor;
import net.focik.zuulservice.filter.JwtAuthenticationFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.cors.reactive.CorsUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import reactor.core.publisher.Mono;
//@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class GatewayConfig  {

    private final JwtAuthenticationFilter filter;
    private static final String ALLOWED_HEADERS = "x-requested-with, authorization, Content-Type, Content-Length, " +
            "Authorization, credential, X-XSRF-TOKEN, Jwt-Token";
    private static final String ALLOWED_METHODS = "GET, PUT, POST, DELETE, OPTIONS, PATCH";
    private static final String ALLOWED_ORIGIN = "*";
    private static final String MAX_AGE = "7200"; //2 hours (2 * 60 * 60)
    @Bean
    public RouteLocator routes(RouteLocatorBuilder builder){
        int i=0;
        return builder.routes()
                .route("taskcalendar", r -> r
                        .path("/api/taskcalendar/**")
                        .filters(f -> f.filter(filter))
                        .uri("lb://TASKCALENDAR-SERVICE"))

                .route("employee", r -> r
                        .path("/api/employee/**", "/api/teams/**")
                        .filters(f -> f.filter(filter))
                        .uri("lb://EMPLOYEE-SERVICE"))
//
//                .route("login", r -> r
//                        .path("/api/auth/login")
//                        .filters(f -> f.filter(filter))
//                        .uri("lb://USER-SERVICE"))
//
                .route("user", r -> r
                        .path("/api/user/**","/api/auth/**")
                        .filters(f -> f.filter(filter))
                        .uri("lb://USER-SERVICE")).build();
//                .route("hello", r -> r.path("/hello/**").filters(f -> f.filter(filter)).uri("lb://hello")).build();

    }
    @Bean
    public WebFilter corsFilter() {
        return (ServerWebExchange ctx, WebFilterChain chain) -> {
            ServerHttpRequest request = ctx.getRequest();
            if (CorsUtils.isCorsRequest(request)) {
                ServerHttpResponse response = ctx.getResponse();
                HttpHeaders headers = response.getHeaders();
                headers.add("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
                headers.add("Access-Control-Allow-Methods", ALLOWED_METHODS);
                headers.add("Access-Control-Max-Age", MAX_AGE); //OPTION how long the results of a preflight request (that is the information contained in the Access-Control-Allow-Methods and Access-Control-Allow-Headers headers) can be cached.
                headers.add("Access-Control-Allow-Headers", ALLOWED_HEADERS);
                if (request.getMethod() == HttpMethod.OPTIONS) {
                    response.setStatusCode(HttpStatus.OK);
                    return Mono.empty();
                }
            }
            return chain.filter(ctx);
        };
    }
//    @Bean
//    public CorsWebFilter corsWebFilter() {
//
//        CorsConfiguration configuration = new CorsConfiguration();
//        configuration.setAllowCredentials(true);
//        configuration.setAllowedOrigins(Collections.singletonList("*"));//setAllowedOrigins(Arrays.asList(FRONT_END_SERVER));
//        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
//        configuration.setAllowedHeaders(List.of("X-Requested-With","Origin","Content-Type","Accept","Authorization",
//                "Access-Control-Allow-Origin","Jwt-Token"));
//
//        // This allow us to expose the headers
//        configuration.setExposedHeaders(List.of("Jwt-Token","Authorization","Access-Control-Allow-Origin"));//"Authorization",  "Access-Control-Allow-Origin",
////                "Access-Control-Allow-Headers", "Origin", "Accept", "X-Requested-With", "Jwt-Token",
////                "Content-Type", "Access-Control-Request-Method", "Access-Control-Request-Headers"));
//
//        //będzie stosowane do wszystkich ścieżek /**
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/**", configuration);
//        return new CorsWebFilter((CorsConfigurationSource) source);
//    }
}
