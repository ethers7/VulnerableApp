package org.sasanlabs.configuration;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Overrides referrer policy on the reset page so level 7 can demonstrate full-URL referrer leakage
 * to third-party resources.
 */
@Component
@Order(Ordered.LOWEST_PRECEDENCE - 100)
public class PasswordResetReferrerPolicyFilter extends OncePerRequestFilter {

    private static final String RESET_PAGE_PATH = "/password-reset/reset.html";
    private static final int REFERRER_LEAK_LEVEL = 7;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (shouldApplyUnsafeUrlReferrerPolicy(request)) {
            response.setHeader("Referrer-Policy", "unsafe-url");
        }
        filterChain.doFilter(request, response);
    }

    private static final int MAX_LEVEL_PARAM_LENGTH = 10;

    private boolean shouldApplyUnsafeUrlReferrerPolicy(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        if (requestUri == null || !requestUri.endsWith(RESET_PAGE_PATH)) {
            return false;
        }

        String level = request.getParameter("level");
        if (level == null || level.isBlank()) {
            return false;
        }

        String trimmedLevel = level.trim();
        if (trimmedLevel.length() > MAX_LEVEL_PARAM_LENGTH
                || !trimmedLevel.matches("^[0-9]+$")) {
            return false;
        }

        int parsedLevel = Integer.parseInt(trimmedLevel);
        return parsedLevel == REFERRER_LEAK_LEVEL;
    }
}
