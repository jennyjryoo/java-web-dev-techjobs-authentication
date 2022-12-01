package org.launchcode.javawebdevtechjobsauthentication;

import org.launchcode.javawebdevtechjobsauthentication.controllers.AuthenticationController;
import org.launchcode.javawebdevtechjobsauthentication.models.User;
import org.launchcode.javawebdevtechjobsauthentication.models.data.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public class AuthenticationFilter extends HandlerInterceptorAdapter {

    @Autowired
    UserRepository userRepository;

    @Autowired
    AuthenticationController authenticationController;

    private static final List<String> allowedList = Arrays.asList("/login", "/register","/logout", "/css");

    private static boolean isWhiteListed (String path) {
        for (String pathroot : allowedList) {
            if (path.equals(pathroot)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean preHandle (HttpServletRequest request, HttpServletResponse response, Object handler) throws IOException {
        HttpSession session = request.getSession();
        User user = authenticationController.getUserFromSession(session);

        if (isWhiteListed(request.getRequestURI())) {
            return true;
        }

        if (user != null) {
            return true;
        }

        response.sendRedirect("/login");
        return false;
    }
}
