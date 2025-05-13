package com.exodia_portal.auth.functions.user.controller;

import com.exodia_portal.auth.functions.user.service.UserService;
import com.exodia_portal.common.dto.ApiResultModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("user")
public class UserController {

    @Autowired
    private UserService userService;

    /**
     * Handles GET requests to "/get" and returns an {@link ApiResultModel} representing the logged-in user.
     *
     * @return An {@link ApiResultModel} object with a success status, a message, and result data.
     */
    @GetMapping("get")
    @ResponseStatus(HttpStatus.OK)
    public ApiResultModel getLoggedInUser() {
        return ApiResultModel.builder()
                .isSuccess(true)
                .message("User retrieved successfully")
                .resultData(userService.getLoggedInUser())
                .build();
    }
}
