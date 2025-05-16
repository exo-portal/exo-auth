package com.exodia_portal.auth.functions.loginmethod.controller;

import com.exodia_portal.auth.functions.loginmethod.dto.UnbindRequestDto;
import com.exodia_portal.auth.functions.loginmethod.service.LoginMethodService;
import com.exodia_portal.common.dto.ApiResultModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/login-method")
public class LoginMethodController {

    @Autowired
    private LoginMethodService loginMethodService;

    @PostMapping("unbind")
    private ApiResultModel unbind(@RequestBody UnbindRequestDto requestDto) {
        return loginMethodService.unbind(requestDto.getProviderId(), requestDto.getProviderName(), requestDto.getUserId());
    }
}
