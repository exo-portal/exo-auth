package com.exodia_portal.auth.functions.loginmethod.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UnbindRequestDto {

    private long userId;

    private String providerId;

    private String providerName;

}
