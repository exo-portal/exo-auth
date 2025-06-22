package com.exodia_portal.auth.functions.auth.dto;

import com.exodia_portal.auth.functions.user.dto.UserResponseDto;
import com.exodia_portal.common.enums.AccessLevelTypeEnum;
import lombok.Builder;

import java.util.List;

@Builder
public record LoginResponseDto(
        UserResponseDto user,
        List<String> featureKeys,
        List<String> roleNames,
        AccessLevelTypeEnum accessLevelRole) {

}
