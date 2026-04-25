package com.pkn.authservice.feigns;


import com.pkn.authservice.dtos.ApiResponseDto;
import com.pkn.authservice.dtos.MailRequestDto;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient("NOTIFICATION-SERVICE")
public interface NotificationService {

    @PostMapping("/notification/send")
    ResponseEntity<ApiResponseDto<?>> sendEmail(@RequestBody MailRequestDto requestDto);
}
