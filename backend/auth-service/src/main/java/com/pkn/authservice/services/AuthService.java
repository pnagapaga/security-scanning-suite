package com.pkn.authservice.services;

import com.pkn.authservice.dtos.ApiResponseDto;
import com.pkn.authservice.dtos.SignInRequestDto;
import com.pkn.authservice.dtos.SignUpRequestDto;
import com.pkn.authservice.exceptions.ServiceLogicException;
import com.pkn.authservice.exceptions.UserAlreadyExistsException;
import com.pkn.authservice.exceptions.UserNotFoundException;
import com.pkn.authservice.exceptions.UserVerificationFailedException;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;

@Service
public interface AuthService {
    ResponseEntity<ApiResponseDto<?>> registerUser(SignUpRequestDto signUpRequestDto) throws UnsupportedEncodingException, UserAlreadyExistsException, ServiceLogicException;
    ResponseEntity<ApiResponseDto<?>> resendVerificationCode(String email) throws UnsupportedEncodingException, UserNotFoundException, ServiceLogicException;
    ResponseEntity<ApiResponseDto<?>> verifyRegistrationVerification(String code) throws UserVerificationFailedException;
    ResponseEntity<ApiResponseDto<?>> authenticateUser(SignInRequestDto signInRequestDto);
    ResponseEntity<ApiResponseDto<?>> validateToken(String token);
}
