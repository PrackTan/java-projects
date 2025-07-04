package com.devteria.identityservice.dto.request;

import com.devteria.identityservice.validator.Dobconstraint;

import jakarta.validation.constraints.Size;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.time.LocalDate;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UserUpdateRequest {
    @Size(min = 8, message = "INVALID_PASSWORD")
    String password;
    String firstName;
    String lastName;
    @Dobconstraint(message = "INVALID_DOB", minAge = 18, maxAge = 100, format = "dd/MM/yyyy")
    LocalDate dob;
    List<String> roles;
}
