package com.example;

import org.springframework.web.bind.annotation.*;
import com.example.UserService;

@RestController
@RequestMapping("/api")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/users/{id}")
    public User getUser(@PathVariable String id) {
        return userService.findById(id);
    }

    @PostMapping("/users")
    public User createUser(@RequestBody UserDto dto) {
        String name = dto.getName();
        return userService.create(name, dto.getEmail());
    }

    @DeleteMapping("/users/{id}")
    public void deleteUser(@PathVariable String id) {
        userService.delete(id);
    }
}
