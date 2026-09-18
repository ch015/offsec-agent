package com.example

import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/api")
class UserController(private val userService: UserService) {

    @GetMapping("/users/{id}")
    fun getUser(@PathVariable id: String): User {
        return userService.findById(id)
    }

    @PostMapping("/users")
    fun createUser(@RequestBody dto: UserDto): User {
        return userService.create(dto.name, dto.email)
    }
}
