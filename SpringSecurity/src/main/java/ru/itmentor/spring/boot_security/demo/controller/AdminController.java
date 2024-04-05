package ru.itmentor.spring.boot_security.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import ru.itmentor.spring.boot_security.demo.model.User;
import ru.itmentor.spring.boot_security.demo.service.RoleService;
import ru.itmentor.spring.boot_security.demo.service.UserService;

import javax.validation.Valid;
import java.util.ArrayList;

@Controller
@RequestMapping("/admin")
public class AdminController {

    private final UserService userService;
    private final RoleService roleService;

    @Autowired
    public AdminController(RoleService roleService, UserService userService) {
        this.roleService = roleService;
        this.userService = userService;
    }

    @GetMapping()
    public String pageForAdmin(Model model) {
        model.addAttribute("users", userService.findAll());
        return "users";
    }

    @GetMapping("/new")
    public String pageCreateUser(User user, Model model) {
        model.addAttribute("listRoles", roleService.findAllRole());
        return "create";
    }

    @PostMapping("/new")
    public String pageCreate(@RequestParam("role") ArrayList<Long> roles,
                             @ModelAttribute("user") @Valid User user,
                             BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return "create";
        }
        user.setRoles(roleService.findByIdRoles(roles));
        userService.save(user);
        return "redirect:/admin";
    }

    @DeleteMapping("/delete/{id}")
    public String pageDelete(@PathVariable("id") long id) {
        userService.deleteById(id);
        return "redirect:/admin";
    }

    @GetMapping("/edit/{id}")
    public String pageEditUser(@PathVariable("id") long id, Model model) {
        model.addAttribute("user", userService.getById(id));
        model.addAttribute("listRoles", roleService.findAllRole());
        return "edit";
    }

    @PutMapping("/edit")
    public String pageEdit(@RequestParam("role") ArrayList<Long> roles,
                           @Valid User user,
                           BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return "edit";
        } else {
            user.setRoles(roleService.findByIdRoles(roles));
            userService.save(user);
            return "redirect:/admin";
        }
    }
}