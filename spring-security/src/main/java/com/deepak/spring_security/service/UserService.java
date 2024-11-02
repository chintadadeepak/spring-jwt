package com.deepak.spring_security.service;

import com.deepak.spring_security.dao.UserDao;
import com.deepak.spring_security.models.Users;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    private UserDao userDao;
    private final BCryptPasswordEncoder ENCODER = new BCryptPasswordEncoder(12);


    @Autowired
    public void setUserDao(UserDao userDao) {
        this.userDao = userDao;
    }

    public Users registerUser(Users newUser) {
        newUser.setPassword(ENCODER.encode(newUser.getPassword()));
        return userDao.save(newUser);
    }
}
