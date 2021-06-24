package com.fnf.security.config;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * @Author： 冯南飞
 * @Date： 2021/6/24 13:04
 **/
@Component
public class MyPasswordEncoder implements PasswordEncoder {
    @Override
    public String encode(CharSequence rowPassword) {
      return privateEncode(rowPassword);
    }

    @Override
    public boolean matches(CharSequence rowPassword, String encodedPassword) {
        // 对明文进行加密
        String formPassword = privateEncode(rowPassword);

        // 数据库密码
        String databasePassword=encodedPassword;

        // 比较
        return Objects.equals(formPassword,databasePassword);
    }
    private String privateEncode(CharSequence rowPassword){
        // 创建MessageDigest
        try {
            String algroithm="MD5";
            MessageDigest messageDigest = MessageDigest.getInstance(algroithm);

            // 2 获取明文的字节数组
            byte[] input=((String)rowPassword).getBytes();

            // 实现加密
            byte[] output = messageDigest.digest(input);

            // 4 转换为16进制对应的字符
            String encode = new BigInteger(1, output).toString(16);
            return encode;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
}
