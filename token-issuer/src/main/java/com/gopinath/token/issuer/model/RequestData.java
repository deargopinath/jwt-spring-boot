package com.gopinath.token.issuer.model;

public class RequestData {
    String subject;
    String user;
    String account;
    
    public String getSubject() {
        return subject;
    }
    
    public String getUser() {
        return user;
    }
    
    public String getAccount() {
        return account;
    }
    
    public void setSubject(String clientURL) {
        subject = clientURL;
    }
    
    public void setUser(String user) {
        this.user = user;
    }

    public void setAccount(String account) {
        this.account = account;
    }
}

