package org.gluu.agama.businesslogin;

import java.util.HashMap;
import java.util.Map;

import org.gluu.agama.businesslogin.jans.JansNewResetService;

public abstract class NewResetService {

    public abstract boolean passwordPolicyMatch(String userPassword);

    public abstract Map<String, String> getUserEntityByMail(String email);

    public abstract String sendEmail(String to);

    public abstract String updateUserPassword(String userPassword, String mail);   

    public static NewResetService  getInstance(){
        return new JansNewResetService();
    }


}
