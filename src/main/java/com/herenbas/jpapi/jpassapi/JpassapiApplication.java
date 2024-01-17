package com.herenbas.jpapi.jpassapi;

import com.mashape.unirest.http.exceptions.UnirestException;
import net.sf.scuba.smartcards.CardServiceException;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.smartcardio.CardException;
import java.io.IOException;
import java.security.GeneralSecurityException;

import static org.springframework.web.bind.annotation.RequestMethod.POST;

@RestController
@SpringBootApplication
@RequestMapping("/api")
public class JpassapiApplication {


    public static void main(String[] args) {
        SpringApplication.run(JpassapiApplication.class, args);
    }
    @RequestMapping(path = "/read", method=POST)
    public String get_data(@RequestParam String DN, @RequestParam String DT, @RequestParam String GT, @RequestParam String PATH, @RequestParam Boolean isEAC, @RequestParam Boolean isFaceMatch, @RequestParam Boolean isFaceMatchN )

    {

        pser ser = new pser();
        try {
            ser.CardService();
        } catch (CardServiceException e) {
            throw new RuntimeException(e);
        } catch (CardException e) {
            throw new RuntimeException(e);
        }
        try {

            if (isEAC == false)
            {
                if(isFaceMatch == true)
                {
                   return ser.PassportService(DN,DT,GT,PATH) + ser.FaceMatch().getBody().toString();

                }
                else if(isFaceMatchN == true) {


                    return  ser.PassportService(DN,DT,GT,PATH) + ser.FaceMatchN().getBody().toString();
                }
                else
                {
                    return  ser.PassportService(DN,DT,GT,PATH);

                }


            }
            if(isEAC == true)
            {
                if(isFaceMatch==true)
                {
                    return  ser.PassportService(DN,DT,GT,PATH) +ser.tryEACC() + ser.FaceMatch().getBody().toString();

                }
                else if(isFaceMatchN==true)
                {
                   return  ser.PassportService(DN,DT,GT,PATH) +ser.tryEACC()+ ser.FaceMatchN().getBody().toString();

                }
                else
                {
                    return  ser.PassportService(DN,DT,GT,PATH)+ ser.tryEACC();
                }

            }



            else
            {

                return "Eksik Parametre";

            }

        } catch (CardServiceException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (UnirestException e) {
            throw new RuntimeException(e);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }







    }






}
