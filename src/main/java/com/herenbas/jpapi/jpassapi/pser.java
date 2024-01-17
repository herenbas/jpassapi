package com.herenbas.jpapi.jpassapi;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;

import net.sf.scuba.smartcards.CardFileInputStream;
import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.CardServiceException;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CertificateParser;
import org.jmrtd.BACKey;
import org.jmrtd.BACKeySpec;
import org.jmrtd.PACEKeySpec;
import org.jmrtd.PassportService;
import org.jmrtd.cert.CVCertificateFactorySpi;
import org.jmrtd.lds.*;
import org.jmrtd.lds.icao.*;
import org.jmrtd.lds.iso19794.FaceImageInfo;
import org.jmrtd.lds.iso19794.FaceInfo;
import org.jmrtd.lds.iso19794.FingerImageInfo;
import org.jmrtd.lds.iso19794.FingerInfo;
import org.jmrtd.protocol.EACCAResult;
import org.jmrtd.protocol.EACTAResult;
import org.jnbis.api.Jnbis;
import com.google.gson.*;

import javax.imageio.ImageIO;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.awt.image.RenderedImage;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactorySpi;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;
import java.util.*;



public class pser {

    public CardService c_Service;
    public PassportService service;
    private String passportNumber, expirationDate, birthDate;
    private DocType docType;
    public static String ChipImage;
    public static String chipTCKN;
    public EACCAResult caRes;
    public String psn;

    public JsonObject jsonObject = new JsonObject();
    public BACKeySpec bacKey;



    final ECNamedCurveParameterSpec secp256r1 = ECNamedCurveTable.getParameterSpec("secp521r1");

    public String PassportService(String passn, String d_tar, String g_tar, String d_path) throws CardServiceException, IOException, UnirestException, GeneralSecurityException {


        bacKey = new BACKey(passn, d_tar, g_tar);


        BACKeySpec bacKeySpec_test = new BACKeySpec() {
            @Override
            public String getDocumentNumber() {
                return passn;
            }

            @Override
            public String getDateOfBirth() {
                return d_tar;
            }

            @Override
            public String getDateOfExpiry() {
                return g_tar;
            }

            @Override
            public String getAlgorithm() {
                return "AES";
            }

            @Override
            public byte[] getKey() {
                return new byte[0];
            }
        };


        PACEKeySpec pace_key_spec = PACEKeySpec.createMRZKey(bacKeySpec_test);


        service = new PassportService(c_Service, PassportService.NORMAL_MAX_TRANCEIVE_LENGTH, PassportService.DEFAULT_MAX_BLOCKSIZE, true, false);

        service.open();
        docType = DocType.ID_CARD;

        //PACEKeySpec canKey = PACEKeySpec.createCANKey("68716029166");

        boolean paceSucceeded = false;

        CardAccessFile cardAccessFile = null;
        try {


            cardAccessFile = new CardAccessFile(service.getInputStream(PassportService.EF_CARD_ACCESS));
            Collection<SecurityInfo> paceInfos = cardAccessFile.getSecurityInfos();
            if (paceInfos != null && paceInfos.size() > 0) {
                SecurityInfo paceInfo = paceInfos.iterator().next();
                PACEInfo infom = (PACEInfo) paceInfo;




                // PACEResult result = service.doPACE(pace_key_spec, infom.getObjectIdentifier(), PACEInfo.toParameterSpec(infom.getParameterId()), (infom.getParameterId()));
                //System.out.println("PACE RESULT############################# : "+result.toString());
                paceSucceeded = false;//true;

            }
            //System.out.println("PACE SONUC : " + paceSucceeded);


        } catch (Exception e) {
            //System.out.println("EXP :" + e);

        }


        service.sendSelectApplet(paceSucceeded);
        if (!paceSucceeded) {
            try {
                service.getInputStream(PassportService.EF_COM).read();
            } catch (Exception e) {

                service.doBAC(bacKey);


            }
        }
        String data = service.getATR().toString();
        // System.out.println("ATR: " + data);
        PersonDetails personDetails = new PersonDetails();
        // -- Personal Details -- //
        CardFileInputStream dg1In = service.getInputStream(PassportService.EF_DG1);
        DG1File dg1File = new DG1File(dg1In);

        MRZInfo mrzInfo = dg1File.getMRZInfo();
        personDetails.setName(mrzInfo.getSecondaryIdentifier().replace("<", " ").trim());
        personDetails.setSurname(mrzInfo.getPrimaryIdentifier().replace("<", " ").trim());
        personDetails.setPersonalNumber(mrzInfo.getPersonalNumber());
        personDetails.setGender(mrzInfo.getGender().toString());
        personDetails.setBirthDate(DateUtil.convertFromMrzDate(mrzInfo.getDateOfBirth()));
        personDetails.setExpiryDate(DateUtil.convertFromMrzDate(mrzInfo.getDateOfExpiry()));
        personDetails.setSerialNumber(mrzInfo.getDocumentNumber());
        personDetails.setNationality(mrzInfo.getNationality());
        personDetails.setIssuerAuthority(mrzInfo.getIssuingState());











        CardFileInputStream dg2In = service.getInputStream(PassportService.EF_DG2);
        DG2File dg2File = new DG2File(dg2In);



        List<FaceInfo> faceInfos = dg2File.getFaceInfos();
        List<FaceImageInfo> allFaceIMageInfos = new ArrayList<>();
        for (FaceInfo faceInfo : faceInfos) {
            allFaceIMageInfos.addAll(faceInfo.getFaceImageInfos());
        }

        if (!allFaceIMageInfos.isEmpty()) {
            FaceImageInfo faceImageInfo = allFaceIMageInfos.iterator().next();
            Image image = new BufferedImage(faceImageInfo.getWidth(), faceImageInfo.getHeight(), faceImageInfo.getFaceImageType());
            BufferedImage imgs = ImageUtils.read(faceImageInfo.getImageInputStream(), faceImageInfo.getImageLength(), "image/jpeg");

            ChipImage = pser.imgToBase64String(imgs, "jpeg");
            //System.out.println("BASE64 IMAGE DATA : " + ChipImage);

            CardFileInputStream dg11In = service.getInputStream(PassportService.EF_DG11);
            DG11File dg11File = new DG11File(dg11In);


            chipTCKN = dg11File.getPersonalNumber();

            Random random = new Random();
            int min = 1;
            int max = 10000000;
            int rastgeleTamSayi = random.nextInt(max - min + 1) + min;
            dg11File.getNameOfHolder().toString();
            // JSON nesnesine verileri ekleyin

            jsonObject.addProperty("ID",rastgeleTamSayi);
            jsonObject.addProperty("Ad", personDetails.getName());
            jsonObject.addProperty("Soyad", personDetails.getSurname());
            jsonObject.addProperty("TCKN", chipTCKN);
            jsonObject.addProperty("Dogum_Tarihi", personDetails.getBirthDate());
            jsonObject.addProperty("Belge_Numarasi",personDetails.getSerialNumber());
            jsonObject.addProperty("Dogum_Yeri",dg11File.getPlaceOfBirth().toString());
            jsonObject.addProperty("Son_Kullanim_Tarihi", personDetails.getExpiryDate());
            jsonObject.addProperty("Cinsiyet", personDetails.getGender());
            jsonObject.addProperty("Uyruk", personDetails.getNationality());
            long othernamescount =  dg11File.getOtherNames().stream().count();
            if (othernamescount>0)
            {
                for (int i=0;i< othernamescount;i++)
                {
                    jsonObject.addProperty("Other_Names"+i,dg11File.getOtherNames().get(i).toString());


                }

            }else {
                jsonObject.addProperty("Other_names","");
            }

            jsonObject.addProperty("NOH",dg11File.getNameOfHolder().toString());
            jsonObject.addProperty("POB",dg11File.getPlaceOfBirth().get(0).toString());

            //jsonObject.addProperty("Telefon",dg11File.getTelephone().toString());
            if (dg11File.getPermanentAddress()!=null)
            {
                long per_adres_count = dg11File.getPermanentAddress().stream().count();
                if (per_adres_count>0)
                {
                    for (int i=0;i< per_adres_count;i++)
                    {
                        jsonObject.addProperty("Adres"+i,dg11File.getPermanentAddress().get(i).toString());


                    }

                }
            }

            else {

                jsonObject.addProperty("Adres","");

            }

            //DG15File dg15File = new DG15File(service.getInputStream(PassportService.EF_DG15));

            //String s = new String(dg15File.getPublicKey().getEncoded(), StandardCharsets.ISO_8859_1);
            //jsonObject.addProperty("MRZ_LINE",s.toString());

            jsonObject.addProperty("IMAGE", ChipImage);

            // JSON nesnesini bir string olarak elde edin

            psn=personDetails.getSerialNumber();
            // JSON verisini yazdırın

            //System.out.println(LocalDate.now().toString());

            String dosyaYolu = rastgeleTamSayi+"-"+"-"+chipTCKN+"-"+personDetails.getSurname()+"-"+personDetails.getName()+".json";
            System.out.println(dosyaYolu);
            System.out.println(d_path);

            try {
                // Dosya nesnesi oluşturma
                File dosya = new File(d_path+"\\"+rastgeleTamSayi+"-"+"-"+chipTCKN+"-"+personDetails.getSurname()+"-"+personDetails.getName()+".json");

                // Dosyayı oluşturma (eğer dosya yoksa)
                if (!dosya.exists()) {
                    dosya.createNewFile();
                }

                // Dosyaya yazma
                FileWriter dosyaYazici = new FileWriter(dosya);
                BufferedWriter yazici = new BufferedWriter(dosyaYazici);

                String jsonString = jsonObject.toString();

                // Veriyi dosyaya yazma
                yazici.write(jsonString);


                // Dosyayı kapatma
                yazici.close();

                System.out.println("Dosya oluşturuldu ve veri yazıldı.");
                //System.out.println(jsonString); String jsonString = jsonObject.toString();
                     byte[] bytes1= jsonString.getBytes(StandardCharsets.UTF_8);
                              String base64s = Base64.getEncoder().encodeToString(bytes1);
                               System.out.println(base64s);
                             return jsonString;


            } catch (IOException e) {
                e.printStackTrace();
            }


        }
        return data;
    }

    public org.ejbca.cvc.CVCertificate readCVCertificateFromFile(File f) {
        try {
            DataInputStream dataIn = new DataInputStream(new FileInputStream(f));
            byte[] data = new byte[(int) f.length()];
            dataIn.readFully(data);
            CVCObject parsedObject = CertificateParser.parseCertificate(data);
            org.ejbca.cvc.CVCertificate c = (org.ejbca.cvc.CVCertificate) parsedObject;
            dataIn.close();
            return c;
        } catch (Exception e) {
            return null;
        }

    }
    public static HttpResponse<String> FaceMatchN() throws UnirestException {

        Unirest.setTimeouts(0, 0);
        HttpResponse<String> response1 = Unirest.post("http://herenbas.com/fapi/FaceMatchN")
                .header("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE2Nzg5NTM2OTksImV4cCI6MTY4MDY4MTY5OSwiaXNzIjoiS29kZGEgWWF6xLFsxLFtICIsImF1ZCI6Ind3dy5oZXJlbmJhcy5jb20ifQ.lE0ue4S9ZOhgZS7iN2w8GpmmOze8kl5QGYbdQekfd30")


                .field("b_64_image", ChipImage)
                .asString();

        return response1;

    }
    public static HttpResponse<String> FaceMatch() throws UnirestException {

        Unirest.setTimeouts(0, 0);
        HttpResponse<String> response = Unirest.post("http://herenbas.com/fapi/FaceMatch")
                .header("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE2Nzg5NTM2OTksImV4cCI6MTY4MDY4MTY5OSwiaXNzIjoiS29kZGEgWWF6xLFsxLFtICIsImF1ZCI6Ind3dy5oZXJlbmJhcy5jb20ifQ.lE0ue4S9ZOhgZS7iN2w8GpmmOze8kl5QGYbdQekfd30")

                .field("TCKN",chipTCKN )
                .field("b_64_image", ChipImage)
                .asString();

        String jsonString = response.getBody(); //assign your JSON String here
        //JSONObject obj = new JSONObject(jsonString);

       /*
        String eslesmeSonucu = (String) obj.get("eslesmeSonucu");
        String isim = (String) obj.get("isim");
        String skor = (String) obj.get("skor");
        String id = (String) obj.get("id");
        */

        return response;

    }


    public static List<PACEInfo> getPACEInfos(Collection<SecurityInfo> securityInfos) {
        List<PACEInfo> paceInfos = new ArrayList<PACEInfo>();

        if (securityInfos == null) {
            return paceInfos;
        }

        for (SecurityInfo securityInfo : securityInfos) {
            if (securityInfo instanceof PACEInfo) {
                paceInfos.add((PACEInfo) securityInfo);
            }
        }

        return paceInfos;
    }

    private void setMrzData(MRZInfo mrzInfo) {


        passportNumber = mrzInfo.getDocumentNumber();
        expirationDate = mrzInfo.getDateOfExpiry();
        birthDate = mrzInfo.getDateOfBirth();
    }




    public static String imgToBase64String(final RenderedImage img, final String formatName) {
        final ByteArrayOutputStream os = new ByteArrayOutputStream();
        try (final OutputStream b64os = Base64.getEncoder().wrap(os)) {
            ImageIO.write(img, formatName, b64os);
        } catch (final IOException ioe) {
            throw new UncheckedIOException(ioe);
        }
        return os.toString();
    }

    public Exception CardService() throws CardServiceException, CardException {


        try {
            List<CardTerminal> terms = TerminalFactory.getDefault().terminals().list();
            CardTerminal terminal = TerminalFactory.getDefault().terminals().list().get(0);
            //System.out.println(terms);

            terminal.getName();

            c_Service = CardService.getInstance(terminal);


            c_Service.open();
        }catch (Exception exception)
        {
            return exception;

        }

        return null;
    }


    public EACCAResult chipA() throws IOException, CardServiceException {
        //File certFile3 = new File("/Users/erenbas/Documents/toTests/17.cvc");
        // File certFile3 = new File("C:\\toTest\\IS_30082022.cvc");
        //FileInputStream fileIn = new FileInputStream(certFile3);
        CardFileInputStream cfis = service.getInputStream(PassportService.EF_DG14);

        //is is a InputStream from passportservice
        DG14File dg14 = new DG14File(cfis);




        List<ChipAuthenticationInfo> lstCAI = dg14.getChipAuthenticationInfos();



        List<ChipAuthenticationPublicKeyInfo> lstCAPKI = dg14.getChipAuthenticationPublicKeyInfos();


        if (lstCAI.size() >= 1 && lstCAPKI.size() >= 1) {
            ChipAuthenticationInfo CAI = lstCAI.get(0);
            ChipAuthenticationPublicKeyInfo CAPKI = lstCAPKI.get(0);
            try {
                caRes = service.doEACCA(CAI.getKeyId(), CAI.getObjectIdentifier(), CAPKI.getSubjectPublicKey().getAlgorithm(), CAPKI.getSubjectPublicKey());
                //ASSUME THERE IS NO EXCEPTION, it's fine..

                System.out.println("OK CA status: AUTHENTICATED");
                return caRes;
            } catch (Exception ex) {
                System.out.println("ERR CA status: FAILED\r\n" + ex.getMessage());
                return caRes;
            }
        }
        return caRes;
    }
    public String tryEACC() throws IOException, GeneralSecurityException, CardServiceException {
        File certFile = new File("/Users/erenbas/Documents/toTest1/TRCVCAEPASS.cvc");

        FileInputStream fileIn = new FileInputStream(certFile);
        CardFileInputStream isCVCA = service.getInputStream(PassportService.EF_CVCA);

        CVCertificateFactorySpi factory = new CVCertificateFactorySpi();
        org.jmrtd.cert.CardVerifiableCertificate certificate = (org.jmrtd.cert.CardVerifiableCertificate) factory.engineGenerateCertificate(fileIn);

        CVCAFile cvc = (CVCAFile) LDSFileUtil.getLDSFile(PassportService.EF_CVCA, isCVCA);


        File certFile2 = new File("/Users/erenbas/Documents/toTest1/TRDVCAEPASS.cvc");

        FileInputStream fileIn2 = new FileInputStream(certFile2);

        CVCertificateFactorySpi factory2 = new CVCertificateFactorySpi();
        org.jmrtd.cert.CardVerifiableCertificate certificate2 = (org.jmrtd.cert.CardVerifiableCertificate) factory2.engineGenerateCertificate(fileIn2);

        File certFile3 = new File("/Users/erenbas/Documents/toTest1/17.cvc");

        FileInputStream fileIn3 = new FileInputStream(certFile3);

        CVCertificateFactorySpi factory3 = new CVCertificateFactorySpi();
        org.jmrtd.cert.CardVerifiableCertificate certificate3 = (org.jmrtd.cert.CardVerifiableCertificate) factory3.engineGenerateCertificate(fileIn3);

        List<org.jmrtd.cert.CardVerifiableCertificate> t = new ArrayList<org.jmrtd.cert.CardVerifiableCertificate>();
        t.add(certificate);
        t.add(certificate2);
        t.add(certificate3);

        Path path = Paths.get("/Users/erenbas/Documents/toTest1/eren.pkcs8");

        byte[] bytes = Files.readAllBytes(path);

        /* Generate private key. */
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());


        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("ECDSA", "BC");
        PrivateKey pvt = kf.generatePrivate(ks);
        EACTAResult resultTA = service.doEACTA(cvc.getCAReference(), t, pvt, null, chipA(), psn);

        System.out.println("EAC DURUMU : " + resultTA);
        System.out.println("EAC DdopaceURUMU : " + resultTA);
        CardFileInputStream dg3In = service.getInputStream(PassportService.EF_DG3);


        DG3File dg3File = new DG3File(dg3In);


        List<FingerInfo> fingerInfos = dg3File.getFingerInfos();
        List<FingerImageInfo> allFingerImageInfos = new ArrayList<>();
        for (FingerInfo fingerInfo : fingerInfos) {
            allFingerImageInfos.addAll(fingerInfo.getFingerImageInfos());


        }


        if (!allFingerImageInfos.isEmpty()) {

            for (FingerImageInfo fingerImageInfo : allFingerImageInfos) {
                Image image = new BufferedImage(fingerImageInfo.getWidth(), fingerImageInfo.getHeight(), fingerImageInfo.getBiometricSubtype());
                String a = fingerImageInfo.getMimeType();

                FingerImageInfo i1 = dg3File.getFingerInfos().get(0).getFingerImageInfos().get(0);
                int l1 = i1.getImageLength();
                byte[] b1 = new byte[l1];


                (new DataInputStream(i1.getImageInputStream())).readFully(b1);
                FingerImageInfo i2 = dg3File.getFingerInfos().get(1).getFingerImageInfos().get(0);
                int l2 = i2.getImageLength();
                byte[] b2 = new byte[l2];
                (new DataInputStream(i2.getImageInputStream())).readFully(b2);

             // RenderedImage test_finger_print = ImageUtils.read(new ByteArrayInputStream(b2), l2, "image/x-wsq");

                DataOutputStream out1 = new DataOutputStream(new FileOutputStream(chipTCKN+".wsq"));
                out1.write(b1);
                byte [] jpgData1 = Jnbis.wsq().decode(b1).toJpg().asByteArray();
                String base64jpg1 = Base64.getEncoder().encodeToString(jpgData1);
                jsonObject.addProperty("Parmak1",base64jpg1);
                out1.flush();
                out1.close();

                DataOutputStream out2 = new DataOutputStream(new FileOutputStream(chipTCKN+"_2"+"img2.wsq"));
                out2.write(b2);
                byte [] jpgData2 = Jnbis.wsq().decode(b1).toJpg().asByteArray();
                String base64jpg2 = Base64.getEncoder().encodeToString(jpgData1);
                jsonObject.addProperty("Parmak2",base64jpg2);
                out2.flush();
                out2.close();





            }

            // personDetails.setFingerprints(fingerprintsImage);



        }
        CardFileInputStream sodFile = service.getInputStream(PassportService.EF_SOD);
        SODFile sod1  = new SODFile(sodFile);






        X509Certificate dscert = (X509Certificate) sod1.getDocSigningCertificate();
        PublicKey dscert_pub_key = sod1.getDocSigningCertificate().getPublicKey();
        dscert.checkValidity();






        Map<Integer, byte[]> datagroupHashes = sod1.getDataGroupHashes();




        System.out.println("SOD_________DOCSIGNER_________________"+sod1.getDocSigningCertificate());
        System.out.println("SOD_ALG---------"+sod1.getDigestAlgorithm() +" - - - "+sod1.getSignerInfoDigestAlgorithm());


        File csca = new File("/Users/erenbas/Documents/toTest1/CSCA.cer");
        FileInputStream file_csca = new FileInputStream(csca);
        CertificateFactorySpi fak_csca = new CertificateFactory();
        X509Certificate cer_csca = (X509Certificate) fak_csca.engineGenerateCertificate(file_csca);

        System.out.println("*******************"+sod1.getDocSigningCertificate().getSigAlgName());
        DG1File dg1File = new DG1File(service.getInputStream(PassportService.EF_DG1));
        DG14File dg14File = new DG14File(service.getInputStream(PassportService.EF_DG14));

        byte [] dg1_hash = calculateHash(dg1File.getEncoded());
        byte [] dg14_hash = calculateHash(dg14File.getEncoded());









        for (Map.Entry<Integer, byte[]> entry : datagroupHashes.entrySet()) {
            int dgNumber = entry.getKey();

            if (dgNumber==1)
            {
                //String s = "DG" + dgNumber + ": " + Hex.bytesToHexString(entry.getValue());
                //System.out.println(s);

                //System.out.println(sod1.getDocSigningCertificate().getSerialNumber());
                boolean isDataGroupsValid = entry.getValue().equals(dg1_hash);


                System.out.println("HESAPLANMIŞ HASH - - - - - - "+ isDataGroupsValid);
            }else{

                System.out.println(" ");

            }

















            try {
                //sodFile.getDocSigningCertificate().verify(cer_csca.getPublicKey());
                cer_csca.verify(cer_csca.getPublicKey());



            }
            catch (CertificateException e)
            {

                System.out.println(e.getMessage()+"-----"+"Verify not handled");
            }
            System.out.println("<<<<>>>>><<<<>>>>>>" + "CSCA - DS DOĞRULANDI" + "<<<<<>>>>><<<>>>>>");
           String jsonString = jsonObject.toString();



           return jsonString;




            // Signature verf = Signature.getInstance("ECDSA", "BC");
            // verf.initVerify(sodFile.getDocSigningCertificate());
            // verf.update(sodFile.getDocSigningCertificate().getSignature());
            // boolean sonuc = verf.verify(sodFile.getEncryptedDigest());

            // System.out.println("SONUC : : : : : : :"+sonuc);


        }
        return null;
    }
    private static byte[] calculateHash(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
    public byte[] tobyteArray(CardFileInputStream cfis) throws IOException {
        InputStream is =  cfis;
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        int nRead;
        byte[] data = new byte[16384];

        while ((nRead = is.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }

        return buffer.toByteArray();


    }
























}




