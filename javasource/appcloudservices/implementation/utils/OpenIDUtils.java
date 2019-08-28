package appcloudservices.implementation.utils;

import com.mendix.core.Core;
import com.mendix.m2ee.api.IMxRuntimeRequest;
import com.mendix.systemwideinterfaces.core.ISession;

import java.io.InputStream;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;

public class OpenIDUtils {

    public static final String APPLICATION_ROOT_URL = Core.getConfiguration().getApplicationRootUrl() + (Core.getConfiguration().getApplicationRootUrl().endsWith("/") ? "" : "/");

    private static String base64Encode(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static String getFingerPrint(IMxRuntimeRequest req) {
        String agent = req.getHeader("User-Agent");
        if (agent != null)
            return base64Encode(agent.getBytes());

        return "";
    }

    public static String getFingerPrint(ISession session) {
        String agent = session.getUserAgent();
        if (agent != null)
            return base64Encode(agent.getBytes());

        return "";

    }

    public static String ensureEndsWithSlash(String text) {
        return text.endsWith("/") ? text : text + "/";
    }

    private static final String ALPHA_CAPS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String ALPHA = "abcdefghijklmnopqrstuvwxyz";
    private static final String NUM = "0123456789";
    private static final String SPL_CHARS = "!@#$%^&*_=+-/";

    public static String randomStrongPassword(int minLen, int maxLen, int noOfCAPSAlpha,
                                              int noOfDigits, int noOfSplChars) {
        if (minLen > maxLen)
            throw new IllegalArgumentException("Min. Length > Max. Length!");
        if ((noOfCAPSAlpha + noOfDigits + noOfSplChars) > minLen)
            throw new IllegalArgumentException
                    ("Min. Length should be at least sum of (CAPS, DIGITS, SPL CHARS) Length!");
        Random rnd = new Random();
        int len = rnd.nextInt(maxLen - minLen + 1) + minLen;
        char[] pswd = new char[len];
        int index;
        for (int i = 0; i < noOfCAPSAlpha; i++) {
            index = getNextIndex(rnd, len, pswd);
            pswd[index] = ALPHA_CAPS.charAt(rnd.nextInt(ALPHA_CAPS.length()));
        }
        for (int i = 0; i < noOfDigits; i++) {
            index = getNextIndex(rnd, len, pswd);
            pswd[index] = NUM.charAt(rnd.nextInt(NUM.length()));
        }
        for (int i = 0; i < noOfSplChars; i++) {
            index = getNextIndex(rnd, len, pswd);
            pswd[index] = SPL_CHARS.charAt(rnd.nextInt(SPL_CHARS.length()));
        }
        for (int i = 0; i < len; i++) {
            if (pswd[i] == 0) {
                pswd[i] = ALPHA.charAt(rnd.nextInt(ALPHA.length()));
            }
        }
        return String.valueOf(pswd);
    }

    private static int getNextIndex(Random rnd, int len, char[] pswd) {
        int index;
        //noinspection StatementWithEmptyBody
        while (pswd[index = rnd.nextInt(len)] != 0) ;
        return index;
    }

    public static String convertInputStreamToString(InputStream is) {
        final Scanner s = new Scanner(is).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";
    }
}
