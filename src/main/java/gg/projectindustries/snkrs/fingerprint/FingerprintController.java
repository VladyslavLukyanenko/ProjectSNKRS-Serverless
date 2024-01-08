package gg.projectindustries.snkrs.fingerprint;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;

@RestController
public class FingerprintController {
    private static final String[] locales = {"AFG", "ALB", "DZA", "ASM", "AND", "AGO", "AIA", "ATA", "ATG", "ARG", "ARM", "ABW", "AUS", "AUT", "AZE", "BHS", "BHR", "BGD", "BRB", "BLR", "BEL", "BLZ", "BEN", "BMU", "BTN", "BOL", "BES", "BIH", "BWA", "BVT", "BRA", "IOT", "BRN", "BGR", "BFA", "BDI", "CPV", "KHM", "CMR", "CAN", "CYM", "CAF", "TCD", "CHL", "CHN", "CXR", "CCK", "COL", "COM", "COD", "COG", "COK", "CRI", "HRV", "CUB", "CUW", "CYP", "CZE", "CIV", "DNK", "DJI", "DMA", "DOM", "ECU", "EGY", "SLV", "GNQ", "ERI", "EST", "SWZ", "ETH", "FLK", "FRO", "FJI", "FIN", "FRA", "GUF", "PYF", "ATF", "GAB", "GMB", "GEO", "DEU", "GHA", "GIB", "GRC", "GRL", "GRD", "GLP", "GUM", "GTM", "GGY", "GIN", "GNB", "GUY", "HTI", "HMD", "VAT", "HND", "HKG", "HUN", "ISL", "IND", "IDN", "IRN", "IRQ", "IRL", "IMN", "ISR", "ITA", "JAM", "JPN", "JEY", "JOR", "KAZ", "KEN", "KIR", "PRK", "KOR", "KWT", "KGZ", "LAO", "LVA", "LBN", "LSO", "LBR", "LBY", "LIE", "LTU", "LUX", "MAC", "MDG", "MWI", "MYS", "MDV", "MLI", "MLT", "MHL", "MTQ", "MRT", "MUS", "MYT", "MEX", "FSM", "MDA", "MCO", "MNG", "MNE", "MSR", "MAR", "MOZ", "MMR", "NAM", "NRU", "NPL", "NLD", "NCL", "NZL", "NIC", "NER", "NGA", "NIU", "NFK", "MNP", "NOR", "OMN", "PAK", "PLW", "PSE", "PAN", "PNG", "PRY", "PER", "PHL", "PCN", "POL", "PRT", "PRI", "QAT", "MKD", "ROU", "RUS", "RWA", "REU", "BLM", "SHN", "KNA", "LCA", "MAF", "SPM", "VCT", "WSM", "SMR", "STP", "SAU", "SEN", "SRB", "SYC", "SLE", "SGP", "SXM", "SVK", "SVN", "SLB", "SOM", "ZAF", "SGS", "SSD", "ESP", "LKA", "SDN", "SUR", "SJM", "SWE", "CHE", "SYR", "TWN", "TJK", "TZA", "THA", "TLS", "TGO", "TKL", "TON", "TTO", "TUN", "TUR", "TKM", "TCA", "TUV", "UGA", "UKR", "ARE", "GBR", "UMI", "USA", "URY", "UZB", "VUT", "VEN", "VNM", "VGB", "VIR", "WLF", "ESH", "YEM", "ZMB", "ZWE", "ALA"};
    private static final String[] AndroidSDKVersions = {"21", "22", "23", "24", "25", "26", "27", "28"};
    private static final String[] AndroidVersions = {"5.0.0", "5.0.1","5.0.2","5.1.0","5.1.1","6.0.0","6.0.1","7.0.0","7.1.0","7.1.1","7.1.2","8.0.0","8.1.0","9.0.0"};
    private static final String[] devices = {"Samsung Galaxy J2 Core","Samsung Galaxy A21","Samsung Galaxy M11","Samsung Galaxy Tab S6 Lite","Samsung Galaxy A31","Samsung Galaxy A41","Samsung Galaxy M21","Samsung Galaxy A11","Samsung Galaxy M31","Samsung Galaxy S20 Ultra","Samsung Galaxy S20+","Samsung Galaxy S20","Samsung Galaxy Z Flip","Samsung Galaxy Xcover Pro","Samsung Galaxy Note10 Lite","Samsung Galaxy S10 Lite","Samsung Galaxy A01","Samsung Galaxy A71","Samsung Galaxy A51","Samsung Galaxy Xcover FieldPro","Samsung Galaxy A70s","Samsung Galaxy A20s","Samsung Galaxy M30s","Samsung Galaxy M10s","Samsung Galaxy Fold","Samsung Galaxy Tab Active Pro","Samsung Galaxy A30s","Samsung Galaxy A50s","Samsung Galaxy Note10+","Samsung Galaxy Note10","Samsung Galaxy Watch Active2","Samsung Galaxy Watch Active2 Aluminum","Samsung Galaxy A10s","Samsung Galaxy A10e","Samsung Galaxy Tab S6","Samsung Galaxy Xcover 4s","Samsung Galaxy A2 Core","Samsung Galaxy Watch Active","Samsung Galaxy View2","Samsung Galaxy S10+","Samsung Galaxy S10","Samsung Galaxy S10e","Samsung Galaxy M40","Samsung Galaxy M30","Samsung Galaxy M20","Samsung Galaxy M10","Samsung Galaxy A80","Samsung Galaxy A70","Samsung Galaxy A60","Samsung Galaxy A50","Samsung Galaxy A40","Samsung Galaxy A30","Samsung Galaxy A20e","Samsung Galaxy A20","Samsung Galaxy A10","Samsung Galaxy Tab S5e","Samsung Galaxy Tab Advanced2","Samsung Galaxy A8s","Samsung Galaxy A6s","Samsung Galaxy A9","Samsung Galaxy A7","Samsung Galaxy Note9","Samsung Galaxy Watch","Samsung Galaxy J6+","Samsung Galaxy J4 Core","Samsung Galaxy J4+","Samsung Galaxy J2 Core","Samsung Galaxy On6","Samsung Galaxy J7","Samsung Galaxy J3","Samsung Galaxy A8 Star","Samsung Galaxy S Light Luxury","Samsung Galaxy J8","Samsung Galaxy J6","Samsung Galaxy J4","Samsung Galaxy A6+","Samsung Galaxy A6","Samsung Galaxy J7 Duo","Samsung Galaxy J7 Prime 2","Samsung Galaxy S9+","Samsung Galaxy S9","Samsung Galaxy J2 Pro","Samsung Galaxy A8+","Samsung Galaxy A8","Samsung Galaxy J2","Samsung Galaxy Tab Active 2","Samsung Galaxy C7","Samsung Gear Sport","Samsung Galaxy Note8","Samsung Galaxy S8 Active","Samsung Galaxy J7 V","Samsung Galaxy Note FE","Samsung Galaxy J7 Max","Samsung Galaxy J7 Pro","Samsung Galaxy J7","Samsung Galaxy J5","Samsung Galaxy J3","Samsung Galaxy Folder2","Samsung Z4","Samsung Galaxy S8","Samsung Galaxy S8+","Samsung Gear S3 classic LTE","Samsung Galaxy C5 Pro","Samsung Galaxy Xcover 4","Samsung Galaxy J1 mini prime","Samsung Galaxy J3 Emerge","Samsung Galaxy C7 Pro","Samsung Galaxy A7","Samsung Galaxy A5","Samsung Galaxy A3","Samsung Galaxy Grand Prime Plus","Samsung Galaxy J2 Prime","Samsung Galaxy C9 Pro","Samsung Galaxy C10","Samsung Galaxy A8","Samsung Galaxy On8","Samsung Galaxy On7","Samsung Gear S3 classic","Samsung Gear S3 frontier","Samsung Gear S3 frontier LTE","Samsung Galaxy J5 Prime","Samsung Galaxy J7 Prime","Samsung Z2","Samsung Galaxy Note7","Samsung Galaxy On7 Pro","Samsung Galaxy On5 Pro","Samsung Galaxy Tab J","Samsung Galaxy J Max","Samsung Galaxy J2 Pro","Samsung Galaxy J2","Samsung Z3 Corporate","Samsung Galaxy Xcover 3 G389F","Samsung Galaxy S7 active","Samsung Galaxy J3 Pro","Samsung Galaxy C7","Samsung Galaxy C5","Samsung Galaxy A9 Pro","Samsung Galaxy J7","Samsung Galaxy J5","Samsung Galaxy S7","Samsung Galaxy S7 edge","Samsung Galaxy S7","Samsung Galaxy J1 Nxt","Samsung Galaxy J1","Samsung Galaxy A9","Samsung Galaxy A7","Samsung Galaxy A5","Samsung Galaxy A3","Samsung Galaxy Express Prime","Samsung Galaxy J3","Samsung Galaxy View","Samsung Galaxy On7","Samsung Galaxy On5","Samsung Z3","Samsung Galaxy J1 Ace","Samsung Gear S2 classic","Samsung Gear S2","Samsung Galaxy Note5","Samsung Galaxy Note5 Duos","Samsung Galaxy S6 edge+","Samsung Galaxy S6 edge+ Duos","Samsung Galaxy S5 Neo","Samsung Galaxy S4 mini I9195I","Samsung Galaxy Folder","Samsung Galaxy A8 Duos","Samsung Galaxy A8","Samsung Galaxy V Plus","Samsung Galaxy J7","Samsung Galaxy J7 Nxt","Samsung Galaxy J5","Samsung Guru Plus","Samsung Metro 360","Samsung Xcover 550","Samsung Galaxy S6 active","Samsung Galaxy Tab 3 V","Samsung Galaxy Xcover 3","Samsung Galaxy S6 edge","Samsung Galaxy S6 Plus","Samsung Galaxy S6 Duos","Samsung Galaxy S6","Samsung Galaxy J1","Samsung Galaxy J2","Samsung Z1","Samsung Galaxy A7 Duos","Samsung Galaxy A7","Samsung Galaxy Grand Max","Samsung Galaxy E7","Samsung Galaxy E5","Samsung Galaxy Core Prime","Samsung Galaxy A5 Duos","Samsung Galaxy A5","Samsung Galaxy A3 Duos","Samsung Galaxy A3","Samsung Galaxy S5 Plus","Samsung Galaxy Pocket 2","Samsung Galaxy V","Samsung Galaxy Grand Prime Duos TV","Samsung Galaxy Grand Prime","Samsung Galaxy Ace Style LTE G357","Samsung Galaxy Note Edge","Samsung Galaxy Note 4 Duos","Samsung Galaxy Note 4","Samsung Galaxy Tab Active LTE","Samsung Galaxy Tab Active","Samsung Galaxy Mega 2","Samsung Gear S","Samsung Gear 2 Neo","Samsung Gear Live","Samsung Gear 2","Samsung Galaxy Gear","Samsung Galaxy S5 LTE-A G901F","Samsung Galaxy Alpha","Samsung Galaxy Alpha","Samsung Galaxy S5 mini Duos","Samsung Galaxy Avant","Samsung Galaxy S Duos 3","Samsung Guru Music 2","Samsung Metro 312","Samsung Galaxy Ace NXT","Samsung Galaxy Star 2 Plus","Samsung Galaxy S5 mini","Samsung Galaxy Ace 4 LTE G313","Samsung Galaxy Ace 4","Samsung Galaxy Young 2","Samsung Galaxy Star 2","Samsung Galaxy Core II","Samsung Galaxy S5 Sport","Samsung Galaxy S5 LTE-A G906S","Samsung Galaxy Core Lite LTE","Samsung I9301I Galaxy S3 Neo","Samsung Galaxy W","Samsung Z","Samsung Galaxy S5 Active","Samsung Galaxy K zoom","Samsung Galaxy Beam2","Samsung I9300I Galaxy S3 Neo","Samsung Galaxy Ace Style","Samsung ATIV SE","Samsung G3812B Galaxy S3 Slim","Samsung I8200 Galaxy S III mini VE","Samsung Galaxy S5 Duos","Samsung Galaxy S5","Samsung Galaxy Core LTE G386W","Samsung Galaxy Core LTE","Samsung S5611","Samsung E1272","Samsung Galaxy Star Trios S5283","Samsung Galaxy Note 3 Neo Duos","Samsung Galaxy Note 3 Neo","Samsung Galaxy Grand Neo","Samsung Galaxy Camera 2 GC200","Samsung Galaxy Core Advance","Samsung Galaxy S4 Active LTE-A","Samsung Galaxy J","Samsung Galaxy Win Pro G3812","Samsung Galaxy S Duos 2 S7582","Samsung Galaxy Grand 2","Samsung I9230 Galaxy Golden","Samsung Galaxy Express 2","Samsung C3590","Samsung I9506 Galaxy S4","Samsung Galaxy Light","Samsung Galaxy Round G910S","Samsung Galaxy Fresh S7390","Samsung Galaxy Core Plus","Samsung Galaxy Fame Lite Duos S6792L","Samsung Galaxy Fame Lite S6790","Samsung Galaxy Star Pro S7260","Samsung Galaxy Note 3","Samsung Ch@t 333","Samsung Galaxy Prevail 2","Samsung Gravity Q T289","Samsung ATIV S Neo","Samsung Galaxy S4 zoom","Samsung Galaxy S II TV","Samsung Galaxy Ace 3","Samsung Galaxy Exhibit T599","Samsung Galaxy Core I8260","Samsung Galaxy Trend II Duos S7572","Samsung Galaxy Win I8550","Samsung Galaxy Pocket Neo S5310","Samsung Galaxy Star S5280","Samsung Galaxy S4 CDMA","Samsung Galaxy Y Plus S5303","Samsung Rex 90 S5292","Samsung Rex 80 S5222R","Samsung Rex 70 S3802","Samsung Rex 60 C3312R","Samsung Metro E2202","Samsung E1282T","Samsung E1207T","Samsung Galaxy Young S6310","Samsung Galaxy Fame S6810","Samsung Galaxy Express I8730","Samsung S7710 Galaxy Xcover 2","Samsung I9105 Galaxy S II Plus","Samsung Ativ Odyssey I930","Samsung Galaxy Grand I9082","Samsung Galaxy Grand I9080","Samsung Star Deluxe Duos S5292","Samsung A997 Rugby III","Samsung Galaxy Axiom R830","Samsung Galaxy Stratosphere II I415","Samsung Galaxy Discover S730M","Samsung Galaxy Pop SHV-E220","Samsung Galaxy Premier I9260","Samsung Google Nexus 10 P8110","Samsung Ativ Tab P8510","Samsung Comment 2 R390C","Samsung I8190 Galaxy S III mini","Samsung Galaxy Music S6010","Samsung Galaxy Music Duos S6012","Samsung Galaxy Rugby Pro I547","Samsung Galaxy Express I437","Samsung Ch@t 357","Samsung I9305 Galaxy S III","Samsung Galaxy Victory 4G LTE L300","Samsung Galaxy S Relay 4G T699","Samsung Champ Neo Duos C3262","Samsung Galaxy Pocket Duos S5302","Samsung Galaxy Note II N7100","Samsung Galaxy Note II CDMA","Samsung Ativ S I8750","Samsung Galaxy Camera GC100","Samsung Galaxy Rush M830","Samsung Galaxy Reverb M950","Samsung Array M390","Samsung Galaxy S Duos S7562","Samsung Manhattan E3300","Samsung E2262","Samsung E1260B","Samsung E1200 Pusha","Samsung E2252","Samsung Galaxy Chat B5330","Realme 6i","Realme 6 Pro","Realme 6","Realme C3","Realme 5i","Realme 5s","Realme C2s","Realme C2 2020","Realme X2 Pro","Realme X2","Realme XT 730G","Realme XT","Realme Q","Realme 5 Pro","Realme 5","Realme 3i","Realme X","Realme 3 Pro","Realme C2","Realme 3","Realme C1","Realme U1","Realme 2 Pro","Realme C1","Realme 2","Realme 1","Google Pixel 4 XL","Google Pixel 4","Google Pixel 3a XL","Google Pixel 3a","Google Pixel 3 XL","Google Pixel 3","Google Pixel XL","Google Pixel 2 XL","Google Pixel 2","Google Pixel","Google Pixel C","Vivo Y50","Vivo V19","Vivo V19","Vivo X30 Pro","Vivo X30","Vivo V17","Vivo iQOO Neo 855 Racing","Vivo Y9s","Vivo Z5i","Vivo V17","Vivo S1 Pro","Vivo S5","Vivo U20","Vivo Y3 Standard","Vivo Y5s","Vivo Y19","Vivo iQOO Neo 855","Vivo Y11","Vivo U3","Vivo U10","Vivo Y3","Vivo V17 Pro","Vivo NEX 3","Vivo Z1x","Vivo iQOO Pro","Vivo Y90","Vivo V17 Neo","Vivo Z5","Vivo S1","Vivo Z1Pro","Vivo iQOO Neo","Vivo Z5x","Huawei nova 7 SE","Huawei MatePad","Huawei Watch GT 2e","Huawei P40 Pro+","Huawei P40 Pro","Huawei P40","Huawei P40 lite E","Huawei P40 lite","Huawei Mate Xs","Huawei P30 lite New Edition","Huawei Y7p","Huawei nova 7i","Huawei Y6s","Huawei P smart Pro 2019","Huawei nova 6 5G","Huawei nova 6","Huawei nova 6 SE","Huawei MatePad Pro","Huawei Mate X","Huawei Y9s","Huawei nova 5z","Huawei Enjoy 10s","Huawei Enjoy 10","Huawei Mate 30 RS Porsche Design","Huawei Mate 30 Pro","Huawei Mate 30","Huawei Watch GT 2","Huawei nova 5i Pro","Huawei Enjoy 10 Plus","Huawei nova 5T","Huawei nova 5 Pro","Huawei nova 5","Honor 9X Lite","Honor 30 Pro+","Honor 30 Pro","Honor 30","Honor 20e","Honor Play 4T Pro","Honor Play 4T","Honor 8A 2020","Honor 8A Prime","Honor 30S","Honor Play 9A","Honor View30 Pro","Honor View30","Honor V30 Pro","Honor V30","Honor MagicWatch 2","Honor 9X","Honor 20 lite","Honor Play 3e","Honor Play 3","Honor 20S","Honor 9X Pro","Honor 9X","Honor 8S"};
    private static final String AB = "0123456789abcdefghijklmnopqrstuvwxyz";
    private static final SecureRandom rnd = new SecureRandom();
    private static String getLocale(){
        int rnd = new Random().nextInt(locales.length);
        return locales[rnd];
    }
    private static String getAndroidSDKVersion(){
        int rnd = new Random().nextInt(AndroidSDKVersions.length);
        return AndroidSDKVersions[rnd];
    }
    private static String getDevice(){
        int rnd = new Random().nextInt(devices.length);
        return devices[rnd];
    }
    private static String getAndroidVersion(){
        int rnd = new Random().nextInt(AndroidVersions.length);
        return AndroidVersions[rnd];
    }
    private static String randomString( int len ){
        StringBuilder sb = new StringBuilder( len );
        for( int i = 0; i < len; i++ )
            sb.append( AB.charAt( rnd.nextInt(AB.length()) ) );
        return sb.toString();
    }
    private static String getFingerprint(){
        return randomString(32);
    }
    private static String getAndroidID(){
        return randomString(16);
    }
    private static String getTime() {
        Calendar instance = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        return String.format("%04d %02d %02d %02d:%02d:%02d.%03d", instance.get(Calendar.YEAR), instance.get(Calendar.MONTH) + 1, instance.get(Calendar.DATE), instance.get(Calendar.HOUR_OF_DAY), instance.get(Calendar.MINUTE), instance.get(Calendar.SECOND), instance.get(Calendar.MILLISECOND));
    }
    @RequestMapping("/")
    public String index() {
        return generate();
    }
    private static String generate() {
        StringBuilder sb = new StringBuilder("0500");
        HashMap<String, String> hashMap = new HashMap<>();
        addToMap(hashMap, "BBSC", "Android");
        addToMap(hashMap, "CLIENT_TIME", getTime());
        addToMap(hashMap, "AFPID", getFingerprint());
        addToMap(hashMap, "MACA", "02:00:00:00:00:00");
        addToMap(hashMap, "ASL", getAndroidSDKVersion());
        addToMap(hashMap, "ABN", "vbox86p-userdebug 8.0.0 OPR6.170623.017 391 test-keys");
        addToMap(hashMap, "AMID", getAndroidID());
        addToMap(hashMap, "ADSV", getAndroidVersion());
        addToMap(hashMap, "ADM", getDevice());
        addToMap(hashMap, "ADLO", getLocale());
        sb.append(toUTF(iterate(hashMap)));
        return sb.toString();
    }
    private static String iterate(Map<String, String> map) {
        StringBuilder sb = new StringBuilder();
        if (map == null) {
            sb.append("0");
        } else {
            Formatter formatter = new Formatter(sb);
            formatter.format("%04x", map.size());
            for (Object o : map.entrySet()) {
                Map.Entry pair = (Map.Entry) o;
                format(formatter, (String) pair.getKey());
                format(formatter, (String) pair.getValue());
            }
        }
        return sb.toString();
    }
    private static void format(Formatter formatter, String str) {
        formatter.format("%04x", str.length());
        formatter.format("%s", str);
    }
    private static void addToMap(Map<String, String> map, String str, String str2) {
        if (str != null && str2 != null && str2.length() > 0) {
            map.put(str, str2);
        }
    }
    private static String toUTF(String str) {
        String str2 = "";
        if (str != null) {
            return encrypt(str.getBytes(StandardCharsets.UTF_8));
        }
        return str2;
    }
    private static String encrypt(byte[] bArr) {
        byte[] bArr2 = {16, -59, 20, -5, -54, -85, 110, 61, -51, -99, 70, -78, 11, -44, 3, 5, -120, 58, -14, 74, 13, -122, 35, 120, 14, -60, 67, 73, -58, -90, 42, 112};
        try {
            byte[] bArr3 = new byte[16];
            new Random().nextBytes(bArr3);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            byteArrayOutputStream.write("0500".getBytes());
            byteArrayOutputStream.write(bArr);
            byteArrayOutputStream.write(new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, byteArrayOutputStream.size() % 16 == 0 ? 0 : 16 - (byteArrayOutputStream.size() % 16));
            Cipher instance = Cipher.getInstance("AES/CBC/NoPadding");
            instance.init(1, new SecretKeySpec(bArr2, "AES"), new IvParameterSpec(bArr3));
            byte[] doFinal = instance.doFinal(byteArrayOutputStream.toByteArray());
            ByteArrayOutputStream byteArrayOutputStream2 = new ByteArrayOutputStream();
            byteArrayOutputStream2.write(bArr3);
            byteArrayOutputStream2.write(doFinal);
            return new String(enCrypt(byteArrayOutputStream2.toByteArray()));
        } catch (Throwable unused) {
            return "";
        }
    }
    private static byte[] enCrypt(byte[] var0) throws Exception {
        byte[] var1 = new byte[]{65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 43, 47};
        if (var0 != null) {
            int var2 = var0.length;
            if (var2 != 0) {
                int var3 = var2 / 3;
                int var4 = 0;
                byte var5;
                if (var2 % 3 != 0) {
                    var5 = 1;
                } else {
                    var5 = 0;
                }
                byte[] var6 = new byte[(var5 + var3) * 4];
                int var7 = 0;
                int var8;
                int var10;
                for(var10 = 0; var4 < var3; ++var7) {
                    var8 = var7 + 1;
                    byte var9 = var0[var7];
                    var7 = var8 + 1;
                    var8 = (var9 & 255) << 16 | (var0[var8] & 255) << 8 | var0[var7] & 255;
                    int var11 = var10 + 1;
                    var6[var10] = var1[var8 >> 18 & 63];
                    var10 = var11 + 1;
                    var6[var11] = var1[var8 >> 12 & 63];
                    var11 = var10 + 1;
                    var6[var10] = var1[var8 >> 6 & 63];
                    var10 = var11 + 1;
                    var6[var11] = var1[var8 & 63];
                    ++var4;
                }
                var8 = var3 * 3;
                if (var8 < var2) {
                    var3 = (var0[var7] & 255) << 16;
                    var4 = var10 + 1;
                    var6[var10] = var1[var3 >> 18 & 63];
                    if (var8 + 1 < var2) {
                        var2 = (var0[var7 + 1] & 255) << 8 | var3;
                        var7 = var4 + 1;
                        var6[var4] = var1[var2 >> 12 & 63];
                        var10 = var7 + 1;
                        var6[var7] = var1[var2 >> 6 & 63];
                    } else {
                        var7 = var4 + 1;
                        var6[var4] = var1[var3 >> 12 & 63];
                        var10 = var7 + 1;
                        var6[var7] = (byte)61;
                    }
                    var6[var10] = (byte)61;
                }
                return var6;
            }
        }
        throw new Exception("Invalid length");
    }
}
