package global;

import java.util.ArrayList;
import java.util.List;

import pivtrum.PivtrumPeerData;

/**
 * Created by furszy on 7/2/17.
 */

public class PivtrumGlobalData {

    // 7 --> new InetSocketAddress("2001:470:1f11:1d4:bc13:daff:fe53:da07", params.getPort());
    // 5 --> 2001:470:1f11:1d4:b81a:24ff:fea3:cd76
    public static final String MAINNET_NODE = "95.179.157.87"; // --> está corriendo en testnet ahora..
    public static final String FURSZY_TESTNET_SERVER = "2001:470:1f11:1d4:bc13:daff:fe53:da07";
    //"192.168.0.3"; //"185.101.98.175" "185.101.98.230";

    public static final String[] TRUSTED_NODES = new String[]{ //MAINNET_NODE,"185.101.98.146"};
        "159.69.88.150", "159.69.18.145", "159.69.12.84", "95.216.164.133", "95.216.164.172", "95.216.164.145"};
     //FURSZY_TESTNET_SERVER, "2001:470:1f11:1d4:b81a:24ff:fea3:cd76", "2001:470:1f11:1d4:58f5:6ff:fe80", MAINNET_NODE};
            //"node.pivxwiki.org", "panther.pivxwiki.org", "pivx.warrows.fr"};

    public static final List<PivtrumPeerData> listTrustedHosts(int paramsPort){
        List<PivtrumPeerData> list = new ArrayList<>();
        //list.add(new PivtrumPeerData(FURSZY_TESTNET_SERVER,8443,55552));
        for (String trustedNode : TRUSTED_NODES) {
            list.add(new PivtrumPeerData(trustedNode,paramsPort,55552));
        }
        return list;
    }

}
