//    Copyright 2018 Tremolo Security, Inc.
// 
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
// 
//        http://www.apache.org/licenses/LICENSE-2.0
// 
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

package com.tremolosecurity.kubernetes.artifacts.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.stream.Collectors;

/**
 * NetUtil
 */
public class NetUtil {

    public static String downloadFile(String url) throws IOException {
        URL urlObj = new URL(url);
        URLConnection conn = urlObj.openConnection();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8)))
        {
            return reader.lines().collect(Collectors.joining("\n"));
        }
    }

    public static String whatsMyIP() throws SocketException {
        Enumeration<NetworkInterface> enumer = NetworkInterface.getNetworkInterfaces();
        while (enumer.hasMoreElements()) {
            NetworkInterface ni = enumer.nextElement();
            Enumeration<InetAddress> enumeri = ni.getInetAddresses();
            while (enumeri.hasMoreElements()) {
                InetAddress addr = enumeri.nextElement();
                if (! addr.getHostAddress().startsWith("127")) {
                    return addr.getHostAddress();
                }
            }
        }

        return "";
    }
}