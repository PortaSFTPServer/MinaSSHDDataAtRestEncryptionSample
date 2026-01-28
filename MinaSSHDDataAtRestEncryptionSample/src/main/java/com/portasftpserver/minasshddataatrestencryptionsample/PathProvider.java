/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.portasftpserver.minasshddataatrestencryptionsample;

import java.io.File;
import java.net.URISyntaxException;
import java.security.CodeSource;

/**
 *
 * @author Porta SFTP Server
 */
public class PathProvider {

    public static String AppLocation() {
        String startUpPath = PathProvider.class.getProtectionDomain().getCodeSource().getLocation().getPath();
        if (startUpPath.endsWith(".jar")) {
            CodeSource source = PathProvider.class.getProtectionDomain().getCodeSource();
            if (source != null) {
                try {
                    File jarFile = new File(source.getLocation().toURI());
                    startUpPath = String.valueOf(jarFile.getParentFile());
                } catch (URISyntaxException e) {
                }
            }
        } else {
            startUpPath = System.getProperty("user.dir");
        }
        return startUpPath;
    }
}
