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
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * DbUtils
 */
public class DbUtils {


    public static void runSQL(List<String> sqls, String driver, String url, String userName, String password)
            throws ClassNotFoundException, SQLException {
        Class.forName(driver);
        Connection con = DriverManager.getConnection(url, userName, password);
        Statement stmt = con.createStatement();
        for (String sql : sqls) {
            System.out.println("sql : '" + sql + "'");
            stmt.execute(sql);
        }

        stmt.close();
        con.close();
    }

    public static List<String> parseSQL(String source) throws IOException {
        ArrayList<String> sqlStatements = new ArrayList<String>();

        BufferedReader in = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(source.getBytes("UTF-8"))));

        String line;
        String sql = null;

        while ((line = in.readLine()) != null) {
            if (sql == null) {
                if (line.trim().length() == 0 || line.trim().startsWith("#") || line.trim().startsWith("-")) {
                    continue;
                } else {
                    sql = line;
                }
            } else {
                sql += " " + line;

            }

            if (sql.trim().endsWith(";")) {
                sql = sql.trim();
                sql = sql.substring(0,sql.lastIndexOf(';'));
                sqlStatements.add(sql);
                sql = null;
            }
        }



        return sqlStatements;

    }
}