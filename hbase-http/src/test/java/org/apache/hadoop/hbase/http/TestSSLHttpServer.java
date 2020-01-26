/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.hbase.http;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.security.Security;
import javax.net.ssl.HttpsURLConnection;
import org.apache.commons.io.FileUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileUtil;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hbase.HBaseClassTestRule;
import org.apache.hadoop.hbase.HBaseCommonTestingUtility;
import org.apache.hadoop.hbase.HBaseConfiguration;
import org.apache.hadoop.hbase.http.log.TestLogLevel;
import org.apache.hadoop.hbase.http.ssl.KeyStoreTestUtil;
import org.apache.hadoop.hbase.testclassification.MiscTests;
import org.apache.hadoop.hbase.testclassification.SmallTests;
import org.apache.hadoop.io.IOUtils;
import org.apache.hadoop.net.NetUtils;
import org.apache.hadoop.security.ssl.SSLFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This testcase issues SSL certificates configures the HttpServer to serve
 * HTTPS using the created certficates and calls an echo servlet using the
 * corresponding HTTPS URL.
 */
@Category({MiscTests.class, SmallTests.class})
public class TestSSLHttpServer extends HttpServerFunctionalTest {

  @ClassRule
  public static final HBaseClassTestRule CLASS_RULE =
    HBaseClassTestRule.forClass(TestSSLHttpServer.class);

  private static String BASEDIR = System.getProperty("test.build.dir", TestSSLHttpServer.class.getSimpleName());

  private static final Logger LOG = LoggerFactory.getLogger(TestSSLHttpServer.class);
  private static Configuration conf;
  private static HttpServer server;
  private static URL baseUrl;
  private static String keystoresDir;
  private static String sslConfDir;
  private static SSLFactory clientSslFactory;

  @BeforeClass
  public static void setup() throws Exception {
    Security.addProvider(new BouncyCastleProvider());

    String classDir = KeyStoreTestUtil.getClasspathDir(TestSSLHttpServer.class);

   // Configuration conf = new Configuration();

    HBaseCommonTestingUtility htu = new HBaseCommonTestingUtility();


    conf = htu.getConfiguration();
    conf.setInt(HttpServer.HTTP_MAX_THREADS, TestHttpServer.MAX_THREADS);

    String subPath = "/test-dir/" + htu.getRandomUUID();
    BASEDIR = classDir + subPath;

    LOG.info("Base dir is " + BASEDIR);

    conf.set("hadoop.home.dir", BASEDIR);

    File base = new File(BASEDIR);
    FileUtil.fullyDelete(base);
    base.mkdirs();

    keystoresDir = new File(BASEDIR).getAbsolutePath();


    LOG.info("Copy {} to {}", classDir, base);

   // FileUtils.copyDirectory(new File(classDir), base);



    KeyStoreTestUtil.setupSSLConfig(BASEDIR, BASEDIR, conf, false);

//   / conf.set("hadoop.ssl.hostname.verifier", "ALLOW_ALL");


    assertTrue(new File(BASEDIR, "ssl-server.xml").exists());
    assertTrue(new File(BASEDIR, "ssl-client.xml").exists());

    Configuration sslConf = new Configuration(false);

    sslConf.addResource(new Path(BASEDIR + "/ssl-server.xml"));
    sslConf.addResource(new Path(BASEDIR + "/ssl-client.xml"));

    System.out.println("sslconf:" + sslConf.getPropsWithPrefix("hadoop"));

  //  sslConf.set("hadoop.ssl.client.conf", new File(BASEDIR, "ssl-client.xml").getAbsolutePath());
   // sslConf.set("hadoop.ssl.server.conf", new File(BASEDIR, "ssl-sever.xml").getAbsolutePath());

    //conf.set("hadoop.ssl.client.conf", new File(BASEDIR, "ssl-server.xml").getAbsolutePath());
    //conf.set("hadoop.ssl.server.conf", new File(BASEDIR, "ssl-sever.xml").getAbsolutePath());


   // System.setProperty("javax.net.ssl.trustStore", sslConf.get("ssl.server.keystore.location"));
    System.out.println("client conf:" + sslConf.getStrings("ssl.client.conf"));
//    sslConf.set("ssl.hostname.verifier", "ALLOW_ALL");
//    sslConf.set("ssl.client.truststore.location", sslConf.get("ssl.server.truststore.location"));
//    sslConf.set("ssl.client.truststore.password", "trustP");

    System.out.println("location:" + sslConf.get("ssl.server.truststore.location"));
    //System.out.println("hostnamever:" + clientSslFactory.getHostnameVerifier().toString());
    sslConf.set("hadoop.ssl.hostname.verifier", "ALLOW_ALL");
    sslConf.set("hadoop.ssl.enabled.protocols", "TLSv1,SSLv2Hello,TLSv1.1,TLSv1.2,TLSv1.3");

    conf.set("hadoop.ssl.hostname.verifier", "ALLOW_ALL");

  //  System.out.println("hostnamever:" + clientSslFactory.getHostnameVerifier().toString());

    //assertTrue(new File(sslConf.get("hadoop.ssl.server.keystore.location")).exists());

    server = new HttpServer.Builder()
      .setName("test")
//      /.setDataDir(new File(BASEDIR))
      .addEndpoint(new URI("https://localhost"))
      .setConf(conf)

      .keyPassword(HBaseConfiguration.getPassword(sslConf, "ssl.server.keystore.keypassword",
        null))
      .keyStore(sslConf.get("ssl.server.keystore.location"),
        HBaseConfiguration.getPassword(sslConf, "ssl.server.keystore.password", null),
        sslConf.get("ssl.server.keystore.type", "jks"))
      .trustStore(sslConf.get("ssl.server.truststore.location"),
        HBaseConfiguration.getPassword(sslConf, "ssl.server.truststore.password", null),
        sslConf.get("ssl.server.truststore.type", "jks")).build();
    server.addServlet("echo", "/echo", TestHttpServer.EchoServlet.class);

    System.setProperty("javax.net.ssl.trustStore",sslConf.get("ssl.server.truststore.location"));

    server.start();

    baseUrl = new URL("https://"
      + NetUtils.getHostPortString(server.getConnectorAddress(0)));
    LOG.info("HTTP server started: " + baseUrl);

    //System.setProperty("javax.net.ssl.trustStore",sslConf.get("ssl.server.truststore.location"));
//    sslConf.set("ssl.client.truststore.location", BASEDIR + "/trustKS.jsk");
//    sslConf.set("hadoop.ssl.client.truststore.location", BASEDIR + "/trustKS.jsk");
//    sslConf.set("ssl.client.truststore.password", "trustP");
//    sslConf.set("hadoop.ssl.client.truststore.password", "trustP");



    // sslConf.set("ssl.client.keystore.location", "file://" + BASEDIR + "/trustKS.jsk");
    sslConf.set("hadoop.ssl.client.conf", "file://" + BASEDIR + "/ssl-client.xml");
    sslConf.set("hadoop." + SSLFactory.SSL_REQUIRE_CLIENT_CERT_KEY, "false");

    System.out.println("STARTS CLIENT!");

    clientSslFactory = new SSLFactory(SSLFactory.Mode.CLIENT, sslConf);

    clientSslFactory.init();

  }

  @AfterClass
  public static void cleanup() throws Exception {
    server.stop();
   // FileUtil.fullyDelete(new File(BASEDIR));
   // KeyStoreTestUtil.cleanupSSLConfig(keystoresDir, sslConfDir);
    clientSslFactory.destroy();
  }

  @Test
  public void testEcho() throws Exception {
    assertEquals("a:b\nc:d\n", readOut(new URL(baseUrl, "/echo?a=b&c=d")));
    assertEquals("a:b\nc&lt;:d\ne:&gt;\n", readOut(new URL(baseUrl,
      "/echo?a=b&c<=d&e=>")));
  }

  private static String readOut(URL url) throws Exception {

    HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
    conn.setSSLSocketFactory(clientSslFactory.createSSLSocketFactory());

    InputStream in = conn.getInputStream();
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    IOUtils.copyBytes(in, out, 1024);
    return out.toString();
  }

}
