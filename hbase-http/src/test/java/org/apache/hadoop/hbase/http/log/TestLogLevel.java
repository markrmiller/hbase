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
package org.apache.hadoop.hbase.http.log;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.net.BindException;
import java.net.ServerSocket;
import java.net.SocketException;
import java.net.URI;
import java.security.PrivilegedExceptionAction;
import java.util.Locale;
import java.util.Properties;
import javax.net.ssl.SSLException;

import org.apache.commons.io.FileUtils;
import org.apache.hadoop.HadoopIllegalArgumentException;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeys;
import org.apache.hadoop.fs.CommonConfigurationKeysPublic;
import org.apache.hadoop.fs.FileUtil;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hbase.HBaseClassTestRule;
import org.apache.hadoop.hbase.HBaseCommonTestingUtility;
import org.apache.hadoop.hbase.http.HttpConfig;
import org.apache.hadoop.hbase.http.HttpServer;
import org.apache.hadoop.hbase.http.TestSSLHttpServer;
import org.apache.hadoop.hbase.http.log.LogLevel.CLI;
import org.apache.hadoop.hbase.http.ssl.KeyStoreTestUtil;
import org.apache.hadoop.hbase.testclassification.MiscTests;
import org.apache.hadoop.hbase.testclassification.SmallTests;
import org.apache.hadoop.hdfs.DFSConfigKeys;
import org.apache.hadoop.minikdc.MiniKdc;
import org.apache.hadoop.net.NetUtils;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.authorize.AccessControlList;
import org.apache.hadoop.security.ssl.SSLFactory;
import org.apache.hadoop.test.GenericTestUtils;
import org.apache.hadoop.util.StringUtils;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.apache.log4j.Level;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.LoggerFactory;

/**
 * Test LogLevel.
 */
@Category({MiscTests.class, SmallTests.class})
public class TestLogLevel {
  @ClassRule
  public static final HBaseClassTestRule CLASS_RULE =
      HBaseClassTestRule.forClass(TestLogLevel.class);

  private static final org.slf4j.Logger LOG = LoggerFactory.getLogger(TestLogLevel.class);

  private static final String KDC_SERVER_HOST = "localhost";
  private static String BASEDIR ;
  private static Configuration serverConf;
  private static Configuration clientConf;
  private static Configuration sslConf;
  private static final String logName = TestLogLevel.class.getName();
  private final Logger log = LogManager.getLogger(logName);
  private final static String PRINCIPAL = "loglevel.principal";
  private final static String KEYTAB  = "loglevel.keytab";

  private static SimpleKdcServer kdc;

  private static final String LOCALHOST = "localhost";
  private static final String clientPrincipal = "client/" + LOCALHOST;
  private static String HTTP_PRINCIPAL = "HTTP/" + LOCALHOST;

  private static File KEYTAB_FILE;

  @BeforeClass
  public static void setUp() throws Exception {

    serverConf = new Configuration();
    clientConf = new Configuration();
    HBaseCommonTestingUtility htu = new HBaseCommonTestingUtility(serverConf);

    String classDir = KeyStoreTestUtil.getClasspathDir(TestLogLevel.class);

    BASEDIR = classDir + "/test-dir/" + htu.getRandomUUID();

    System.out.println("dir is:" + BASEDIR);


    File base = new File(BASEDIR);
    FileUtil.fullyDelete(base);
    base.mkdirs();

    KEYTAB_FILE = new File(BASEDIR,"keytab");

    KEYTAB_FILE.getParentFile().mkdirs();

    setupSSL(base, serverConf);

    serverConf.set("hadoop.ssl.hostname.verifier", "ALLOW_ALL");
    serverConf.set("ssl.hostname.verifier", "ALLOW_ALL");
    kdc = setupMiniKdc();
    // Create two principles: a client and an HTTP principal

  }

  /**
   * Sets up {@link SimpleKdcServer} for testing security.
   * Copied from HBaseTestingUtility#setupMiniKdc().
   */
  static private SimpleKdcServer setupMiniKdc() throws Exception {
    Logger log = LogManager.getLogger(logName);
    Properties conf = MiniKdc.createConf();
    conf.put(MiniKdc.DEBUG, true);
    File kdcDir = null;
    // There is time lag between selecting a port and trying to bind with it. It's possible that
    // another service captures the port in between which'll result in BindException.
    boolean bindException;
    int numTries = 0;
    do {
      try {
        bindException = false;
        kdcDir = new File(BASEDIR, "kdc");
        kdc = new SimpleKdcServer();

        if (kdcDir.exists()) {
          deleteRecursively(kdcDir);
        }
        kdcDir.mkdirs();
        kdc.setWorkDir(kdcDir);

        kdc.setKdcHost(KDC_SERVER_HOST);
        int kdcPort = getFreePort();
        kdc.setAllowTcp(true);
        kdc.setAllowUdp(false);
        kdc.setKdcTcpPort(kdcPort);

        LOG.info("Starting KDC server at " + KDC_SERVER_HOST + ":" + kdcPort);

        //kdc.getKdcConfig().setString("default_tkt_enctypes", "AES_128_GCM_SHA256 rsa_pkcs1_sha256 aes256-cts-hmac-sha1-96 des-cbc-md5 des-cbc-crc aes128-cts-hmac-sha1-96 des3-cbc-sha1 arcfour-hmac-md5 camellia256-cts-cmac des-cbc-crc SSL_RSA_WITH_RC4_128_SHA ecdsa_secp256r1_sha256 ecdsa_secp384r1_sha384 ecdsa_secp512r1_sha512 rsa_pss_rsae_sha256, rsa_pss_rsae_sha384 rsa_pss_rsae_sha512 rsa_pss_pss_sha256 rsa_pss_pss_sha384 rsa_pss_pss_sha512 rsa_pkcs1_sha256 rsa_pkcs1_sha384 rsa_pkcs1_sha512 dsa_sha256 ecdsa_sha224 rsa_sha224 dsa_sha224 ecdsa_sha1 rsa_pkcs1_sha1, dsa_sha1");
       // kdc.getKdcConfig().setString("default_tgs_enctypes", "AES_128_GCM_SHA256 rsa_pkcs1_sha256 aes256-cts-hmac-sha1-96 des-cbc-md5 des-cbc-crc aes128-cts-hmac-sha1-96 des3-cbc-sha1 arcfour-hmac-md5 camellia256-cts-cmac des-cbc-crc SSL_RSA_WITH_RC4_128_SHA ecdsa_secp256r1_sha256 ecdsa_secp384r1_sha384 ecdsa_secp512r1_sha512 rsa_pss_rsae_sha256, rsa_pss_rsae_sha384 rsa_pss_rsae_sha512 rsa_pss_pss_sha256 rsa_pss_pss_sha384 rsa_pss_pss_sha512 rsa_pkcs1_sha256 rsa_pkcs1_sha384 rsa_pkcs1_sha512 dsa_sha256 ecdsa_sha224 rsa_sha224 dsa_sha224 ecdsa_sha1 rsa_pkcs1_sha1, dsa_sha1");

        kdc.init();

        kdc.createAndExportPrincipals(KEYTAB_FILE, HTTP_PRINCIPAL, clientPrincipal);


        kdc.start();
      } catch (BindException e) {
       // FileUtils.deleteDirectory(kdcDir);  // clean directory
        numTries++;
        if (numTries == 3) {
          log.error("Failed setting up MiniKDC. Tried " + numTries + " times.");
          throw e;
        }
        log.error("BindException encountered when setting up MiniKdc. Trying again.");
        bindException = true;
      }
    } while (bindException);
    return kdc;
  }

  static private void setupSSL(File base, Configuration conf) throws Exception {
    conf.set(DFSConfigKeys.DFS_HTTP_POLICY_KEY, HttpConfig.Policy.HTTPS_ONLY.name());
    conf.set(DFSConfigKeys.DFS_NAMENODE_HTTPS_ADDRESS_KEY, "localhost:0");
    conf.set(DFSConfigKeys.DFS_DATANODE_HTTPS_ADDRESS_KEY, "localhost:0");


    KeyStoreTestUtil.setupSSLConfig(base.getAbsolutePath(), base.getAbsolutePath(), conf, false);

    sslConf = getSslConfig(conf);
    System.out.println("conf: " + conf.getFinalParameters());
    System.out.println("ssl conf: " + sslConf.getFinalParameters());
  }

  /**
   * Get the SSL configuration.
   * This method is copied from KeyStoreTestUtil#getSslConfig() in Hadoop.
   * @return {@link Configuration} instance with ssl configs loaded.
   */
  private static Configuration getSslConfig(Configuration sslConf ){

    File sslClientConfFile = new File(BASEDIR + "/ssl-client.xml");
    File sslServerConfFile = new File(BASEDIR + "/ssl-server.xml");

    sslConf.addResource(new Path(sslServerConfFile.getAbsolutePath()));
    sslConf.addResource(new Path(sslClientConfFile.getAbsolutePath()));
    sslConf.set("hadoop.ssl.client.conf", "file://" + sslClientConfFile.getAbsolutePath());
    sslConf.set("hadoop.ssl.server.conf", "file://" + sslServerConfFile.getAbsolutePath());
    sslConf.set("ssl.client.conf", "file://" + sslClientConfFile.getAbsolutePath());
    sslConf.set("ssl.server.conf", "file://" + sslServerConfFile.getAbsolutePath());
    return sslConf;
  }

  @AfterClass
  public static void tearDown() throws KrbException {
    if (kdc != null) {
      kdc.stop();
    }

  //  FileUtil.fullyDelete(BASEDIR);
  }

  /**
   * Test client command line options. Does not validate server behavior.
   * @throws Exception if commands return unexpected results.
   */
  @Test
  public void testCommandOptions() throws Exception {
    final String className = this.getClass().getName();

    assertFalse(validateCommand(new String[] {"-foo" }));
    // fail due to insufficient number of arguments
    assertFalse(validateCommand(new String[] {}));
    assertFalse(validateCommand(new String[] {"-getlevel" }));
    assertFalse(validateCommand(new String[] {"-setlevel" }));
    assertFalse(validateCommand(new String[] {"-getlevel", "foo.bar:8080" }));

    // valid command arguments
    assertTrue(validateCommand(
        new String[] {"-getlevel", "foo.bar:8080", className }));
    assertTrue(validateCommand(
        new String[] {"-setlevel", "foo.bar:8080", className, "DEBUG" }));
    assertTrue(validateCommand(
        new String[] {"-getlevel", "foo.bar:8080", className }));
    assertTrue(validateCommand(
        new String[] {"-setlevel", "foo.bar:8080", className, "DEBUG" }));

    // fail due to the extra argument
    assertFalse(validateCommand(
        new String[] {"-getlevel", "foo.bar:8080", className, "blah" }));
    assertFalse(validateCommand(
        new String[] {"-setlevel", "foo.bar:8080", className, "DEBUG", "blah" }));
    assertFalse(validateCommand(
        new String[] {"-getlevel", "foo.bar:8080", className, "-setlevel", "foo.bar:8080",
          className }));
  }

  /**
   * Check to see if a command can be accepted.
   *
   * @param args a String array of arguments
   * @return true if the command can be accepted, false if not.
   */
  private boolean validateCommand(String[] args) {
    CLI cli = new CLI(clientConf);
    try {
      cli.parseArguments(args);
    } catch (HadoopIllegalArgumentException e) {
      return false;
    } catch (Exception e) {
      // this is used to verify the command arguments only.
      // no HadoopIllegalArgumentException = the arguments are good.
      return true;
    }
    return true;
  }

  /**
   * Creates and starts a Jetty server binding at an ephemeral port to run
   * LogLevel servlet.
   * @param protocol "http" or "https"
   * @param isSpnego true if SPNEGO is enabled
   * @return a created HttpServer object
   * @throws Exception if unable to create or start a Jetty server
   */
  private HttpServer createServer(String protocol, boolean isSpnego)
      throws Exception {
    HttpServer.Builder builder = new HttpServer.Builder()
        .setName("..")
        .addEndpoint(new URI(protocol + "://localhost:0"))
        .setFindPort(true)
        .setConf(serverConf);

    if (isSpnego) {
      // Set up server Kerberos credentials.
      // Since the server may fall back to simple authentication,
      // use ACL to make sure the connection is Kerberos/SPNEGO authenticated.
      builder.setSecurityEnabled(true)
          .setUsernameConfKey(PRINCIPAL)
          .setKeytabConfKey(KEYTAB)
          .setACL(new AccessControlList("client"));
    }

    // if using HTTPS, configure keystore/truststore properties.
    if (protocol.equals(LogLevel.PROTOCOL_HTTPS)) {
      builder = builder.
          keyPassword(sslConf.get("ssl.server.keystore.keypassword"))
          .keyStore(sslConf.get("ssl.server.keystore.location"),
              sslConf.get("ssl.server.keystore.password"),
              sslConf.get("ssl.server.keystore.type", "jks"))
          .trustStore(sslConf.get("ssl.server.truststore.location"),
              sslConf.get("ssl.server.truststore.password"),
              sslConf.get("ssl.server.truststore.type", "jks"));
    }
    HttpServer server = builder.build();
    server.start();
    return server;
  }

  private void testDynamicLogLevel(final String bindProtocol, final String connectProtocol,
      final boolean isSpnego)
      throws Exception {
    testDynamicLogLevel(bindProtocol, connectProtocol, isSpnego, Level.DEBUG.toString());
  }

  /**
   * Run both client and server using the given protocol.
   *
   * @param bindProtocol specify either http or https for server
   * @param connectProtocol specify either http or https for client
   * @param isSpnego true if SPNEGO is enabled
   * @throws Exception if client can't accesss server.
   */
  private void testDynamicLogLevel(final String bindProtocol, final String connectProtocol,
      final boolean isSpnego, final String newLevel)
      throws Exception {
    if (!LogLevel.isValidProtocol(bindProtocol)) {
      throw new Exception("Invalid server protocol " + bindProtocol);
    }
    if (!LogLevel.isValidProtocol(connectProtocol)) {
      throw new Exception("Invalid client protocol " + connectProtocol);
    }
    Level oldLevel = log.getEffectiveLevel();
    assertNotEquals("Get default Log Level which shouldn't be ERROR.",
        Level.ERROR, oldLevel);

    // configs needed for SPNEGO at server side
    if (isSpnego) {
      serverConf.set(PRINCIPAL, HTTP_PRINCIPAL);
      serverConf.set(KEYTAB, KEYTAB_FILE.getAbsolutePath());
      serverConf.set(CommonConfigurationKeysPublic.HADOOP_SECURITY_AUTHENTICATION, "kerberos");
      serverConf.setBoolean(CommonConfigurationKeys.HADOOP_SECURITY_AUTHORIZATION, true);
      UserGroupInformation.setConfiguration(serverConf);
    } else {
      serverConf.set(CommonConfigurationKeysPublic.HADOOP_SECURITY_AUTHENTICATION, "simple");
      serverConf.setBoolean(CommonConfigurationKeys.HADOOP_SECURITY_AUTHORIZATION, false);
      UserGroupInformation.setConfiguration(serverConf);
    }

    final HttpServer server = createServer(bindProtocol, isSpnego);
    // get server port
    final String authority = NetUtils.getHostPortString(server.getConnectorAddress(0));

    String keytabFilePath = KEYTAB_FILE.getAbsolutePath();

    UserGroupInformation clientUGI = UserGroupInformation.
        loginUserFromKeytabAndReturnUGI(clientPrincipal, keytabFilePath);
    try {
      clientUGI.doAs((PrivilegedExceptionAction<Void>) () -> {
        // client command line
        getLevel(connectProtocol, authority);
        setLevel(connectProtocol, authority, newLevel);
        return null;
      });
    } finally {
      clientUGI.logoutUserFromKeytab();
      server.stop();
    }

    // restore log level
    GenericTestUtils.setLogLevel(log, oldLevel);
  }

  /**
   * Run LogLevel command line to start a client to get log level of this test
   * class.
   *
   * @param protocol specify either http or https
   * @param authority daemon's web UI address
   * @throws Exception if unable to connect
   */
  private void getLevel(String protocol, String authority) throws Exception {
    String[] getLevelArgs = {"-getlevel", authority, logName, "-protocol", protocol};
    CLI cli = new CLI(clientConf);
    cli.run(getLevelArgs);
  }

  /**
   * Run LogLevel command line to start a client to set log level of this test
   * class to debug.
   *
   * @param protocol specify either http or https
   * @param authority daemon's web UI address
   * @throws Exception if unable to run or log level does not change as expected
   */
  private void setLevel(String protocol, String authority, String newLevel)
      throws Exception {
    String[] setLevelArgs = {"-setlevel", authority, logName, newLevel, "-protocol", protocol};
    CLI cli = new CLI(clientConf);
    cli.run(setLevelArgs);

    assertEquals("new level not equal to expected: ", newLevel.toUpperCase(),
        log.getEffectiveLevel().toString());
  }

  /**
   * Test setting log level to "Info".
   *
   * @throws Exception if client can't set log level to INFO.
   */
  @Test
  public void testInfoLogLevel() throws Exception {
    testDynamicLogLevel(LogLevel.PROTOCOL_HTTP, LogLevel.PROTOCOL_HTTP, true, "INFO");
  }

  /**
   * Test setting log level to "Error".
   *
   * @throws Exception if client can't set log level to ERROR.
   */
  @Test
  public void testErrorLogLevel() throws Exception {
    testDynamicLogLevel(LogLevel.PROTOCOL_HTTP, LogLevel.PROTOCOL_HTTP, true, "ERROR");
  }

  /**
   * Server runs HTTP, no SPNEGO.
   *
   * @throws Exception if http client can't access http server,
   *   or http client can access https server.
   */
  @Test
  public void testLogLevelByHttp() throws Exception {
    testDynamicLogLevel(LogLevel.PROTOCOL_HTTP, LogLevel.PROTOCOL_HTTP, false);
    try {
      testDynamicLogLevel(LogLevel.PROTOCOL_HTTP, LogLevel.PROTOCOL_HTTPS,
          false);
      fail("An HTTPS Client should not have succeeded in connecting to a " +
          "HTTP server");
    } catch (SSLException e) {
      exceptionShouldContains("Unrecognized SSL message", e);
    }
  }

  /**
   * Server runs HTTP + SPNEGO.
   *
   * @throws Exception if http client can't access http server,
   *   or http client can access https server.
   */
  @Test
  public void testLogLevelByHttpWithSpnego() throws Exception {
    testDynamicLogLevel(LogLevel.PROTOCOL_HTTP, LogLevel.PROTOCOL_HTTP, true);
    try {
      testDynamicLogLevel(LogLevel.PROTOCOL_HTTP, LogLevel.PROTOCOL_HTTPS,
          true);
      fail("An HTTPS Client should not have succeeded in connecting to a " +
          "HTTP server");
    } catch (SSLException e) {
      exceptionShouldContains("Unrecognized SSL message", e);
    }
  }

  /**
   * Server runs HTTPS, no SPNEGO.
   *
   * @throws Exception if https client can't access https server,
   *   or https client can access http server.
   */
  @Test
  public void testLogLevelByHttps() throws Exception {
    testDynamicLogLevel(LogLevel.PROTOCOL_HTTPS, LogLevel.PROTOCOL_HTTPS,
        false);
    try {
      testDynamicLogLevel(LogLevel.PROTOCOL_HTTPS, LogLevel.PROTOCOL_HTTP,
          false);
      fail("An HTTP Client should not have succeeded in connecting to a " +
          "HTTPS server");
    } catch (SocketException e) {
      exceptionShouldContains("Unexpected end of file from server", e);
    }
  }

  /**
   * Server runs HTTPS + SPNEGO.
   *
   * @throws Exception if https client can't access https server,
   *   or https client can access http server.
   */
  @Test
  public void testLogLevelByHttpsWithSpnego() throws Exception {
    testDynamicLogLevel(LogLevel.PROTOCOL_HTTPS, LogLevel.PROTOCOL_HTTPS,
        true);
    try {
      testDynamicLogLevel(LogLevel.PROTOCOL_HTTPS, LogLevel.PROTOCOL_HTTP,
          true);
      fail("An HTTP Client should not have succeeded in connecting to a " +
          "HTTPS server");
    }  catch (SocketException e) {
      exceptionShouldContains("Unexpected end of file from server", e);
    }
  }

  /**
   * Assert that a throwable or one of its causes should contain the substr in its message.
   *
   * Ideally we should use {@link GenericTestUtils#assertExceptionContains(String, Throwable)} util
   * method which asserts t.toString() contains the substr. As the original throwable may have been
   * wrapped in Hadoop3 because of HADOOP-12897, it's required to check all the wrapped causes.
   * After stop supporting Hadoop2, this method can be removed and assertion in tests can use
   * t.getCause() directly, similar to HADOOP-15280.
   */
  private static void exceptionShouldContains(String substr, Throwable throwable) {
    substr = substr.toLowerCase(Locale.ROOT);
    Throwable t = throwable;
    while (t != null) {
      String msg = t.toString().toLowerCase(Locale.ROOT);
      if (msg != null && msg.contains(substr)) {
        return;
      }
      t = t.getCause();
    }
    throw new AssertionError("Expected to find '" + substr + "' but got unexpected exception:" +
        StringUtils.stringifyException(throwable), throwable);
  }

  /**
   * Recursively deletes a {@link File}.
   */
  protected static void deleteRecursively(File d) {
    if (d.isDirectory()) {
      for (String name : d.list()) {
        File child = new File(d, name);
        if (child.isFile()) {
          child.delete();
        } else {
          deleteRecursively(child);
        }
      }
    }
    d.delete();
  }

  protected static int getFreePort() throws IOException {
    ServerSocket s = new ServerSocket(0);
    try {
      s.setReuseAddress(true);
      int port = s.getLocalPort();
      return port;
    } finally {
      if (null != s) {
        s.close();
      }
    }
  }
}
