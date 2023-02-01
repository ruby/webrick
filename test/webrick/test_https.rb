# frozen_string_literal: false
require "test/unit"
require "net/http"
require "webrick"
require "webrick/https"
require "webrick/utils"
require_relative "utils"

class TestWEBrickHTTPS < Test::Unit::TestCase
  empty_log = Object.new
  def empty_log.<<(str)
    assert_equal('', str)
    self
  end
  NoLog = WEBrick::Log.new(empty_log, WEBrick::BasicLog::WARN)

  class HTTPSNITest < ::Net::HTTP
    attr_accessor :sni_hostname

    def ssl_socket_connect(s, timeout)
      s.hostname = sni_hostname
      super
    end
  end

  def teardown
    WEBrick::Utils::TimeoutHandler.terminate
    super
  end

  def https_get(addr, port, hostname, path, verifyname = nil)
    subject = nil
    http = HTTPSNITest.new(addr, port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    http.verify_callback = proc { |x, store| subject = store.chain[0].subject.to_s; x }
    http.sni_hostname = hostname
    req = Net::HTTP::Get.new(path)
    req["Host"] = "#{hostname}:#{port}"
    response = http.start { http.request(req).body }
    assert_equal("/CN=#{verifyname || hostname}", subject)
    response
  end

  def test_sni
    config = {
      :ServerName => "localhost",
      :SSLEnable => true,
      :SSLCertName => "/CN=localhost",
    }
    TestWEBrick.start_httpserver(config){|server, addr, port, log|
      server.mount_proc("/") {|req, res| res.body = "master" }

      # catch stderr in create_self_signed_cert
      stderr_buffer = StringIO.new
      old_stderr, $stderr = $stderr, stderr_buffer

      begin
        vhost_config1 = {
          :ServerName => "vhost1",
          :Port => port,
          :DoNotListen => true,
          :Logger => NoLog,
          :AccessLog => [],
          :SSLEnable => true,
          :SSLCertName => "/CN=vhost1",
        }
        vhost1 = WEBrick::HTTPServer.new(vhost_config1)
        vhost1.mount_proc("/") {|req, res| res.body = "vhost1" }
        server.virtual_host(vhost1)

        vhost_config2 = {
          :ServerName => "vhost2",
          :ServerAlias => ["vhost2alias"],
          :Port => port,
          :DoNotListen => true,
          :Logger => NoLog,
          :AccessLog => [],
          :SSLEnable => true,
          :SSLCertName => "/CN=vhost2",
        }
        vhost2 = WEBrick::HTTPServer.new(vhost_config2)
        vhost2.mount_proc("/") {|req, res| res.body = "vhost2" }
        server.virtual_host(vhost2)
      ensure
        # restore stderr
        $stderr = old_stderr
      end

      assert_match(/\A([.+*]+\n)+\z/, stderr_buffer.string)
      assert_equal("master", https_get(addr, port, "localhost", "/localhost"))
      assert_equal("master", https_get(addr, port, "unknown", "/unknown", "localhost"))
      assert_equal("vhost1", https_get(addr, port, "vhost1", "/vhost1"))
      assert_equal("vhost2", https_get(addr, port, "vhost2", "/vhost2"))
      assert_equal("vhost2", https_get(addr, port, "vhost2alias", "/vhost2alias", "vhost2"))
    }
  end

  def test_check_ssl_virtual
    config = {
      :ServerName => "localhost",
      :SSLEnable => true,
      :SSLCertName => "/CN=localhost",
    }
    TestWEBrick.start_httpserver(config){|server, addr, port, log|
      assert_raise ArgumentError do
        vhost = WEBrick::HTTPServer.new({:DoNotListen => true, :Logger => NoLog})
        server.virtual_host(vhost)
      end
    }
  end

  def test_ssl_meta_vars
    # CA cert
    ca_cert, ca_key = WEBrick::Utils.create_self_signed_cert(2048, "/CN=ca", "is CA")
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = ca_cert
    ef.issuer_certificate = ca_cert
    ca_cert.extensions = [
      ef.create_extension("basicConstraints", "CA:TRUE", true),
      ef.create_extension("keyUsage", "keyCertSign, cRLSign", true),
      ef.create_extension("subjectKeyIdentifier", "hash", false)
    ]
    ca_cert.add_extension ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always")
    ca_cert.sign(ca_key, "SHA256")

    # Client cert
    client_cert, client_key = WEBrick::Utils.create_self_signed_cert(2048, "/CN=client", "is client")
    client_cert.issuer = ca_cert.issuer
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = client_cert
    ef.issuer_certificate = ca_cert
    client_cert.extensions = [
      ef.create_extension("basicConstraints", "CA:FALSE", true),
      ef.create_extension("keyUsage", "digitalSignature", true),
      ef.create_extension("subjectKeyIdentifier", "hash", false),
      ef.create_extension("subjectAltName", "DNS:localhost,IP:127.0.0.1", false)
    ]
    client_cert.sign(ca_key, "SHA256")


    # Server cert
    server_cert, server_key = WEBrick::Utils.create_self_signed_cert(2048, "/CN=server", "is server")
    server_cert.issuer = ca_cert.issuer
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = server_cert
    ef.issuer_certificate = ca_cert
    server_cert.extensions = [
      ef.create_extension("basicConstraints", "CA:FALSE", true),
      ef.create_extension("keyUsage", "digitalSignature", true),
      ef.create_extension("subjectKeyIdentifier", "hash", false),
      ef.create_extension("subjectAltName", "DNS:localhost,IP:127.0.0.1", false)
    ]
    server_cert.sign(ca_key, "SHA256")

    # Client CA Store
    ca_client_store = OpenSSL::X509::Store.new
    ca_client_store.add_cert(ca_cert)
    ca_client_store.add_cert(client_cert)

    # Server CA Store
    server_ca_store = OpenSSL::X509::Store.new
    server_ca_store.add_cert(ca_cert)
    server_ca_store.add_cert(server_cert)

    config = {
      SSLEnable: true,
      :SSLCertName => "/CN=localhost",
      SSLCertificate: server_cert,
      SSLPrivateKey: server_key,
      SSLVerifyClient: OpenSSL::SSL::VERIFY_PEER,
      SSLCertificateStore: ca_client_store
    }
    TestWEBrick.start_httpserver(config){|server, addr, port, log|
      env = nil
      server.mount_proc("/") {|req, res|
        env = req.meta_vars
        res.body = "OK"
      }

      subject = nil
      http = Net::HTTP.new(addr, port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_CLIENT_ONCE
      http.cert = client_cert
      http.key = client_key
      http.extra_chain_cert = [ca_cert]
      http.cert_store = server_ca_store
      req = Net::HTTP::Get.new("/")
      body = http.request(req).body
      assert_not_nil(env)
      assert_equal("SUCCESS", env["SSL_CLIENT_VERIFY"])
      assert_equal("/CN=client", env["SSL_CLIENT_S_DN"])
      assert_equal(client_cert.to_pem, env["SSL_CLIENT_CERT"])
    }
  end
end
