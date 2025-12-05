# frozen_string_literal: false
require "webrick"
require "stringio"
require "test/unit"

class TestWEBrickHTTPRequest < Test::Unit::TestCase
  def teardown
    WEBrick::Utils::TimeoutHandler.terminate
    super
  end

  def test_simple_request
    msg = <<~HTTP.gsub("\n", "\r\n")
      GET /
    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    assert(req.meta_vars) # fails if @header was not initialized and iteration is attempted on the nil reference
  end

  def test_parse_09
    msg = <<~HTTP.gsub("\n", "\r\n")
      GET /
      foobar    # HTTP/0.9 request don't have header nor entity body.
    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    assert_equal("GET", req.request_method)
    assert_equal("/", req.unparsed_uri)
    assert_equal(WEBrick::HTTPVersion.new("0.9"), req.http_version)
    assert_equal(WEBrick::Config::HTTP[:ServerName], req.host)
    assert_equal(80, req.port)
    assert_equal(false, req.keep_alive?)
    assert_equal(nil, req.body)
    assert(req.query.empty?)
  end

  def test_parse_10
    msg = <<~HTTP.gsub("\n", "\r\n")
      GET / HTTP/1.0

    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    assert_equal("GET", req.request_method)
    assert_equal("/", req.unparsed_uri)
    assert_equal(WEBrick::HTTPVersion.new("1.0"), req.http_version)
    assert_equal(WEBrick::Config::HTTP[:ServerName], req.host)
    assert_equal(80, req.port)
    assert_equal(false, req.keep_alive?)
    assert_equal(nil, req.body)
    assert(req.query.empty?)
  end

  def test_parse_11
    msg = <<~HTTP.gsub("\n", "\r\n")
      GET /path HTTP/1.1

    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    assert_equal("GET", req.request_method)
    assert_equal("/path", req.unparsed_uri)
    assert_equal("", req.script_name)
    assert_equal("/path", req.path_info)
    assert_equal(WEBrick::HTTPVersion.new("1.1"), req.http_version)
    assert_equal(WEBrick::Config::HTTP[:ServerName], req.host)
    assert_equal(80, req.port)
    assert_equal(true, req.keep_alive?)
    assert_equal(nil, req.body)
    assert(req.query.empty?)
  end

  def test_request_uri_too_large
    msg = <<~HTTP.gsub("\n", "\r\n")
      GET /#{"a"*2084} HTTP/1.1
    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    assert_raise(WEBrick::HTTPStatus::RequestURITooLarge){
      req.parse(StringIO.new(msg))
    }
  end

  def test_invalid_content_length_header
    ['', ' ', ' +1', ' -1', ' a'].each do |cl|
      msg = <<~HTTP.gsub("\n", "\r\n")
        GET / HTTP/1.1
        Content-Length:#{cl}

      HTTP
      req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
      assert_raise(WEBrick::HTTPStatus::BadRequest){
        req.parse(StringIO.new(msg))
      }
    end
  end

  def test_bare_lf_request_line
    msg = <<~HTTP.gsub("\n", "\r\n")
      GET / HTTP/1.1
      Content-Length: 0\r
      \r
    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    assert_raise(WEBrick::HTTPStatus::EOFError){
      req.parse(StringIO.new(msg))
    }
  end

  def test_bare_lf_header
    msg = <<~HTTP.gsub("\n", "\r\n")
      GET / HTTP/1.1\r
      Content-Length: 0
      \r
    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    assert_raise(WEBrick::HTTPStatus::BadRequest){
      req.parse(StringIO.new(msg))
    }
  end

  def test_header_vt_ff_whitespace
    msg = <<~HTTP
      GET / HTTP/1.1\r
      Foo: \x0b1\x0c\r
      \r
    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    assert_equal("\x0b1\x0c", req["Foo"])

    msg = <<~HTTP
      GET / HTTP/1.1\r
      Foo: \x0b1\x0c\r
       \x0b2\x0c\r
      \r
    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    assert_equal("\x0b1\x0c \x0b2\x0c", req["Foo"])
  end

  def test_bare_cr_request_line
    msg = <<~HTTP.gsub("\n", "\r\n")
      GET / HTTP/1.1\r\r
      Content-Length: 0\r
      \r
    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    assert_raise(WEBrick::HTTPStatus::BadRequest){
      req.parse(StringIO.new(msg))
    }
  end

  def test_bare_cr_header
    msg = <<~HTTP.gsub("\n", "\r\n")
      GET / HTTP/1.1\r
      Content-Type: foo\rbar\r
      \r
    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    assert_raise(WEBrick::HTTPStatus::BadRequest){
      req.parse(StringIO.new(msg))
    }
  end

  def test_invalid_request_lines
    msg = <<~HTTP.gsub("\n", "\r\n")
      GET  / HTTP/1.1\r
      Content-Length: 0\r
      \r
    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    assert_raise(WEBrick::HTTPStatus::BadRequest){
      req.parse(StringIO.new(msg))
    }

    msg = <<~HTTP.gsub("\n", "\r\n")
      GET /  HTTP/1.1\r
      Content-Length: 0\r
      \r
    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    assert_raise(WEBrick::HTTPStatus::BadRequest){
      req.parse(StringIO.new(msg))
    }

    msg = <<~HTTP.gsub("\n", "\r\n")
      GET /\r HTTP/1.1\r
      Content-Length: 0\r
      \r
    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    assert_raise(WEBrick::HTTPStatus::BadRequest){
      req.parse(StringIO.new(msg))
    }

    msg = <<~HTTP.gsub("\n", "\r\n")
      GET / HTTP/1.1 \r
      Content-Length: 0\r
      \r
    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    assert_raise(WEBrick::HTTPStatus::BadRequest){
      req.parse(StringIO.new(msg))
    }
  end

  def test_duplicate_content_length_header
    msg = <<~HTTP.gsub("\n", "\r\n")
      GET / HTTP/1.1
      Content-Length: 1
      Content-Length: 2

    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    assert_raise(WEBrick::HTTPStatus::BadRequest){
      req.parse(StringIO.new(msg))
    }
  end

  def test_content_length_and_transfer_encoding_headers_smuggling
    msg = <<~HTTP.gsub("\n", "\r\n")
      POST /user HTTP/1.1
      Content-Length: 28
      Transfer-Encoding: chunked

      0

      GET /admin HTTP/1.1

    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    assert_raise(WEBrick::HTTPStatus::BadRequest){
      req.body
    }
  end

  def test_parse_headers
    msg = <<~HTTP.gsub("\n", "\r\n")
      GET /path HTTP/1.1
      Host: test.ruby-lang.org:8080
      Connection: close
      Accept: text/*;q=0.3, text/html;q=0.7, text/html;level=1,
              text/html;level=2;q=0.4, */*;q=0.5
      Accept-Encoding: compress;q=0.5
      Accept-Encoding: gzip;q=1.0, identity; q=0.4, *;q=0
      Accept-Language: en;q=0.5, *; q=0
      Accept-Language: ja
      Content-Type: text/plain
      Content-Length: 8
      X-Empty-Header:

      foobar
    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    assert_equal(
      URI.parse("http://test.ruby-lang.org:8080/path"), req.request_uri)
    assert_equal("test.ruby-lang.org", req.host)
    assert_equal(8080, req.port)
    assert_equal(false, req.keep_alive?)
    assert_equal(
      %w(text/html;level=1 text/html */* text/html;level=2 text/*),
      req.accept)
    assert_equal(%w(gzip compress identity *), req.accept_encoding)
    assert_equal(%w(ja en *), req.accept_language)
    assert_equal(8, req.content_length)
    assert_equal("text/plain", req.content_type)
    assert_equal("foobar\r\n", req.body)
    assert_equal("", req["x-empty-header"])
    assert_equal(nil, req["x-no-header"])
    assert(req.query.empty?)
  end

  def test_parse_header2()
    msg = <<~HTTP.gsub("\n", "\r\n")
      POST /foo/bar/../baz?q=a HTTP/1.0
      Content-Length: 10
      User-Agent:
        FOO   BAR
        BAZ

      hogehoge
    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    assert_equal("POST", req.request_method)
    assert_equal("/foo/baz", req.path)
    assert_equal("", req.script_name)
    assert_equal("/foo/baz", req.path_info)
    assert_equal("10", req['content-length'])
    assert_equal("FOO   BAR BAZ", req['user-agent'])
    assert_equal("hogehoge\r\n", req.body)
  end

  def test_parse_headers3
    msg = <<~HTTP.gsub("\n", "\r\n")
      GET /path HTTP/1.1
      Host: test.ruby-lang.org

    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    assert_equal(URI.parse("http://test.ruby-lang.org/path"), req.request_uri)
    assert_equal("test.ruby-lang.org", req.host)
    assert_equal(80, req.port)

    msg = <<~HTTP.gsub("\n", "\r\n")
      GET /path HTTP/1.1
      Host: 192.168.1.1

    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    assert_equal(URI.parse("http://192.168.1.1/path"), req.request_uri)
    assert_equal("192.168.1.1", req.host)
    assert_equal(80, req.port)

    msg = <<~HTTP.gsub("\n", "\r\n")
      GET /path HTTP/1.1
      Host: [fe80::208:dff:feef:98c7]

    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    assert_equal(URI.parse("http://[fe80::208:dff:feef:98c7]/path"),
                 req.request_uri)
    assert_equal("[fe80::208:dff:feef:98c7]", req.host)
    assert_equal(80, req.port)

    msg = <<~HTTP.gsub("\n", "\r\n")
      GET /path HTTP/1.1
      Host: 192.168.1.1:8080

    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    assert_equal(URI.parse("http://192.168.1.1:8080/path"), req.request_uri)
    assert_equal("192.168.1.1", req.host)
    assert_equal(8080, req.port)

    msg = <<~HTTP.gsub("\n", "\r\n")
      GET /path HTTP/1.1
      Host: [fe80::208:dff:feef:98c7]:8080

    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    assert_equal(URI.parse("http://[fe80::208:dff:feef:98c7]:8080/path"),
                 req.request_uri)
    assert_equal("[fe80::208:dff:feef:98c7]", req.host)
    assert_equal(8080, req.port)
  end

  def test_parse_get_params
    param = "foo=1;foo=2;foo=3;bar=x"
    msg = <<~HTTP.gsub("\n", "\r\n")
      GET /path?#{param} HTTP/1.1
      Host: test.ruby-lang.org:8080

    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    query = req.query
    assert_equal("1", query["foo"])
    assert_equal(["1", "2", "3"], query["foo"].to_ary)
    assert_equal(["1", "2", "3"], query["foo"].list)
    assert_equal("x", query["bar"])
    assert_equal(["x"], query["bar"].list)
  end

  def test_parse_post_params
    param = "foo=1;foo=2;foo=3;bar=x"
    msg = <<~HTTP.gsub("\n", "\r\n")
      POST /path?foo=x;foo=y;foo=z;bar=1 HTTP/1.1
      Host: test.ruby-lang.org:8080
      Content-Length: #{param.size}
      Content-Type: application/x-www-form-urlencoded

      #{param}
    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    query = req.query
    assert_equal("1", query["foo"])
    assert_equal(["1", "2", "3"], query["foo"].to_ary)
    assert_equal(["1", "2", "3"], query["foo"].list)
    assert_equal("x", query["bar"])
    assert_equal(["x"], query["bar"].list)
  end

  def test_chunked
    crlf = "\x0d\x0a"
    expect = File.binread(__FILE__).freeze
    msg = <<~HTTP.gsub("\n", "\r\n")
      POST /path HTTP/1.1
      Host: test.ruby-lang.org:8080
      Transfer-Encoding: chunked

    HTTP
    File.open(__FILE__){|io|
      while chunk = io.read(100)
        msg << chunk.size.to_s(16) << crlf
        msg << chunk << crlf
      end
    }
    msg << "0" << crlf
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    assert_equal(expect, req.body)

    # chunked req.body_reader
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    dst = StringIO.new
    IO.copy_stream(req.body_reader, dst)
    assert_equal(expect, dst.string)
  end

  def test_bad_chunked
    msg = <<~HTTP
      POST /path HTTP/1.1\r
      Transfer-Encoding: chunked\r
      \r
      01x1\r
      \r
      1
    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    assert_raise(WEBrick::HTTPStatus::BadRequest){ req.body }

    # chunked req.body_reader
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    dst = StringIO.new
    assert_raise(WEBrick::HTTPStatus::BadRequest) do
      IO.copy_stream(req.body_reader, dst)
    end
  end

  def test_bad_chunked_extra_data
    msg = <<~HTTP
      POST /path HTTP/1.1\r
      Transfer-Encoding: chunked\r
      \r
      3\r
      ABCthis-all-gets-ignored\r
      0\r
      \r
    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    assert_raise(WEBrick::HTTPStatus::BadRequest){ req.body }

    # chunked req.body_reader
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    dst = StringIO.new
    assert_raise(WEBrick::HTTPStatus::BadRequest) do
      IO.copy_stream(req.body_reader, dst)
    end
  end

  def test_null_byte_in_header
    msg = <<~HTTP.gsub("\n", "\r\n")
      POST /path HTTP/1.1\r
      Evil: evil\x00\r
      \r
    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    assert_raise(WEBrick::HTTPStatus::BadRequest){ req.parse(StringIO.new(msg)) }
  end

  def test_forwarded
    msg = <<~HTTP.gsub("\n", "\r\n")
      GET /foo HTTP/1.1
      Host: localhost:10080
      User-Agent: w3m/0.5.2
      X-Forwarded-For: 123.123.123.123
      X-Forwarded-Host: forward.example.com
      X-Forwarded-Server: server.example.com
      Connection: Keep-Alive

    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    assert_equal("server.example.com", req.server_name)
    assert_equal("http://forward.example.com/foo", req.request_uri.to_s)
    assert_equal("forward.example.com", req.host)
    assert_equal(80, req.port)
    assert_equal("123.123.123.123", req.remote_ip)
    assert(!req.ssl?)

    msg = <<~HTTP.gsub("\n", "\r\n")
      GET /foo HTTP/1.1
      Host: localhost:10080
      User-Agent: w3m/0.5.2
      X-Forwarded-For: 192.168.1.10, 172.16.1.1, 123.123.123.123
      X-Forwarded-Host: forward.example.com:8080
      X-Forwarded-Server: server.example.com
      Connection: Keep-Alive

    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    assert_equal("server.example.com", req.server_name)
    assert_equal("http://forward.example.com:8080/foo", req.request_uri.to_s)
    assert_equal("forward.example.com", req.host)
    assert_equal(8080, req.port)
    assert_equal("123.123.123.123", req.remote_ip)
    assert(!req.ssl?)

    msg = <<~HTTP.gsub("\n", "\r\n")
      GET /foo HTTP/1.1
      Host: localhost:10080
      Client-IP: 234.234.234.234
      X-Forwarded-Proto: https, http
      X-Forwarded-For: 192.168.1.10, 10.0.0.1, 123.123.123.123
      X-Forwarded-Host: forward.example.com
      X-Forwarded-Server: server.example.com
      X-Requested-With: XMLHttpRequest
      Connection: Keep-Alive

    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    assert_equal("server.example.com", req.server_name)
    assert_equal("https://forward.example.com/foo", req.request_uri.to_s)
    assert_equal("forward.example.com", req.host)
    assert_equal(443, req.port)
    assert_equal("234.234.234.234", req.remote_ip)
    assert(req.ssl?)

    msg = <<~HTTP.gsub("\n", "\r\n")
      GET /foo HTTP/1.1
      Host: localhost:10080
      Client-IP: 234.234.234.234
      X-Forwarded-Proto: https
      X-Forwarded-For: 192.168.1.10
      X-Forwarded-Host: forward1.example.com:1234, forward2.example.com:5678
      X-Forwarded-Server: server1.example.com, server2.example.com
      X-Requested-With: XMLHttpRequest
      Connection: Keep-Alive

    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    assert_equal("server1.example.com", req.server_name)
    assert_equal("https://forward1.example.com:1234/foo", req.request_uri.to_s)
    assert_equal("forward1.example.com", req.host)
    assert_equal(1234, req.port)
    assert_equal("234.234.234.234", req.remote_ip)
    assert(req.ssl?)

    msg = <<~HTTP.gsub("\n", "\r\n")
      GET /foo HTTP/1.1
      Host: localhost:10080
      Client-IP: 234.234.234.234
      X-Forwarded-Proto: https
      X-Forwarded-For: 192.168.1.10
      X-Forwarded-Host: [fd20:8b1e:b255:8154:250:56ff:fea8:4d84], forward2.example.com:5678
      X-Forwarded-Server: server1.example.com, server2.example.com
      X-Requested-With: XMLHttpRequest
      Connection: Keep-Alive

    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    assert_equal("server1.example.com", req.server_name)
    assert_equal("https://[fd20:8b1e:b255:8154:250:56ff:fea8:4d84]/foo", req.request_uri.to_s)
    assert_equal("[fd20:8b1e:b255:8154:250:56ff:fea8:4d84]", req.host)
    assert_equal(443, req.port)
    assert_equal("234.234.234.234", req.remote_ip)
    assert(req.ssl?)

    msg = <<~HTTP.gsub("\n", "\r\n")
      GET /foo HTTP/1.1
      Host: localhost:10080
      Client-IP: 234.234.234.234
      X-Forwarded-Proto: https
      X-Forwarded-For: 192.168.1.10
      X-Forwarded-Host: [fd20:8b1e:b255:8154:250:56ff:fea8:4d84]:1234, forward2.example.com:5678
      X-Forwarded-Server: server1.example.com, server2.example.com
      X-Requested-With: XMLHttpRequest
      Connection: Keep-Alive

    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    assert_equal("server1.example.com", req.server_name)
    assert_equal("https://[fd20:8b1e:b255:8154:250:56ff:fea8:4d84]:1234/foo", req.request_uri.to_s)
    assert_equal("[fd20:8b1e:b255:8154:250:56ff:fea8:4d84]", req.host)
    assert_equal(1234, req.port)
    assert_equal("234.234.234.234", req.remote_ip)
    assert(req.ssl?)
  end

  def test_continue_sent
    msg = <<~HTTP.gsub("\n", "\r\n")
      POST /path HTTP/1.1
      Expect: 100-continue

    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    assert req['expect']
    l = msg.size
    req.continue
    assert_not_equal l, msg.size
    assert_match(/HTTP\/1.1 100 continue\r\n\r\n\z/, msg)
    assert !req['expect']
  end

  def test_continue_not_sent
    msg = <<~HTTP.gsub("\n", "\r\n")
      POST /path HTTP/1.1

    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    assert !req['expect']
    l = msg.size
    req.continue
    assert_equal l, msg.size
  end

  def test_bad_messages
    param = "foo=1;foo=2;foo=3;bar=x"
    msg = <<~HTTP.gsub("\n", "\r\n")
      POST /path?foo=x;foo=y;foo=z;bar=1 HTTP/1.1
      Host: test.ruby-lang.org:8080
      Content-Type: application/x-www-form-urlencoded

      #{param}
    HTTP
    assert_raise(WEBrick::HTTPStatus::LengthRequired){
      req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
      req.parse(StringIO.new(msg))
      req.body
    }

    msg = <<~HTTP.gsub("\n", "\r\n")
      POST /path?foo=x;foo=y;foo=z;bar=1 HTTP/1.1
      Host: test.ruby-lang.org:8080
      Content-Length: 100000

      body is too short.
    HTTP
    assert_raise(WEBrick::HTTPStatus::BadRequest){
      req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
      req.parse(StringIO.new(msg))
      req.body
    }

    msg = <<~HTTP.gsub("\n", "\r\n")
      POST /path?foo=x;foo=y;foo=z;bar=1 HTTP/1.1
      Host: test.ruby-lang.org:8080
      Transfer-Encoding: foobar

      body is too short.
    HTTP
    assert_raise(WEBrick::HTTPStatus::NotImplemented){
      req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
      req.parse(StringIO.new(msg))
      req.body
    }
  end

  def test_eof_raised_when_line_is_nil
    assert_raise(WEBrick::HTTPStatus::EOFError) {
      req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
      req.parse(StringIO.new(""))
    }
  end

  def test_eof_raised_with_missing_line_between_headers_and_body
    msg = <<~HTTP.gsub("\n", "\r\n")
      GET / HTTP/1.0
    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    assert_raise(WEBrick::HTTPStatus::EOFError) {
      req.parse(StringIO.new(msg))
    }

    msg = <<~HTTP.gsub("\n", "\r\n")
      GET / HTTP/1.0
      Foo: 1
    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    assert_raise(WEBrick::HTTPStatus::EOFError) {
      req.parse(StringIO.new(msg))
    }
  end

  def test_cookie_join
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new("GET / HTTP/1.1\r\ncookie: a=1\r\ncookie: b=2\r\n\r\n"))
    assert_equal 2, req.cookies.length
    assert_equal 'a=1; b=2', req['cookie']
  end

  def test_options_asterisk
    # Test that OPTIONS * requests properly extract host and port from Host header
    msg = <<~HTTP.gsub("\n", "\r\n")
      OPTIONS * HTTP/1.1
      Host: test.ruby-lang.org:8080

    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    assert_equal("OPTIONS", req.request_method)
    assert_equal("*", req.unparsed_uri)
    assert_equal("test.ruby-lang.org", req.host)
    assert_equal(8080, req.port)

    # Verify meta_vars includes correct SERVER_NAME and SERVER_PORT
    meta = req.meta_vars
    assert_equal("test.ruby-lang.org", meta["SERVER_NAME"])
    assert_equal("8080", meta["SERVER_PORT"])
  end

  def test_options_asterisk_default_port
    # Test OPTIONS * with Host header without explicit port
    msg = <<~HTTP.gsub("\n", "\r\n")
      OPTIONS * HTTP/1.1
      Host: test.ruby-lang.org

    HTTP
    req = WEBrick::HTTPRequest.new(WEBrick::Config::HTTP)
    req.parse(StringIO.new(msg))
    assert_equal("OPTIONS", req.request_method)
    assert_equal("*", req.unparsed_uri)
    assert_equal("test.ruby-lang.org", req.host)
    assert_nil(req.port) # Port is nil when not specified

    meta = req.meta_vars
    assert_equal("test.ruby-lang.org", meta["SERVER_NAME"])
  end
end
