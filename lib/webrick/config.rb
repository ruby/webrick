#
# config.rb -- Default configurations.
#
# Author: IPR -- Internet Programming with Ruby -- writers
# Copyright (c) 2000, 2001 TAKAHASHI Masayoshi, GOTOU Yuuzou
# Copyright (c) 2003 Internet Programming with Ruby writers. All rights
# reserved.
#
# $IPR: config.rb,v 1.52 2003/07/22 19:20:42 gotoyuzo Exp $

require 'webrick/version'
require 'webrick/httpversion'
require 'webrick/httputils'
require 'webrick/utils'
require 'webrick/log'

module WEBrick
  module Config
    LIBDIR = File::dirname(__FILE__)

    # for GenericServer
    General = {
      :ServerName     => Utils::getservername,
      :BindAddress    => nil,   # "0.0.0.0" or "::" or nil
      :Port           => nil,   # users MUST specifiy this!!
      :MaxClients     => 100,   # maximum number of the concurrent connections
      :ServerType     => nil,   # default: WEBrick::SimpleServer
      :Logger         => nil,   # default: WEBrick::Log.new
      :ServerSoftware => "WEBrick/#{WEBrick::VERSION} " +
                         "(Ruby/#{RUBY_VERSION}/#{RUBY_RELEASE_DATE})",
      :TempDir        => ENV['TMPDIR']||ENV['TMP']||ENV['TEMP']||'/tmp',
      :DoNotListen    => false,
      :StartCallback  => nil,
      :StopCallback   => nil,
      :AcceptCallback => nil,
    }

    # for HTTPServer, HTTPRequest, HTTPResponse ...
    HTTP = General.dup.update(
      :Port           => 80,
      :RequestTimeout => 30,
      :HTTPVersion    => HTTPVersion.new("1.1"),
      :AccessLog      => nil,
      :MimeTypes      => HTTPUtils::DefaultMimeTypes,
      :DirectoryIndex => ["index.html","index.htm","index.cgi","index.rhtml"],
      :DocumentRoot   => nil,
      :DocumentRootOptions => { :FancyIndexing => true },

      :RequestHandler => nil,
      :ProxyAuthProc  => nil,
      :ProxyContentHandler => nil,
      :ProxyVia       => true,
      :ProxyTimeout   => true,

      # upstream proxy server
      :ProxyURI       => nil,

      :CGIInterpreter => nil,
      :CGIPathEnv     => nil,

      # workaround: if Request-URIs contain 8bit chars,
      # they should be escaped before calling of URI::parse().
      :Escape8bitURI  => false
    )

    FileHandler = {
      :NondisclosureName => ".ht*",
      :FancyIndexing     => false,
      :HandlerTable      => {},
      :HandlerCallback   => nil,
      :DirectoryCallback => nil,
      :FileCallback      => nil,
      :UserDir           => "public_html",
    }

    BasicAuth = {
      :AutoReloadUserDB     => true,
    }

    DigestAuth = {
      :Algorithm            => 'MD5-sess', # or 'MD5' 
      :Domain               => nil,        # an array includes domain names.
      :Qop                  => [ 'auth' ], # 'auth' or 'auth-int' or both.
      :UseOpaque            => true,
      :UseNextNonce         => false,
      :CheckNc              => false,
      :UseAuthenticationInfoHeader => true,
      :AutoReloadUserDB     => true,
      :NonceExpirePeriod    => 30*60,
      :NonceExpireDelta     => 60,
      :InternetExplorerHack => true,
      :OperaHack            => true,
    }
  end
end