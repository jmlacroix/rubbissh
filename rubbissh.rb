require 'yaml'

CONFIG_IN     = File.join(File.dirname(__FILE__), "config.yml")
CONFIG_OUT    = File.join(File.dirname(__FILE__), "config.out")

SYM  = '-'
WILD = '*'
DEF  = 'host_name'

ENTRIES = []

KEYWORDS = {
  :address_family => "AddressFamily",
  :local_command => "LocalCommand",
  :forward_x11 => "ForwardX11",
  :server_alive_count_max => "ServerAliveCountMax",
  :host_name => "HostName",
  :dynamic_forward => "DynamicForward",
  :rekey_limit => "RekeyLimit",
  :user_known_hosts_file => "UserKnownHostsFile",
  :compression_level => "CompressionLevel",
  :port => "Port",
  :gssapi_trust_dns => "GSSAPITrustDns",
  :check_host_ip => "CheckHostIP",
  :no_host_authentication_for_localhost => "NoHostAuthenticationForLocalhost",
  :gssapi_authentication => "GSSAPIAuthentication",
  :tunnel => "Tunnel",
  :host => "Host",
  :kbd_interactive_devices => "KbdInteractiveDevices",
  :forward_agent => "ForwardAgent",
  :send_env => "SendEnv",
  :host_key_alias => "HostKeyAlias",
  :control_path => "ControlPath",
  :pubkey_authentication => "PubkeyAuthentication",
  :user => "User",
  :gssapi_renewal_forces_rekey => "GSSAPIRenewalForcesRekey",
  :compression => "Compression",
  :pkcs11_provider => "PKCS11Provider",
  :global_known_hosts_file => "GlobalKnownHostsFile",
  :tcp_keep_alive => "TCPKeepAlive",
  :challenge_response_authentication => "ChallengeResponseAuthentication",
  :macs => "MACs",
  :rsa_authentication => "RSAAuthentication",
  :kbd_interactive_authentication => "KbdInteractiveAuthentication",
  :exit_on_forward_failure => "ExitOnForwardFailure",
  :xauth_location => "XAuthLocation",
  :host_key_algorithms => "HostKeyAlgorithms",
  :control_master => "ControlMaster",
  :proxy_command => "ProxyCommand",
  :gssapi_delegate_credentials => "GSSAPIDelegateCredentials",
  :use_privileged_port => "UsePrivilegedPort",
  :clear_all_forwardings => "ClearAllForwardings",
  :permit_local_command => "PermitLocalCommand",
  :gateway_ports => "GatewayPorts",
  :strict_host_key_checking => "StrictHostKeyChecking",
  :bind_address => "BindAddress",
  :log_level => "LogLevel",
  :escape_char => "EscapeChar",
  :rhosts_rsa_authentication => "RhostsRSAAuthentication",
  :identity_file => "IdentityFile",
  :visual_host_key => "VisualHostKey",
  :connect_timeout => "ConnectTimeout",
  :protocol => "Protocol",
  :hostbased_authentication => "HostbasedAuthentication",
  :password_authentication => "PasswordAuthentication",
  :gssapi_client_identity => "GSSAPIClientIdentity",
  :use_blacklisted_keys => "UseBlacklistedKeys",
  :ciphers => "Ciphers",
  :forward_x11_trusted => "ForwardX11Trusted",
  :server_alive_interval => "ServerAliveInterval",
  :batch_mode => "BatchMode",
  :local_forward => "LocalForward",
  :enable_ssh_keysign => "EnableSSHKeysign",
  :remote_forward => "RemoteForward",
  :identities_only => "IdentitiesOnly",
  :verify_host_key_dns => "VerifyHostKeyDNS",
  :connection_attempts => "ConnectionAttempts",
  :preferred_authentications => "PreferredAuthentications",
  :hash_known_hosts => "HashKnownHosts",
  :cipher => "Cipher",
  :number_of_password_prompts => "NumberOfPasswordPrompts",
  :gssapi_key_exchange => "GSSAPIKeyExchange",
  :tunnel_device => "TunnelDevice"
}

def map_cfg(cfg)
  cfg.inject({}) { |m, o| m[KEYWORDS[o[0].to_sym]] = o[1].to_s ; m }
end

def parse_cfg(lvl, cfg)
  if cfg.has_key? WILD
    ENTRIES << [ (lvl + [WILD]).join(SYM), map_cfg(cfg.delete(WILD)) ]
  end

  cfg.each_pair do |slvl, scfg|
    if slvl.end_with? SYM
      parse_cfg(lvl + [slvl[0..-2]], scfg)
    else
      scfg = { DEF => scfg } if !scfg.is_a?(Hash)
      ENTRIES << [ (lvl + [slvl]).join(SYM), map_cfg(scfg) ]
    end
  end
end

def str_cfg
  ENTRIES.inject([]) { |r, e|
    r << [
      'Host ' + e[0],
      e[1].inject([]) { |sr, o| sr << "\t#{o[0].to_s}\t#{o[1].to_s}" }
    ]
  }.join("\n")
end

def write_cfg
  File.open(CONFIG_OUT, 'w') { |f| f.write(str_cfg + "\n") }
end

parse_cfg([], YAML.load_file(CONFIG_IN))
write_cfg
