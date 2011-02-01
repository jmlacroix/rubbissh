require 'yaml'

CONFIG_IN  = File.join(File.dirname(__FILE__), "config.yml")
CONFIG_OUT = File.join(File.dirname(__FILE__), "config.out")

SYMBOL    = '-'
WILDCARD  = '*'
DEFAULT   = 'host_name'
INDENT    = "\t"
SEPARATOR = "\t"

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

# map a rubyfied keywords hash real ssh keywords
def map_keywords(keywords)
  keywords.inject({}) do |out, keyvalue|
    key, value = keyvalue
    out.merge({ KEYWORDS[key.to_sym], value.to_s })
  end
end

# add a host and its keywords into the entries list
def add_entry(level, keywords)
  ENTRIES << [
    level.join(SYMBOL),
    map_keywords(keywords)
  ]
end

# parse the YAML config file recursively
def parse_config(level, config)
  if config.has_key? WILDCARD
    add_entry level + [WILDCARD], config.delete(WILDCARD)
  end

  config.each_pair do |sublevel, subconfig|
    if sublevel.end_with? SYMBOL
      parse_config(level + [sublevel.chomp(SYMBOL)], subconfig)
    else
      if !subconfig.is_a?(Hash)
        subconfig = { DEFAULT => subconfig }
      end
      add_entry level + [sublevel], subconfig
    end
  end
end

# transform the entries list in a classic ssh config
def ssh_config
  ENTRIES.inject([]) { |out, keyvalue|
    host, keywords = keyvalue
    out << [
      'Host ' + host,
      keywords.inject([]) do |subout, subkeyvalue|
        key, value = subkeyvalue
        subout << "#{INDENT}#{key.to_s}#{SEPARATOR}#{value.to_s}"
      end
    ]
  }.join("\n")
end

# write the config into an out file
def write_config
  File.open(CONFIG_OUT, 'w') do |f|
    f.write(ssh_config + "\n")
  end
end

parse_config([], YAML.load_file(CONFIG_IN))
write_config
