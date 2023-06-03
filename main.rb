#!/usr/bin/env ruby
# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'gpgme'
require 'dnsruby'
require 'base64'

# Retrieve signature
resolv = Dnsruby::Resolver.new
ret = resolv.query('security.2fa.directory', 'CERT')
GPGME::Crypto.new
data = GPGME::Key.import(ret.answer.rrsets[0][0].cert)

# Fetch key from vault
intnd_sig = GPGME::Key.find(:public, 'security@2fa.directory')[0]

# Trust DNS-supplied signature
# Fetch file
res = Net::HTTP.get_response(URI('https://api.2fa.directory/v3/totp.json.sig')).body
crypto = GPGME::Crypto.new
signature = GPGME::Data.new(res)

data = crypto.verify(signature) do |sig|
  # Verify that the same key as before signed the file
  raise 'Invalid key' unless sig.key.== intnd_sig
end

# Write verified data to new file
File.open('totp.json', 'w') { |file| file.write data }
