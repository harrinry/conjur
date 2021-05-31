# frozen_string_literal: true

# Utility methods for JWT and JWKs manipulation

require 'openssl'
require 'jwt'

module JwtJwksHelper

  module Algorithms
    RS256 = "RS256".freeze
  end

  JWKS_ROOT_PATH = "/var/jwks".freeze
  JWKS_BASE_URI = "http://jwks".freeze
  BITS_2048 = 2048
  HOUR_IN_SECONDS = 3600

  def init_jwks_file(file_name)
    jwks = { keys: [jwk.export] }
    File.write(
      "#{JWKS_ROOT_PATH}/#{file_name}", 
      JSON.pretty_generate(jwks)
    )
  end

  def issue_jwt_token(token_body, algorithm = Algorithms::RS256)
    @jwt_token = JWT.encode(
      token_body,
      rsa_key,
      algorithm,
      { kid: jwk.kid }
    )
  end

  def jwt_token
    @jwt_token
  end

  def jwk
    @jwk ||= JWT::JWK.new(rsa_key)
  end

  def rsa_key
    @rsa_key ||= OpenSSL::PKey::RSA.new(BITS_2048)
  end

  def token_body_with_valid_expiration(token_body)
    token_body["exp"] = Time.now.to_i + HOUR_IN_SECONDS
    token_body
  end

end

World(JwtJwksHelper)
