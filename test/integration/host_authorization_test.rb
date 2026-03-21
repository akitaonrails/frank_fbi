require "test_helper"

class HostAuthorizationTest < ActiveSupport::TestCase
  test "production hosts config does not contain IPv4 wildcard 0.0.0.0/0" do
    # Load production config hosts
    hosts = Rails.application.config.hosts

    wildcard_v4 = IPAddr.new("0.0.0.0/0")
    has_wildcard = hosts.any? { |h| h.is_a?(IPAddr) && h == wildcard_v4 }

    refute has_wildcard, "config.hosts must not contain 0.0.0.0/0 (accepts all IPv4 Host headers)"
  end

  test "production hosts config does not contain IPv6 wildcard ::/0" do
    hosts = Rails.application.config.hosts

    wildcard_v6 = IPAddr.new("::/0")
    has_wildcard = hosts.any? { |h| h.is_a?(IPAddr) && h == wildcard_v6 }

    refute has_wildcard, "config.hosts must not contain ::/0 (accepts all IPv6 Host headers)"
  end
end
