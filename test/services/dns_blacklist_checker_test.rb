require "test_helper"
require "resolv"

class DnsBlacklistCheckerTest < ActiveSupport::TestCase
  setup do
    @original_dns_new = Resolv::DNS.method(:new)
    @dns_responses = {}
    fake_responses = @dns_responses

    Resolv::DNS.define_singleton_method(:new) do |**_|
      FakeDnsResolver.new(fake_responses)
    end
  end

  teardown do
    original = @original_dns_new
    Resolv::DNS.define_singleton_method(:new) { |**kwargs| original.call(**kwargs) }
  end

  # --- Spamhaus ZEN ---

  test "Spamhaus ZEN 127.0.0.2 is a valid SBL listing" do
    set_dns("4.3.2.1.zen.spamhaus.org", ["127.0.0.2"])

    results = checker_with_ip.check
    zen = results["zen.spamhaus.org"]

    assert zen[:listed], "Should be listed for valid SBL code"
    assert_includes zen[:categories], "sbl"
    assert zen[:authoritative_malicious]
    assert_nil zen[:error]
  end

  test "Spamhaus ZEN 127.255.255.254 is a rate-limit error, not a listing" do
    set_dns("4.3.2.1.zen.spamhaus.org", ["127.255.255.254"])

    results = checker_with_ip.check
    zen = results["zen.spamhaus.org"]

    assert_not zen[:listed], "Rate-limit code should NOT count as listed"
    assert_equal "rate_limited_or_blocked", zen[:error]
  end

  test "Spamhaus ZEN 127.255.255.252 is a rate-limit error" do
    set_dns("4.3.2.1.zen.spamhaus.org", ["127.255.255.252"])

    results = checker_with_ip.check
    zen = results["zen.spamhaus.org"]

    assert_not zen[:listed]
    assert_equal "rate_limited_or_blocked", zen[:error]
  end

  test "Spamhaus ZEN 127.255.255.255 is a rate-limit error" do
    set_dns("4.3.2.1.zen.spamhaus.org", ["127.255.255.255"])

    results = checker_with_ip.check
    zen = results["zen.spamhaus.org"]

    assert_not zen[:listed]
    assert_equal "rate_limited_or_blocked", zen[:error]
  end

  # --- Spamhaus DBL ---

  test "Spamhaus DBL 127.0.1.4 is a valid phishing listing" do
    set_dns("example.com.dbl.spamhaus.org", ["127.0.1.4"])

    results = checker_with_ip.check
    dbl = results["dbl.spamhaus.org"]

    assert dbl[:listed], "Should be listed for valid phishing code"
    assert_includes dbl[:categories], "phishing"
    assert dbl[:authoritative_malicious]
  end

  test "Spamhaus DBL 127.255.255.255 is a rate-limit error, not a listing" do
    set_dns("example.com.dbl.spamhaus.org", ["127.255.255.255"])

    results = checker_with_ip.check
    dbl = results["dbl.spamhaus.org"]

    assert_not dbl[:listed], "Rate-limit code should NOT count as listed"
    assert_equal "rate_limited_or_blocked", dbl[:error]
  end

  # --- URIBL ---

  test "URIBL 127.0.0.1 is a refused query, not a listing" do
    set_dns("example.com.multi.uribl.com", ["127.0.0.1"])

    results = checker_with_ip.check
    uribl = results["multi.uribl.com"]

    assert_not uribl[:listed], "Refused code should NOT count as listed"
    assert_equal "query_refused", uribl[:error]
  end

  test "URIBL 127.0.0.2 is a valid listing" do
    set_dns("example.com.multi.uribl.com", ["127.0.0.2"])

    results = checker_with_ip.check
    uribl = results["multi.uribl.com"]

    assert uribl[:listed], "Should be listed for valid bitmask code"
    assert_nil uribl[:error]
  end

  test "URIBL 127.0.0.8 is a valid listing" do
    set_dns("example.com.multi.uribl.com", ["127.0.0.8"])

    results = checker_with_ip.check
    uribl = results["multi.uribl.com"]

    assert uribl[:listed]
  end

  # --- Barracuda ---

  test "Barracuda 127.0.0.2 is a valid listing" do
    set_dns("4.3.2.1.b.barracudacentral.org", ["127.0.0.2"])

    results = checker_with_ip.check
    barracuda = results["b.barracudacentral.org"]

    assert barracuda[:listed]
    assert_nil barracuda[:error]
  end

  test "Barracuda unknown code is not a listing" do
    set_dns("4.3.2.1.b.barracudacentral.org", ["127.0.0.99"])

    results = checker_with_ip.check
    barracuda = results["b.barracudacentral.org"]

    assert_not barracuda[:listed]
    assert_equal "unknown_response_codes", barracuda[:error]
  end

  # --- Empty response ---

  test "empty DNS response means not listed" do
    # All queries return empty by default
    results = checker_with_ip.check

    results.each do |_, result|
      assert_not result[:listed]
    end
  end

  # --- Mixed valid + error codes ---

  test "Spamhaus ZEN with mixed valid and error codes correctly identifies listing" do
    set_dns("4.3.2.1.zen.spamhaus.org", ["127.0.0.2", "127.255.255.254"])

    results = checker_with_ip.check
    zen = results["zen.spamhaus.org"]

    assert zen[:listed], "Valid code should still result in listing even with error codes present"
  end

  # --- Domain-only check (no IP) ---

  test "check without IP only queries domain blacklists" do
    checker = DnsBlacklistChecker.new("example.com")
    results = checker.check

    assert results.key?("dbl.spamhaus.org")
    assert results.key?("multi.uribl.com")
    assert_not results.key?("zen.spamhaus.org")
    assert_not results.key?("b.barracudacentral.org")
  end

  test "DNSBL_SKIP env var skips listed blacklists entirely" do
    ENV["DNSBL_SKIP"] = "zen.spamhaus.org,dbl.spamhaus.org"
    DnsBlacklistChecker.reset_skipped_blacklists!
    set_dns("4.3.2.1.zen.spamhaus.org", ["127.0.0.2"]) # would be a listing
    set_dns("example.com.dbl.spamhaus.org", ["127.0.1.4"]) # would be a listing

    results = checker_with_ip.check

    assert_nil results["zen.spamhaus.org"], "Skipped blacklist must not be queried"
    assert_nil results["dbl.spamhaus.org"], "Skipped blacklist must not be queried"
    # Non-skipped blacklists still run
    assert results.key?("multi.uribl.com")
  ensure
    ENV.delete("DNSBL_SKIP")
    DnsBlacklistChecker.reset_skipped_blacklists!
  end

  private

  def checker_with_ip
    DnsBlacklistChecker.new("example.com", ip: "1.2.3.4")
  end

  def set_dns(query, response_ips)
    @dns_responses[query] = response_ips.map { |ip| Resolv::IPv4.create(ip) }
  end

  class FakeDnsResolver
    def initialize(responses = {})
      @responses = responses
    end

    attr_writer :timeouts

    def timeouts=(val)
      # no-op
    end

    def getaddresses(query)
      @responses[query] || []
    end

    def close
      # no-op
    end
  end
end
