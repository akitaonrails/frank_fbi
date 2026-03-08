require "test_helper"

class KnownDomainTest < ActiveSupport::TestCase
  test "validates domain uniqueness" do
    KnownDomain.create!(domain: "example.com")
    duplicate = KnownDomain.new(domain: "example.com")
    assert_not duplicate.valid?
  end

  test "fraud_ratio calculation" do
    domain = KnownDomain.create!(domain: "test.com", times_seen: 10, times_flagged_fraud: 7)
    assert_in_delta 0.7, domain.fraud_ratio, 0.01
  end

  test "fraud_ratio with zero seen" do
    domain = KnownDomain.create!(domain: "test.com")
    assert_equal 0.0, domain.fraud_ratio
  end

  test "record_analysis increments counters" do
    domain = KnownDomain.create!(domain: "test.com", times_seen: 0)
    domain.record_analysis("fraudulent")
    assert_equal 1, domain.reload.times_seen
    assert_equal 1, domain.times_flagged_fraud
  end

  test "whois_stale? returns true when never checked" do
    domain = KnownDomain.create!(domain: "test.com")
    assert domain.whois_stale?
  end
end
