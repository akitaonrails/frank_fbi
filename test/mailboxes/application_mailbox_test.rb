require "test_helper"

class ApplicationMailboxTest < ActionMailbox::TestCase
  setup do
    ENV["ADMIN_EMAIL"] = "admin@example.com"
  end

  # --- Basic routing ---

  test "admin_email? returns true for admin sender (no auth header = local dev)" do
    inbound = create_inbound_email_from_mail(
      from: "admin@example.com", to: "fbi@example.com", subject: "stats", body: ""
    )
    assert ApplicationMailbox.send(:admin_email?, inbound)
  end

  test "admin_email? returns false for non-admin sender" do
    inbound = create_inbound_email_from_mail(
      from: "other@example.com", to: "fbi@example.com", subject: "stats", body: ""
    )
    assert_not ApplicationMailbox.send(:admin_email?, inbound)
  end

  test "allowed_sender? returns true for whitelisted sender" do
    create(:allowed_sender, email_address: "trusted@example.com")
    inbound = create_inbound_email_from_mail(
      from: "trusted@example.com", to: "fbi@example.com", subject: "Check this", body: "content"
    )
    assert ApplicationMailbox.send(:allowed_sender?, inbound)
  end

  test "allowed_sender? returns false for unknown sender" do
    inbound = create_inbound_email_from_mail(
      from: "stranger@example.com", to: "fbi@example.com", subject: "Hello", body: "Hi"
    )
    assert_not ApplicationMailbox.send(:allowed_sender?, inbound)
  end

  # --- SPF/DKIM anti-spoofing ---

  test "rejects spoofed admin email when SPF/DKIM fail" do
    raw = <<~EML
      From: admin@example.com
      To: fbi@example.com
      Subject: stats
      Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=admin@example.com; dkim=fail
      Message-ID: <spoofed-admin@example.com>

      body
    EML
    inbound = create_inbound_email_from_source(raw)
    assert_not ApplicationMailbox.send(:admin_email?, inbound)
  end

  test "accepts admin email when SPF passes" do
    raw = <<~EML
      From: admin@example.com
      To: fbi@example.com
      Subject: stats
      Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=admin@example.com; dkim=none
      Message-ID: <legit-admin@example.com>

      body
    EML
    inbound = create_inbound_email_from_source(raw)
    assert ApplicationMailbox.send(:admin_email?, inbound)
  end

  test "accepts admin email when DKIM passes" do
    raw = <<~EML
      From: admin@example.com
      To: fbi@example.com
      Subject: stats
      Authentication-Results: mx.google.com; spf=none; dkim=pass header.i=@example.com
      Message-ID: <dkim-admin@example.com>

      body
    EML
    inbound = create_inbound_email_from_source(raw)
    assert ApplicationMailbox.send(:admin_email?, inbound)
  end

  test "rejects spoofed allowed sender when SPF/DKIM fail" do
    create(:allowed_sender, email_address: "trusted@example.com")
    raw = <<~EML
      From: trusted@example.com
      To: fbi@example.com
      Subject: Check this
      Authentication-Results: mx.google.com; spf=fail; dkim=fail
      Message-ID: <spoofed-sender@example.com>

      body
    EML
    inbound = create_inbound_email_from_source(raw)
    assert_not ApplicationMailbox.send(:allowed_sender?, inbound)
  end

  test "accepts allowed sender when SPF passes" do
    create(:allowed_sender, email_address: "trusted@example.com")
    raw = <<~EML
      From: trusted@example.com
      To: fbi@example.com
      Subject: Check this
      Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=trusted@example.com
      Message-ID: <legit-sender@example.com>

      body
    EML
    inbound = create_inbound_email_from_source(raw)
    assert ApplicationMailbox.send(:allowed_sender?, inbound)
  end

  test "allows through when Authentication-Results header is absent (local dev)" do
    inbound = create_inbound_email_from_mail(
      from: "admin@example.com", to: "fbi@example.com", subject: "stats", body: ""
    )
    assert ApplicationMailbox.send(:email_authenticated?, inbound)
  end

  # --- Admin command vs analysis routing ---

  test "admin with command keyword routes to admin_command" do
    inbound = create_inbound_email_from_mail(
      from: "admin@example.com", to: "fbi@example.com", subject: "list", body: ""
    )
    assert ApplicationMailbox.send(:admin_command?, inbound)
  end

  test "admin without command keyword routes to fraud_analysis" do
    inbound = create_inbound_email_from_mail(
      from: "admin@example.com", to: "fbi@example.com", subject: "Fwd: Suspicious email", body: "spam content"
    )
    assert_not ApplicationMailbox.send(:admin_command?, inbound)
    assert ApplicationMailbox.send(:admin_email?, inbound)
  end

  test "admin is never routed to rejection" do
    inbound = create_inbound_email_from_mail(
      from: "admin@example.com", to: "fbi@example.com", subject: "Check this spam", body: ""
    )
    assert ApplicationMailbox.send(:admin_email?, inbound)
  end
end
