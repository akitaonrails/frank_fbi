require "test_helper"

class ApplicationMailboxTest < ActionMailbox::TestCase
  setup do
    ENV["ADMIN_EMAIL"] = "admin@example.com"
  end

  test "admin_email? returns true for admin sender" do
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
end
