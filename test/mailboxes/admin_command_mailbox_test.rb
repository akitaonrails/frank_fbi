require "test_helper"

class AdminCommandMailboxTest < ActionMailbox::TestCase
  include ActionMailer::TestHelper

  setup do
    @admin_email = "admin@example.com"
    ENV["ADMIN_EMAIL"] = @admin_email
  end

  test "admin add command creates allowed senders" do
    assert_difference -> { AllowedSender.count }, 2 do
      receive_inbound_email_from_mail(
        from: @admin_email,
        to: "fbi@example.com",
        subject: "add senders",
        body: "alice@example.com\nbob@example.com"
      )
    end

    assert AllowedSender.authorized?("alice@example.com")
    assert AllowedSender.authorized?("bob@example.com")
  end

  test "admin remove command deactivates senders" do
    create(:allowed_sender, email_address: "remove-me@example.com")

    receive_inbound_email_from_mail(
      from: @admin_email,
      to: "fbi@example.com",
      subject: "remove",
      body: "remove-me@example.com"
    )

    assert_not AllowedSender.authorized?("remove-me@example.com")
  end

  test "admin list command sends reply" do
    create(:allowed_sender, email_address: "listed@example.com")

    assert_emails 1 do
      receive_inbound_email_from_mail(
        from: @admin_email,
        to: "fbi@example.com",
        subject: "list",
        body: ""
      )
    end
  end

  test "admin stats command sends reply" do
    assert_emails 1 do
      receive_inbound_email_from_mail(
        from: @admin_email,
        to: "fbi@example.com",
        subject: "stats",
        body: ""
      )
    end
  end
end
