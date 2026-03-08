require "test_helper"

class RejectionMailboxTest < ActionMailbox::TestCase
  include ActionMailer::TestHelper

  setup do
    ENV["ADMIN_EMAIL"] = "admin@example.com"
  end

  test "non-whitelisted sender receives rejection email" do
    assert_emails 1 do
      receive_inbound_email_from_mail(
        from: "stranger@example.com",
        to: "fbi@example.com",
        subject: "Check this email",
        body: "Is this spam?"
      )
    end
  end
end
