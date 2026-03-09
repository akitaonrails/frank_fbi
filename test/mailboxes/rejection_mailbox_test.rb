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

  test "rate-limited sender receives rate limit notice instead of rejection" do
    create(:allowed_sender, email_address: "trusted@example.com")

    with_memory_cache do
      # Push over the limit
      (AllowedSender::MAX_SUBMISSIONS_PER_HOUR + 1).times do
        AllowedSender.rate_limited?("trusted@example.com")
      end

      assert_emails 1 do
        receive_inbound_email_from_mail(
          from: "trusted@example.com",
          to: "fbi@example.com",
          subject: "Another email",
          body: "content"
        )
      end

      last_email = ActionMailer::Base.deliveries.last
      assert_includes last_email.subject, "Limite de Envios"
    end
  end
end
