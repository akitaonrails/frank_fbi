require "test_helper"

class AllowedSenderTest < ActiveSupport::TestCase
  test "validates presence of email_address" do
    sender = AllowedSender.new(email_address: nil)
    assert_not sender.valid?
    assert_includes sender.errors[:email_address], "can't be blank"
  end

  test "validates uniqueness of email_address" do
    create(:allowed_sender, email_address: "dupe@example.com")
    sender = AllowedSender.new(email_address: "dupe@example.com")
    assert_not sender.valid?
    assert_includes sender.errors[:email_address], "has already been taken"
  end

  test "active scope returns only active senders" do
    active = create(:allowed_sender, active: true)
    _inactive = create(:allowed_sender, :inactive)

    assert_includes AllowedSender.active, active
    assert_equal 1, AllowedSender.active.count
  end

  test ".authorized? returns true for active sender" do
    create(:allowed_sender, email_address: "user@example.com")
    assert AllowedSender.authorized?("user@example.com")
  end

  test ".authorized? returns false for inactive sender" do
    create(:allowed_sender, email_address: "user@example.com", active: false)
    assert_not AllowedSender.authorized?("user@example.com")
  end

  test ".authorized? returns false for unknown email" do
    assert_not AllowedSender.authorized?("unknown@example.com")
  end

  test ".authorized? normalizes email case and whitespace" do
    create(:allowed_sender, email_address: "user@example.com")
    assert AllowedSender.authorized?("  User@Example.COM  ")
  end

  test "cannot add admin email as allowed sender" do
    ENV["ADMIN_EMAIL"] = "admin@example.com"
    sender = AllowedSender.new(email_address: "admin@example.com", added_by: "someone")
    assert_not sender.valid?
    assert_includes sender.errors[:email_address], "cannot be the admin email — admin access is managed separately"
  end

  test "cannot add admin email case-insensitively" do
    ENV["ADMIN_EMAIL"] = "admin@example.com"
    sender = AllowedSender.new(email_address: "Admin@Example.COM", added_by: "someone")
    assert_not sender.valid?
  end

  test "encrypts email_address" do
    sender = create(:allowed_sender, email_address: "secret@example.com")
    raw_value = AllowedSender.connection.select_value(
      "SELECT email_address FROM allowed_senders WHERE id = #{sender.id}"
    )
    assert_not_equal "secret@example.com", raw_value
  end
end
