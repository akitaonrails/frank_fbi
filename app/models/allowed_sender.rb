class AllowedSender < ApplicationRecord
  MAX_SUBMISSIONS_PER_HOUR = ENV.fetch("MAX_SUBMISSIONS_PER_HOUR", "20").to_i

  encrypts :email_address, deterministic: true
  encrypts :added_by, deterministic: true

  validates :email_address, presence: true, uniqueness: true
  validate :cannot_be_admin_email

  scope :active, -> { where(active: true) }

  def self.authorized?(email)
    active.exists?(email_address: email.downcase.strip)
  end

  def self.admin_email
    ENV["ADMIN_EMAIL"]&.downcase&.strip
  end

  # Increment the rate counter and return true if the sender is now over the limit.
  # Returns false when rate limiting is disabled (MAX=0) or cache is null_store.
  def self.rate_limited?(email)
    return false if MAX_SUBMISSIONS_PER_HOUR <= 0

    key = rate_limit_key(email)
    count = Rails.cache.increment(key, 1, expires_in: 1.hour)
    return false if count.nil? # null_store returns nil

    if count > MAX_SUBMISSIONS_PER_HOUR
      Rails.logger.warn("AllowedSender: rate limited #{email.downcase.strip} — #{count} submissions in the last hour (limit: #{MAX_SUBMISSIONS_PER_HOUR})")
      true
    else
      false
    end
  end

  # Check if a sender is over the limit WITHOUT incrementing the counter.
  # Used by RejectionMailbox to differentiate rate-limit vs unauthorized replies.
  def self.over_rate_limit?(email)
    return false if MAX_SUBMISSIONS_PER_HOUR <= 0

    key = rate_limit_key(email)
    count = Rails.cache.read(key)
    return false if count.nil?

    count > MAX_SUBMISSIONS_PER_HOUR
  end

  private

  def self.rate_limit_key(email)
    "rate_limit:allowed_sender:#{email.downcase.strip}"
  end

  def cannot_be_admin_email
    admin = self.class.admin_email
    return if admin.blank?

    if email_address&.downcase&.strip == admin
      errors.add(:email_address, "cannot be the admin email — admin access is managed separately")
    end
  end
end
