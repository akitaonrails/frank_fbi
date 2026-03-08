class AllowedSender < ApplicationRecord
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

  private

  def cannot_be_admin_email
    admin = self.class.admin_email
    return if admin.blank?

    if email_address&.downcase&.strip == admin
      errors.add(:email_address, "cannot be the admin email — admin access is managed separately")
    end
  end
end
