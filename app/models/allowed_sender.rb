class AllowedSender < ApplicationRecord
  encrypts :email_address, deterministic: true
  encrypts :added_by, deterministic: true

  validates :email_address, presence: true, uniqueness: true

  scope :active, -> { where(active: true) }

  def self.authorized?(email)
    active.exists?(email_address: email.downcase.strip)
  end
end
