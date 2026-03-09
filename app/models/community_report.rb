class CommunityReport < ApplicationRecord
  belongs_to :email

  validates :email_id, uniqueness: true
end
