class AnalysisReport < ApplicationRecord
  belongs_to :email

  validates :status, presence: true, inclusion: {
    in: %w[pending generating generated sending sent failed]
  }

  scope :pending, -> { where(status: "pending") }
  scope :sent, -> { where(status: "sent") }

  def sent!
    update!(status: "sent", sent_at: Time.current)
  end
end
