class Email < ApplicationRecord
  encrypts :submitter_email, deterministic: true

  has_many :analysis_layers, dependent: :destroy
  has_many :llm_verdicts, dependent: :destroy
  has_one :analysis_report, dependent: :destroy

  validates :message_id, presence: true, uniqueness: true
  validates :submitter_email, presence: true
  validates :status, presence: true, inclusion: {
    in: %w[pending parsing analyzing completed failed]
  }
  validates :verdict, inclusion: {
    in: %w[legitimate suspicious_likely_ok suspicious_likely_fraud fraudulent],
    allow_nil: true
  }
  validates :final_score, numericality: {
    only_integer: true, greater_than_or_equal_to: 0,
    less_than_or_equal_to: 100
  }, allow_nil: true

  scope :pending, -> { where(status: "pending") }
  scope :completed, -> { where(status: "completed") }
  scope :failed, -> { where(status: "failed") }
  scope :fraudulent, -> { where(verdict: "fraudulent") }

  def fully_analyzed?
    analysis_layers.where(status: "completed").count == AnalysisLayer::LAYER_NAMES.size
  end

  def layer_completed?(layer_name)
    analysis_layers.exists?(layer_name: layer_name, status: "completed")
  end
end
