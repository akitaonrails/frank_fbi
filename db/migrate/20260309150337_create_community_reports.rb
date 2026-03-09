class CreateCommunityReports < ActiveRecord::Migration[8.1]
  def change
    create_table :community_reports do |t|
      t.references :email, null: false, foreign_key: true, index: { unique: true }
      t.json :iocs_submitted, default: {}
      t.json :providers, default: []
      t.json :details, default: {}
      t.timestamps
    end
  end
end
