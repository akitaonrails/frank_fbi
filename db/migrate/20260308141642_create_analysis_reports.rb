class CreateAnalysisReports < ActiveRecord::Migration[8.1]
  def change
    create_table :analysis_reports do |t|
      t.references :email, null: false, foreign_key: true, index: false
      t.text :report_html
      t.text :report_text
      t.string :reply_message_id
      t.string :status, null: false, default: "pending"
      t.datetime :sent_at

      t.timestamps
    end

    add_index :analysis_reports, :email_id, unique: true
  end
end
