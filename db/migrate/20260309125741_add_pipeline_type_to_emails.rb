class AddPipelineTypeToEmails < ActiveRecord::Migration[8.1]
  def change
    add_column :emails, :pipeline_type, :string, default: "fraud_analysis", null: false
    add_index :emails, :pipeline_type
  end
end
