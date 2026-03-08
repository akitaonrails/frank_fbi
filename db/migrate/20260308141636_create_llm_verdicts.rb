class CreateLlmVerdicts < ActiveRecord::Migration[8.1]
  def change
    create_table :llm_verdicts do |t|
      t.references :email, null: false, foreign_key: true
      t.string :provider, null: false
      t.string :model_id
      t.integer :score
      t.string :verdict
      t.text :reasoning
      t.json :key_findings, default: []
      t.float :confidence
      t.integer :prompt_tokens
      t.integer :completion_tokens
      t.float :response_time_seconds

      t.timestamps
    end

    add_index :llm_verdicts, [:email_id, :provider], unique: true
  end
end
