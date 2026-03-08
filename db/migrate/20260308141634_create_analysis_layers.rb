class CreateAnalysisLayers < ActiveRecord::Migration[8.1]
  def change
    create_table :analysis_layers do |t|
      t.references :email, null: false, foreign_key: true
      t.string :layer_name, null: false
      t.integer :score
      t.float :weight, null: false
      t.float :confidence, default: 1.0
      t.json :details, default: {}
      t.text :explanation
      t.string :status, null: false, default: "pending"

      t.timestamps
    end

    add_index :analysis_layers, [:email_id, :layer_name], unique: true
  end
end
